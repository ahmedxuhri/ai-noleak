package cliroot

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"noleak/internal/config"
	"noleak/internal/ipc"
	"noleak/internal/watch"
)

type doctorSeverity int

const (
	doctorOK doctorSeverity = iota
	doctorWarn
	doctorFail
)

type doctorCheck struct {
	Name     string
	Severity doctorSeverity
	Message  string
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check whether noleak is installed and protecting traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			checks := runDoctor(home)
			fails := printDoctor(os.Stdout, checks)
			if fails > 0 {
				return fmt.Errorf("doctor: %d failing checks", fails)
			}
			return nil
		},
	}
}

func runDoctor(home string) []doctorCheck {
	var checks []doctorCheck
	cfgPath := config.Path(home)
	cfg, cfgErr := config.Load(home)
	if cfgErr != nil {
		checks = append(checks, doctorCheck{"config", doctorFail, cfgErr.Error()})
		cfg = config.Defaults(home)
	} else if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		checks = append(checks, doctorCheck{"config", doctorWarn, cfgPath + " missing; defaults loaded"})
	} else {
		checks = append(checks, doctorCheck{"config", doctorOK, cfgPath})
	}
	if err := config.Validate(cfg); err != nil {
		checks = append(checks, doctorCheck{"config validation", doctorFail, err.Error()})
	} else {
		checks = append(checks, doctorCheck{"config validation", doctorOK, "valid"})
	}

	checks = append(checks, checkSocketPath(cfg.SocketPath))
	checks = append(checks, checkDaemon(ipc.NewClient(cfg.SocketPath))...)
	checks = append(checks, checkProxyConfig(cfg)...)
	checks = append(checks, checkWatchRules(home, cfg)...)
	checks = append(checks, checkAgentHints(home, cfg.ProxyListen)...)
	return checks
}

func checkSocketPath(path string) doctorCheck {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return doctorCheck{"socket", doctorFail, path + " missing; start noleakd"}
		}
		return doctorCheck{"socket", doctorFail, err.Error()}
	}
	if st.Mode()&os.ModeSocket == 0 {
		return doctorCheck{"socket", doctorFail, path + " exists but is not a Unix socket"}
	}
	if st.Mode().Perm()&0o077 != 0 {
		return doctorCheck{"socket permissions", doctorWarn, fmt.Sprintf("%s mode %s is broader than 0600/0700 expectations", path, st.Mode().Perm())}
	}
	return doctorCheck{"socket", doctorOK, path}
}

func checkDaemon(client *ipc.Client) []doctorCheck {
	resp, err := client.Call(&ipc.Request{Op: ipc.OpHealth})
	if err != nil {
		return []doctorCheck{{"daemon health", doctorFail, err.Error()}}
	}
	if resp.Error != "" {
		return []doctorCheck{{"daemon health", doctorFail, resp.Error}}
	}
	if resp.Health == nil {
		return []doctorCheck{{"daemon health", doctorFail, "empty health response"}}
	}
	h := resp.Health
	severity := doctorOK
	msg := fmt.Sprintf("version=%s unlocked=%v vault_entries=%d pending_review=%d uptime=%s",
		h.Version, h.Unlocked, h.VaultEntries, h.PendingReview, time.Duration(h.UptimeSeconds)*time.Second)
	if !h.Unlocked {
		severity = doctorFail
		msg += "; unlock daemon before use"
	}
	return []doctorCheck{{"daemon health", severity, msg}}
}

func checkProxyConfig(cfg config.Config) []doctorCheck {
	var checks []doctorCheck
	host, port, err := net.SplitHostPort(cfg.ProxyListen)
	if err != nil {
		checks = append(checks, doctorCheck{"proxy listen", doctorFail, err.Error()})
	} else if !loopbackHost(host) {
		checks = append(checks, doctorCheck{"proxy listen", doctorFail, cfg.ProxyListen + " is not loopback-only"})
	} else {
		checks = append(checks, doctorCheck{"proxy listen", doctorOK, net.JoinHostPort(host, port)})
	}
	if cfg.ProxyUpstream == "" {
		checks = append(checks, doctorCheck{"proxy upstream", doctorWarn, "proxy_upstream is empty; `noleak proxy` will not start"})
	} else if u, err := url.Parse(cfg.ProxyUpstream); err != nil || u.Scheme == "" || u.Host == "" {
		checks = append(checks, doctorCheck{"proxy upstream", doctorFail, "must be an absolute URL"})
	} else {
		checks = append(checks, doctorCheck{"proxy upstream", doctorOK, cfg.ProxyUpstream})
	}
	if len(cfg.ProxyPreserveHeaders) == 0 {
		checks = append(checks, doctorCheck{"proxy headers", doctorWarn, "proxy_preserve_headers is empty; upstream auth headers may be dropped by future policy changes"})
	} else {
		checks = append(checks, doctorCheck{"proxy headers", doctorOK, strings.Join(cfg.ProxyPreserveHeaders, ", ")})
	}
	if len(cfg.ProxyPassthroughTokens) > 0 {
		checks = append(checks, doctorCheck{"passthrough tokens", doctorWarn, fmt.Sprintf("%d exact token(s) exempt from body redaction", len(cfg.ProxyPassthroughTokens))})
	}
	return checks
}

func checkWatchRules(home string, cfg config.Config) []doctorCheck {
	rules := watch.DefaultRules(home)
	if cfg.Watch != nil {
		rules = nil
		for _, r := range cfg.Watch {
			rules = append(rules, watch.Rule{Path: r.Path, Action: watch.Action(r.Action)})
		}
	}
	existing := 0
	for _, r := range rules {
		if _, err := os.Stat(r.Path); err == nil {
			existing++
		}
	}
	if len(rules) == 0 {
		return []doctorCheck{{"watch rules", doctorWarn, "no watch rules configured"}}
	}
	if existing == 0 {
		return []doctorCheck{{"watch rules", doctorWarn, fmt.Sprintf("%d configured, none currently exist", len(rules))}}
	}
	return []doctorCheck{{"watch rules", doctorOK, fmt.Sprintf("%d configured, %d existing", len(rules), existing)}}
}

func checkAgentHints(home, listen string) []doctorCheck {
	var checks []doctorCheck
	localBase := "http://" + listen
	hints := []struct {
		name string
		path string
	}{
		{"Claude local settings", filepath.Join(home, ".claude", "settings.json")},
		{"Codex config", filepath.Join(home, ".codex", "config.toml")},
	}
	for _, h := range hints {
		data, err := os.ReadFile(h.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				checks = append(checks, doctorCheck{h.name, doctorWarn, h.path + " not found; verify agent base URL manually"})
				continue
			}
			checks = append(checks, doctorCheck{h.name, doctorWarn, err.Error()})
			continue
		}
		if strings.Contains(string(data), localBase) {
			checks = append(checks, doctorCheck{h.name, doctorOK, "references " + localBase})
		} else {
			checks = append(checks, doctorCheck{h.name, doctorWarn, "does not reference " + localBase})
		}
	}
	return checks
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func printDoctor(w io.Writer, checks []doctorCheck) int {
	fails := 0
	for _, c := range checks {
		label := "ok"
		switch c.Severity {
		case doctorWarn:
			label = "warn"
		case doctorFail:
			label = "fail"
			fails++
		}
		fmt.Fprintf(w, "[%s] %-24s %s\n", label, c.Name, c.Message)
	}
	return fails
}
