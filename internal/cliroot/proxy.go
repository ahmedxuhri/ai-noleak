package cliroot

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"noleak/internal/config"
	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/proxy"
	"noleak/internal/vault"
)

// newProxyCmd starts the L2 local API proxy. Loads ~/.noleak/config.yaml
// for upstream URL and listen address. Vault and detector are constructed
// fresh in this process and shared with the daemon via the same on-disk
// vault file (vault.OpenFile) — both processes read the same encrypted
// blob, but only one writes (the daemon). We open in read-only mode for
// the proxy by treating it as a separate vault instance.
//
// In v0 the proxy and daemon both load the vault directly from disk. This
// works because the file is small and re-read on each scan via the AC
// stage's SetExactValues. A future refactor may have the proxy talk to
// the daemon via IPC instead, removing the duplicate-load pattern.
func newProxyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "proxy",
		Short: "Run the L2 local API proxy (mask + forward to upstream)",
		Long:  "Reads upstream URL and listen address from ~/.noleak/config.yaml.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProxy()
		},
	}
	return c
}

func runProxy() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfg, err := config.Load(home)
	if err != nil {
		return err
	}
	if cfg.ProxyUpstream == "" {
		return fmt.Errorf("proxy: set proxy_upstream in %s before starting", config.Path(home))
	}

	// Use the daemon's IPC vault rather than re-opening on disk: the daemon
	// is the single writer, and we want both processes to see live updates.
	// Talking to the daemon over UDS adds one round-trip per scan but keeps
	// data consistent across mutations from any source (paste, harvest,
	// review).
	client := ipc.NewClient(cfg.SocketPath)

	master, err := vault.NewMasterSecret()
	if err != nil {
		return err
	}

	srv, err := proxy.New(proxy.Config{
		ListenAddr:          cfg.ProxyListen,
		Upstream:            cfg.ProxyUpstream,
		Vault:               &daemonProxyVault{client: client},
		Detector:            detect.New(detect.Options{}),
		MasterSecret:        master,
		AutoRegisterMinConf: cfg.AutoRegisterMinConf,
		Notify: func(ev proxy.Event) {
			fmt.Fprintf(os.Stderr, "[noleak proxy] %s %s %s -> %s (kind=%s, conf=%.2f)\n",
				ev.When.Format("15:04:05"), ev.Direction, ev.Path, ev.Placeholder, ev.Kind, ev.Confidence)
		},
		RequestLog: func(ev proxy.RequestEvent) {
			fmt.Fprintf(os.Stderr, "[noleak proxy] %s %s %s -> %s [%d]\n",
				ev.When.Format("15:04:05"), ev.Method, ev.Path, ev.UpstreamPath, ev.Status)
		},
	})
	if err != nil {
		return err
	}
	if _, err := srv.Listen(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "noleak proxy listening on %s -> %s\n", cfg.ProxyListen, cfg.ProxyUpstream)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return srv.Serve(ctx)
}
