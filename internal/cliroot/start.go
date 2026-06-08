package cliroot

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"noleak/internal/config"
	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/keymgr"
	"noleak/internal/proxy"
	"noleak/internal/vault"
	"noleak/internal/watch"
)

func newStartCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "start",
		Short: "Start all noleak services concurrently (daemon, proxy, watcher) in a single command",
		Long:  "Runs the vault daemon, HTTP proxy, and file watcher in the background as goroutines, sharing stdout/stderr.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ephemeral, _ := cmd.Flags().GetBool("ephemeral")
			extraRedact, _ := cmd.Flags().GetStringSlice("redact")
			extraPurge, _ := cmd.Flags().GetStringSlice("purge")
			return runStart(ephemeral, extraRedact, extraPurge)
		},
	}
	c.Flags().Bool("ephemeral", false, "run vault in-memory only (good for temporary testing)")
	c.Flags().StringSlice("redact", nil, "extra path(s) to watch and redact")
	c.Flags().StringSlice("purge", nil, "extra path(s) to watch and purge")
	return c
}

func runStart(ephemeral bool, extraRedact, extraPurge []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home: %w", err)
	}
	cfg, err := config.Load(home)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("config validate: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. Open Vault
	v, err := startOpenVault(cfg, ephemeral)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer v.Close()

	master, err := vault.NewMasterSecret()
	if err != nil {
		return fmt.Errorf("master secret: %w", err)
	}

	// 2. Start Daemon Server
	server := ipc.NewServer(ipc.ServerConfig{
		SocketPath:   cfg.SocketPath,
		Vault:        v,
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
		Version:      version,
	})

	if _, err := server.Listen(); err != nil {
		return fmt.Errorf("ipc listen: %w", err)
	}

	errChan := make(chan error, 3)

	fmt.Fprintf(os.Stderr, "[noleakd] starting on %s (vault: %s)\n", cfg.SocketPath, startVaultDesc(ephemeral, cfg))
	go func() {
		err := server.Serve(ctx, func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[noleakd] "+format+"\n", args...)
		})
		if err != nil {
			errChan <- fmt.Errorf("daemon: %w", err)
		}
	}()

	// Wait a moment for daemon to start listening on socket
	time.Sleep(200 * time.Millisecond)

	// 3. Start Proxy (if upstream configured)
	if cfg.ProxyUpstream == "" {
		fmt.Fprintln(os.Stderr, "[proxy] WARNING: proxy_upstream is empty in config.yaml. Proxy service is disabled.")
	} else {
		client := ipc.NewClient(cfg.SocketPath)
		srv, err := proxy.New(proxy.Config{
			ListenAddr:          cfg.ProxyListen,
			Upstream:            cfg.ProxyUpstream,
			PreserveHeaders:     cfg.ProxyPreserveHeaders,
			PassthroughTokens:   cfg.ProxyPassthroughTokens,
			Vault:               &daemonProxyVault{client: client},
			Detector:            detect.New(detect.Options{}),
			MasterSecret:        master,
			AutoRegisterMinConf: cfg.AutoRegisterMinConf,
			Notify: func(ev proxy.Event) {
				fmt.Fprintf(os.Stderr, "[proxy] %s %s %s -> %s (kind=%s, conf=%.2f)\n",
					ev.When.Format("15:04:05"), ev.Direction, ev.Path, ev.Placeholder, ev.Kind, ev.Confidence)
			},
			RequestLog: func(ev proxy.RequestEvent) {
				if ev.ErrorSnippet != "" {
					fmt.Fprintf(os.Stderr, "[proxy] %s %s %s -> %s [%d] %s\n",
						ev.When.Format("15:04:05"), ev.Method, ev.Path, ev.UpstreamPath, ev.Status, ev.ErrorSnippet)
					return
				}
				fmt.Fprintf(os.Stderr, "[proxy] %s %s %s -> %s [%d]\n",
					ev.When.Format("15:04:05"), ev.Method, ev.Path, ev.UpstreamPath, ev.Status)
			},
		})
		if err != nil {
			return fmt.Errorf("proxy construct: %w", err)
		}
		if _, err := srv.Listen(); err != nil {
			return fmt.Errorf("proxy listen: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[proxy] listening on %s -> %s\n", cfg.ProxyListen, cfg.ProxyUpstream)
		go func() {
			if err := srv.Serve(ctx); err != nil {
				errChan <- fmt.Errorf("proxy: %w", err)
			}
		}()
	}

	// 4. Start Watcher
	watcherClient := ipc.NewClient(cfg.SocketPath)
	watcherLogger := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[watcher] "+format+"\n", args...)
	}
	w := watch.New(watcherClient, watcherLogger)

	// Add watch rules from config or defaults
	if len(cfg.Watch) > 0 {
		for _, rule := range cfg.Watch {
			w.AddRule(watch.Rule{
				Path:   rule.Path,
				Action: watch.Action(rule.Action),
			})
		}
	} else {
		for _, r := range watch.DefaultRules(home) {
			w.AddRule(r)
		}
	}

	// Add extra watch rules from CLI flags
	for _, p := range extraRedact {
		w.AddRule(watch.Rule{Path: p, Action: watch.ActionRedact})
	}
	for _, p := range extraPurge {
		w.AddRule(watch.Rule{Path: p, Action: watch.ActionPurge})
	}

	go func() {
		if err := w.Run(ctx); err != nil {
			errChan <- fmt.Errorf("watcher: %w", err)
		}
	}()

	// Wait for context cancellation or sub-service error
	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[noleak] shutting down services...")
		// Wait a brief moment for goroutines to clean up
		time.Sleep(300 * time.Millisecond)
		return nil
	case err := <-errChan:
		return err
	}
}

func startOpenVault(cfg config.Config, ephemeral bool) (vault.Vault, error) {
	if ephemeral {
		fmt.Fprintln(os.Stderr, "[noleakd] WARNING: running with --ephemeral; vault will not persist across restarts")
		return vault.NewMemory(), nil
	}

	dataDir := startDirOf(cfg.VaultPath)
	mode := keymgr.Mode(cfg.MasterKeyMode)

	var pass []byte
	if mode == keymgr.ModePassphrase {
		fd := -1
		if v := os.Getenv("NOLEAK_PASSPHRASE_FD"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				fd = n
			}
		}
		if fd >= 0 {
			buf, err := io.ReadAll(os.NewFile(uintptr(fd), "passphrase"))
			if err != nil {
				return nil, fmt.Errorf("read passphrase from fd %d: %w", fd, err)
			}
			pass = startTrimNewline(buf)
		} else {
			// Read passphrase interactively from TTY
			p, err := readPassphrase("noleak vault passphrase: ")
			if err != nil {
				return nil, fmt.Errorf("read passphrase: %w", err)
			}
			pass = p
		}
		if len(pass) == 0 {
			return nil, fmt.Errorf("empty passphrase")
		}
	}

	key, err := keymgr.Resolve(mode, dataDir, pass)
	if err != nil {
		return nil, err
	}
	return vault.OpenFile(cfg.VaultPath, key)
}

func startDirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func startTrimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func startVaultDesc(ephemeral bool, cfg config.Config) string {
	if ephemeral {
		return "ephemeral memory"
	}
	return cfg.VaultPath + " (" + cfg.MasterKeyMode + ")"
}
