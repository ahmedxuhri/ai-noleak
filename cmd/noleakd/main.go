// Command noleakd runs the noleak daemon: vault, IPC, detector hot path.
//
// Master-key sourcing:
//   - passphrase mode (default for VPS): reads a passphrase from --pass-fd
//     or NOLEAK_PASSPHRASE_FD on start. Derives the AES-256 key via Argon2id
//     and opens the encrypted file vault. Salt persists at ~/.noleak/salt.bin.
//   - kernel-keyring mode (Linux opt-in): fetches a previously-planted key
//     from the user keyring; no passphrase needed at start.
//   - libsecret mode: not yet implemented.
//
// See SPEC.md §4.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"noleak/internal/config"
	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/keymgr"
	"noleak/internal/vault"
)

const version = "0.0.0-dev"

func main() {
	var (
		passFd  = flag.Int("pass-fd", -1, "file descriptor to read passphrase from (passphrase mode)")
		ephem   = flag.Bool("ephemeral", false, "in-memory vault; no persistence (development only)")
	)
	flag.Parse()

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("noleakd: home: %v", err)
	}
	cfg, err := config.Load(home)
	if err != nil {
		log.Fatalf("noleakd: config: %v", err)
	}
	if err := config.Validate(cfg); err != nil {
		log.Fatalf("noleakd: %v", err)
	}

	v, err := openVault(cfg, *passFd, *ephem)
	if err != nil {
		log.Fatalf("noleakd: vault: %v", err)
	}

	master, err := vault.NewMasterSecret()
	if err != nil {
		log.Fatalf("noleakd: master secret: %v", err)
	}

	server := ipc.NewServer(ipc.ServerConfig{
		SocketPath:   cfg.SocketPath,
		Vault:        v,
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
		Version:      version,
	})

	if _, err := server.Listen(); err != nil {
		log.Fatalf("noleakd: listen: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "noleakd %s — listening on %s (vault: %s)\n", version, cfg.SocketPath, vaultDescription(*ephem, cfg))
	if err := server.Serve(ctx, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "noleakd: "+format+"\n", args...)
	}); err != nil {
		log.Fatalf("noleakd: serve: %v", err)
	}
	if err := v.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "noleakd: vault close: %v\n", err)
	}
	fmt.Fprintln(os.Stderr, "noleakd: shutdown")
}

// openVault opens the persistent vault using the configured master-key mode,
// or returns an in-memory vault when --ephemeral is set.
func openVault(cfg config.Config, passFd int, ephemeral bool) (vault.Vault, error) {
	if ephemeral {
		fmt.Fprintln(os.Stderr, "noleakd: WARNING — running with --ephemeral; vault will not persist across restarts")
		return vault.NewMemory(), nil
	}

	dataDir := dirOf(cfg.VaultPath)
	mode := keymgr.Mode(cfg.MasterKeyMode)

	var pass []byte
	if mode == keymgr.ModePassphrase {
		fd := passFd
		if fd < 0 {
			if v := os.Getenv("NOLEAK_PASSPHRASE_FD"); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					fd = n
				}
			}
		}
		if fd < 0 {
			return nil, fmt.Errorf("passphrase mode requires --pass-fd or NOLEAK_PASSPHRASE_FD; pipe the passphrase via `noleak unlock | noleakd --pass-fd 0`")
		}
		buf, err := io.ReadAll(os.NewFile(uintptr(fd), "passphrase"))
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		pass = trimNewline(buf)
		if len(pass) == 0 {
			return nil, fmt.Errorf("empty passphrase on fd %d", fd)
		}
	}

	key, err := keymgr.Resolve(mode, dataDir, pass)
	if err != nil {
		return nil, err
	}
	return vault.OpenFile(cfg.VaultPath, key)
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func vaultDescription(ephemeral bool, cfg config.Config) string {
	if ephemeral {
		return "ephemeral memory"
	}
	return cfg.VaultPath + " (" + cfg.MasterKeyMode + ")"
}
