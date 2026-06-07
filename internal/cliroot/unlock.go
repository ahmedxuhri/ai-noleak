package cliroot

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"noleak/internal/config"
	"noleak/internal/keymgr"
)

// unlockCommand returns the cobra command for `noleak unlock`. Renamed
// from newUnlockCmd to avoid colliding with the stub in cmds.go; cmds.go
// re-exports this through newUnlockCmd to preserve the registration order.
func unlockCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the noleak vault: prompt for passphrase, write to stdout (or plant in kernel keyring)",
		Long:  "Pipe into the daemon: `noleak unlock | noleakd --pass-fd 0`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			cfg, err := config.Load(home)
			if err != nil {
				return err
			}
			if err := config.Validate(cfg); err != nil {
				return err
			}

			switch keymgr.Mode(cfg.MasterKeyMode) {
			case keymgr.ModePassphrase:
				return unlockPassphrase()
			case keymgr.ModeKernelKeyring:
				return unlockKernelKeyring(dirOfPath(cfg.VaultPath))
			case keymgr.ModeLibsecret:
				return fmt.Errorf("libsecret mode not yet implemented; switch to passphrase or kernel-keyring in %s",
					config.Path(home))
			default:
				return fmt.Errorf("unknown master_key_mode %q", cfg.MasterKeyMode)
			}
		},
	}
	return c
}

// unlockPassphrase reads the passphrase from /dev/tty without echo and
// writes it (with a trailing newline) to stdout.
func unlockPassphrase() error {
	pass, err := readPassphrase("noleak vault passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		return fmt.Errorf("empty passphrase")
	}
	_, err = fmt.Println(string(pass))
	return err
}

// unlockKernelKeyring derives the key and plants it in the Linux user
// keyring. Subsequent noleakd starts read it back without re-prompting.
func unlockKernelKeyring(dataDir string) error {
	pass, err := readPassphrase("noleak vault passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		return fmt.Errorf("empty passphrase")
	}
	key, err := keymgr.Resolve(keymgr.ModePassphrase, dataDir, pass)
	if err != nil {
		return err
	}
	if err := keymgr.PlantInKeyring(key); err != nil {
		return fmt.Errorf("plant: %w", err)
	}
	fmt.Fprintln(os.Stderr, "key planted in kernel keyring as noleak:master")
	return nil
}

// readPassphrase prompts on stderr and reads from /dev/tty (so we work even
// when stdin is being piped into the daemon).
func readPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Fall back to stdin if /dev/tty isn't available (CI, containers).
		tty = os.Stdin
	} else {
		defer tty.Close()
	}
	if !term.IsTerminal(int(tty.Fd())) {
		fmt.Fprintln(os.Stderr, " (input not a TTY; reading raw line)")
		var buf [4096]byte
		n, _ := tty.Read(buf[:])
		return trimNewline(buf[:n]), nil
	}
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	return pass, err
}

func dirOfPath(p string) string {
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
