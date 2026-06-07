//go:build linux

package keymgr

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// resolveKernelKeyring fetches the noleak master key from the Linux user
// keyring (KEY_SPEC_USER_KEYRING). Requires the key to have been planted
// previously by `noleak unlock --kernel-keyring`, which derives it via
// the same Argon2 path the passphrase mode uses, then plants it under the
// description "noleak:master".
//
// The key dies when the user logs out (or sooner if `keyctl revoke` is run).
// This is the right behavior for headless VPSes: the daemon survives reboots
// only if the user explicitly re-unlocks.
const kernelKeyDescription = "noleak:master"

func resolveKernelKeyring() ([]byte, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", kernelKeyDescription, 0)
	if err != nil {
		return nil, fmt.Errorf("keymgr: keyring lookup %q: %w (run `noleak unlock --kernel-keyring`?)", kernelKeyDescription, err)
	}
	buf := make([]byte, keyLen)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("keymgr: keyring read: %w", err)
	}
	if n != keyLen {
		return nil, fmt.Errorf("keymgr: keyring returned %d bytes, expected %d", n, keyLen)
	}
	return buf, nil
}

// PlantInKeyring stores key in the user keyring. Used by `noleak unlock
// --kernel-keyring` after deriving the key from a passphrase.
func PlantInKeyring(key []byte) error {
	if len(key) != keyLen {
		return errors.New("keymgr: bad key length for keyring plant")
	}
	if _, err := unix.AddKey("user", kernelKeyDescription, key, unix.KEY_SPEC_USER_KEYRING); err != nil {
		return fmt.Errorf("keymgr: keyring plant: %w", err)
	}
	return nil
}

// silence unused-import warnings if we strip optional code paths
var _ = os.Stat
