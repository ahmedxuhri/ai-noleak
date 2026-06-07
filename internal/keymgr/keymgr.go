// Package keymgr resolves the master encryption key the vault uses. Three
// modes are supported, in order of decreasing portability:
//
//   "passphrase"     — derive key from a user-entered passphrase via Argon2id.
//                      Default for VPS deployments. Requires `noleak unlock`
//                      once per daemon start; the derived key lives in
//                      process memory only.
//
//   "kernel-keyring" — fetch key from the Linux user keyring (keyctl).
//                      Pure Go via golang.org/x/sys/unix. Survives until
//                      the user logs out; no daemon required. Requires the
//                      key to have been added previously via `noleak unlock`.
//
//   "libsecret"      — fetch key from the freedesktop.org Secret Service
//                      via D-Bus. Works on Linux desktops with gnome-keyring
//                      or KeePassXC running. NOT generally available on
//                      headless VPSes. Implementation deferred (see TODO);
//                      callers requesting it on a host without secret
//                      service get a clear error pointing at passphrase.
//
// The Argon2 parameters here are conservative: 64 MiB memory, 3 iterations,
// 4 lanes. Tunable via env (NOLEAK_ARGON2_MEM_MIB / TIME / LANES) if the
// host can't spare the RAM, but the defaults are appropriate for any VPS
// big enough to run a coding agent.
package keymgr

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// Mode names a sourcing strategy.
type Mode string

const (
	ModePassphrase    Mode = "passphrase"
	ModeKernelKeyring Mode = "kernel-keyring"
	ModeLibsecret     Mode = "libsecret"
)

// argon2 parameters. 32-byte derived key (matches AES-256). Salt lives in
// the vault directory under salt.bin (0600); regenerated once at unlock
// time and persisted so the same passphrase reproducibly derives the same
// key across daemon restarts.
const (
	keyLen = 32
	salt   = "salt.bin"
)

const (
	defMemMiB = 64
	defTime   = 3
	defLanes  = 4
)

// Resolve returns the 32-byte key for the given mode. For passphrase mode
// the caller MUST provide passphrase; for kernel-keyring mode passphrase is
// ignored. For libsecret mode (TODO) returns an error.
//
// dataDir is the vault directory (e.g. ~/.noleak/) used to persist salts.
func Resolve(mode Mode, dataDir string, passphrase []byte) ([]byte, error) {
	switch mode {
	case ModePassphrase:
		return resolvePassphrase(dataDir, passphrase)
	case ModeKernelKeyring:
		return resolveKernelKeyring()
	case ModeLibsecret:
		return nil, errors.New("keymgr: libsecret mode not yet implemented (use passphrase or kernel-keyring on headless hosts)")
	default:
		return nil, fmt.Errorf("keymgr: unknown mode %q", mode)
	}
}

// resolvePassphrase derives the key from passphrase + salt via Argon2id.
// On first call the salt is generated and persisted; subsequent calls
// reuse it so the same passphrase always derives the same key.
func resolvePassphrase(dataDir string, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keymgr: empty passphrase")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("keymgr: mkdir: %w", err)
	}
	saltPath := filepath.Join(dataDir, salt)
	saltBytes, err := loadOrCreateSalt(saltPath)
	if err != nil {
		return nil, err
	}

	mem := uint32(envOr("NOLEAK_ARGON2_MEM_MIB", defMemMiB)) * 1024 // KiB
	time := uint32(envOr("NOLEAK_ARGON2_TIME", defTime))
	lanes := uint8(envOr("NOLEAK_ARGON2_LANES", defLanes))

	return argon2.IDKey(passphrase, saltBytes, time, mem, lanes, keyLen), nil
}

func loadOrCreateSalt(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) < 16 {
			return nil, errors.New("keymgr: salt file truncated")
		}
		return data, nil
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keymgr: salt: %w", err)
	}
	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return nil, fmt.Errorf("keymgr: write salt: %w", err)
	}
	return salt, nil
}

func envOr(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
