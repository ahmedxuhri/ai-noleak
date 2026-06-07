//go:build !linux

package keymgr

import "errors"

func resolveKernelKeyring() ([]byte, error) {
	return nil, errors.New("keymgr: kernel-keyring mode is Linux-only")
}

// PlantInKeyring is a stub on non-Linux platforms.
func PlantInKeyring(key []byte) error {
	return errors.New("keymgr: kernel-keyring mode is Linux-only")
}
