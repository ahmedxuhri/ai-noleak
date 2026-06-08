//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// checkPeerCred enforces same-UID access on Linux using SO_PEERCRED getsockopt.
func checkPeerCred(uc *net.UnixConn) error {
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return err
	}
	if inner != nil {
		return inner
	}
	if cred.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("uid mismatch: peer=%d self=%d", cred.Uid, os.Getuid())
	}
	return nil
}
