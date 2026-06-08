//go:build darwin

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeerCred enforces same-UID access on macOS using LOCAL_PEERCRED getsockopt.
func checkPeerCred(uc *net.UnixConn) error {
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
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
