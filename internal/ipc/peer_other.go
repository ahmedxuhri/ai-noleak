//go:build !linux && !darwin

package ipc

import (
	"net"
)

// checkPeerCred is a fallback noop for unsupported platforms.
func checkPeerCred(uc *net.UnixConn) error {
	return nil
}
