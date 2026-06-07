package ipc

import (
	"fmt"
	"net"
	"time"
)

// Client is a minimal one-shot client for the daemon socket. Each call dials,
// sends one request, reads one response, and closes the connection. Cheap on
// a UDS; no need for connection pooling at this scale.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// NewClient constructs a client with sensible defaults.
func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 10 * time.Second}
}

// Call sends req and returns the daemon's response.
func (c *Client) Call(req *Request) (*Response, error) {
	dialer := net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.Dial("unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))

	if err := WriteRequest(conn, req); err != nil {
		return nil, err
	}
	return ReadResponse(conn)
}
