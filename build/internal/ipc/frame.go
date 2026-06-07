package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Maximum request/response size. 16 MiB is far above any legitimate body
// (a 200 KB conversation transcript is the practical worst case) and far
// below anything that would let a malformed length cause memory pressure.
const MaxFrame = 16 << 20

var errFrameTooLarge = errors.New("frame exceeds MaxFrame")

// WriteFrame writes a length-prefixed payload. Big-endian uint32, then bytes.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return errFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("ipc: write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("ipc: write body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed payload. Returns io.EOF on a clean
// connection close before any header bytes have arrived.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, errFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("ipc: read body: %w", err)
	}
	return buf, nil
}

// WriteRequest marshals req to JSON and writes a single frame.
func WriteRequest(w io.Writer, req *Request) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("ipc: marshal request: %w", err)
	}
	return WriteFrame(w, b)
}

// ReadRequest reads one frame and unmarshals it into a Request.
func ReadRequest(r io.Reader) (*Request, error) {
	b, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("ipc: unmarshal request: %w", err)
	}
	return &req, nil
}

// WriteResponse marshals resp to JSON and writes a single frame.
func WriteResponse(w io.Writer, resp *Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("ipc: marshal response: %w", err)
	}
	return WriteFrame(w, b)
}

// ReadResponse reads one frame and unmarshals it into a Response.
func ReadResponse(r io.Reader) (*Response, error) {
	b, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("ipc: unmarshal response: %w", err)
	}
	return &resp, nil
}
