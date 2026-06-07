package ipc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"noleak/internal/detect"
	"noleak/internal/vault"
)

// Server hosts the daemon on a Unix domain socket.
type Server struct {
	socketPath   string
	vault        vault.Vault
	detector     *detect.Detector
	masterSecret []byte
	startedAt    time.Time
	version      string

	mu      sync.Mutex
	ln      net.Listener
	stopped atomic.Bool
}

// ServerConfig is what cmd/noleakd builds before calling Listen.
type ServerConfig struct {
	SocketPath   string
	Vault        vault.Vault
	Detector     *detect.Detector
	MasterSecret []byte
	Version      string
}

// NewServer constructs a server. Listen has not yet been called.
func NewServer(cfg ServerConfig) *Server {
	return &Server{
		socketPath:   cfg.SocketPath,
		vault:        cfg.Vault,
		detector:     cfg.Detector,
		masterSecret: cfg.MasterSecret,
		startedAt:    time.Now().UTC(),
		version:      cfg.Version,
	}
}

// Listen begins accepting connections. Removes any stale socket file at the
// configured path, creates the new one with mode 0600, and returns the
// underlying net.Listener for caller-controlled shutdown.
func (s *Server) Listen() (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove any stale socket from a previous run. The parent dir is the
	// caller's responsibility (typically ~/.noleak/, mode 0700).
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
	}

	// Mask file mode so the new socket is owner-only regardless of umask.
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", s.socketPath)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: chmod socket: %w", err)
	}
	s.ln = ln
	return ln, nil
}

// Serve accepts connections until ctx is cancelled or the listener is closed.
// Each connection is handled in its own goroutine. Per-connection errors are
// not surfaced; they are logged via the optional logger if provided.
func (s *Server) Serve(ctx context.Context, log func(format string, args ...any)) error {
	ln := s.ln
	if ln == nil {
		return errors.New("ipc: Serve called before Listen")
	}
	if log == nil {
		log = func(string, ...any) {}
	}

	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.stopped.Load() {
				return nil
			}
			return fmt.Errorf("ipc: accept: %w", err)
		}
		go s.handle(c, log)
	}
}

// handle services one connection. The protocol is one-shot: a single request
// returns a single response, then the connection closes.
func (s *Server) handle(c net.Conn, log func(string, ...any)) {
	defer c.Close()

	// Reject non-matching peer UID. UDS does not authenticate by default;
	// SO_PEERCRED gives us the peer's credentials at connect time.
	uc, ok := c.(*net.UnixConn)
	if !ok {
		log("ipc: non-unix connection rejected")
		return
	}
	if err := checkPeerCred(uc); err != nil {
		log("ipc: peer-cred reject: %v", err)
		return
	}

	c.SetDeadline(time.Now().Add(30 * time.Second))

	req, err := ReadRequest(c)
	if err != nil {
		log("ipc: read: %v", err)
		return
	}
	resp := s.dispatch(req)
	if err := WriteResponse(c, resp); err != nil {
		log("ipc: write: %v", err)
	}
}

// checkPeerCred enforces same-UID access. Returns nil iff the peer's effective
// UID equals the daemon's own UID.
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

// dispatch routes a request to the appropriate handler.
func (s *Server) dispatch(req *Request) *Response {
	switch req.Op {
	case OpScan:
		return s.handleScan(req.Scan)
	case OpResolve:
		return s.handleResolve(req.Resolve)
	case OpRegister:
		return s.handleRegister(req.Register)
	case OpBind:
		return s.handleBind(req.Bind, true)
	case OpUnbind:
		return s.handleBind(req.Unbind, false)
	case OpList:
		return s.handleList()
	case OpRotate:
		return s.handleRotate(req.Rotate)
	case OpDelete:
		return s.handleDelete(req.Delete)
	case OpHealth:
		return s.handleHealth()
	default:
		return &Response{Error: "unknown op: " + req.Op}
	}
}

func (s *Server) handleScan(req *ScanRequest) *Response {
	if req == nil {
		return &Response{Error: "scan: missing payload"}
	}
	raw, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		return &Response{Error: "scan: decode: " + err.Error()}
	}

	// Keep the AC stage in sync with the vault before scanning.
	s.detector.SetExactValues(toStrings(s.vault.Values()))

	matches := s.detector.Scan(raw)

	// Resolve each match to a placeholder. AC hits map directly via the value
	// in input; regex/entropy/context hits at high confidence get auto-
	// registered when AutoRegister is set, populating .Placeholder so the
	// redacted output uses the stable token.
	ipcMatches := make([]Match, 0, len(matches))
	for _, m := range matches {
		val := string(raw[m.Start:m.End])
		var placeholder string
		switch {
		case m.Source == "ac":
			placeholder = vault.MakePlaceholder(val, s.masterSecret)
			s.vault.MarkUse(placeholder)
		case req.AutoRegister && m.Confidence >= 0.85:
			e, err := s.vault.Register(val, m.Kind, "auto:"+m.Source, nil, s.masterSecret)
			if err == nil {
				placeholder = e.Placeholder
			}
		}
		ipcMatches = append(ipcMatches, Match{
			Start: m.Start, End: m.End,
			Kind: m.Kind, Source: m.Source, Confidence: m.Confidence,
			Placeholder: placeholder,
		})
	}

	redacted := redactInPlace(raw, ipcMatches)

	return &Response{
		Scan: &ScanResponse{
			Matches:     ipcMatches,
			RedactedB64: base64.StdEncoding.EncodeToString(redacted),
		},
	}
}

// redactInPlace returns a copy of input with each placeholder-bearing match
// replaced by its placeholder string. Overlap policy: longest match wins.
func redactInPlace(input []byte, matches []Match) []byte {
	if len(matches) == 0 {
		return append([]byte(nil), input...)
	}
	// Resolve overlap: sort by start asc, then by length desc; keep matches
	// that don't overlap a previously-kept match.
	sorted := append([]Match(nil), matches...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return (sorted[i].End - sorted[i].Start) > (sorted[j].End - sorted[j].Start)
	})
	kept := sorted[:0]
	cursor := -1
	for _, m := range sorted {
		if m.Placeholder == "" {
			continue
		}
		if m.Start < cursor {
			continue
		}
		kept = append(kept, m)
		cursor = m.End
	}

	var out []byte
	pos := 0
	for _, m := range kept {
		out = append(out, input[pos:m.Start]...)
		out = append(out, []byte(m.Placeholder)...)
		pos = m.End
	}
	out = append(out, input[pos:]...)
	return out
}

func (s *Server) handleResolve(req *ResolveRequest) *Response {
	if req == nil {
		return &Response{Error: "resolve: missing payload"}
	}
	val, err := s.vault.Resolve(req.Placeholder, req.DestHost)
	if err != nil {
		return &Response{Error: err.Error()}
	}
	s.vault.MarkUse(req.Placeholder)
	return &Response{Resolve: &ResolveResponse{Value: val}}
}

func (s *Server) handleRegister(req *RegisterRequest) *Response {
	if req == nil {
		return &Response{Error: "register: missing payload"}
	}
	e, err := s.vault.Register(req.Value, req.Kind, req.Source, req.Bindings, s.masterSecret)
	if err != nil {
		return &Response{Error: err.Error()}
	}
	return &Response{Register: &RegisterResponse{Placeholder: e.Placeholder}}
}

func (s *Server) handleBind(req *BindRequest, add bool) *Response {
	if req == nil {
		return &Response{Error: "bind: missing payload"}
	}
	var err error
	if add {
		err = s.vault.Bind(req.Placeholder, req.Hosts)
	} else {
		err = s.vault.Unbind(req.Placeholder, req.Hosts)
	}
	if err != nil {
		return &Response{Error: err.Error()}
	}
	return &Response{OK: true}
}

func (s *Server) handleList() *Response {
	es, err := s.vault.List(false)
	if err != nil {
		return &Response{Error: err.Error()}
	}
	out := make([]ListEntry, 0, len(es))
	for _, e := range es {
		out = append(out, ListEntry{
			Placeholder:  e.Placeholder,
			Kind:         e.Kind,
			Source:       e.Source,
			Bindings:     e.Bindings,
			Status:       string(e.Status),
			RegisteredAt: e.RegisteredAt.Format(time.RFC3339),
			Uses:         e.Uses,
		})
	}
	return &Response{List: &ListResponse{Entries: out}}
}

func (s *Server) handleRotate(req *RotateRequest) *Response {
	if req == nil {
		return &Response{Error: "rotate: missing payload"}
	}
	if err := s.vault.Rotate(req.Placeholder, req.NewValue); err != nil {
		return &Response{Error: err.Error()}
	}
	return &Response{OK: true}
}

func (s *Server) handleDelete(req *DeleteRequest) *Response {
	if req == nil {
		return &Response{Error: "delete: missing payload"}
	}
	if err := s.vault.Delete(req.Placeholder); err != nil {
		return &Response{Error: err.Error()}
	}
	return &Response{OK: true}
}

func (s *Server) handleHealth() *Response {
	es, _ := s.vault.List(false)
	pending := 0
	for _, e := range es {
		if e.Status == vault.StatusPendingReview {
			pending++
		}
	}
	return &Response{Health: &HealthResponse{
		Version:       s.version,
		Unlocked:      true,
		VaultEntries:  len(es),
		PendingReview: pending,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
	}}
}

func toStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}
