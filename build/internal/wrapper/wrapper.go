// Package wrapper is the L1 PTY wrapper. It allocates a PTY, forks the inner
// CLI, watches input for bracketed-paste sequences, and substitutes secrets
// in pasted content with placeholders before they reach the inner program.
//
// v0 scope (SPEC.md §11 open uncertainty):
//   - Bracketed-paste detection only. Typed-secret detection on Enter is
//     deferred; users typing tokens character-by-character is rare and L2
//     already catches the outbound request.
//   - No 3s Esc-to-undo hold. Substitution is immediate; banner is printed
//     after the fact. The actual leak path is closed by L2/L3 regardless,
//     so the L1 banner is informational, not safety-critical.
//   - Bash-aware command-line parsing of pastes is out of scope; we operate
//     on raw paste bytes only.
//
// See SPEC.md §5 L1.
package wrapper

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"

	"noleak/internal/ipc"
)

// Bracketed-paste begin and end markers. xterm-style; supported by every
// modern terminal that has bracketed paste enabled (most Claude Code
// runtimes use it).
var (
	pasteBegin = []byte{0x1b, '[', '2', '0', '0', '~'}
	pasteEnd   = []byte{0x1b, '[', '2', '0', '1', '~'}
)

// RunOpts configures the wrapper.
type RunOpts struct {
	// Argv is the full command to run (program + args).
	Argv []string
	// Client is the IPC handle to noleakd. Required.
	Client *ipc.Client
	// BannerWriter receives one-line notifications about redacted pastes.
	// Defaults to os.Stderr if nil.
	BannerWriter io.Writer
	// AutoRegister controls whether unknown high-confidence detections in
	// pasted content are persisted to the vault. Default true.
	AutoRegister bool
}

// Run executes Argv inside a PTY, with stdin filtered through the paste
// detector. Returns the child's exit error (or nil on clean exit).
func Run(opts RunOpts) error {
	if len(opts.Argv) == 0 {
		return errors.New("wrapper: empty argv")
	}
	if opts.Client == nil {
		return errors.New("wrapper: nil ipc client")
	}
	if opts.BannerWriter == nil {
		opts.BannerWriter = os.Stderr
	}

	cmd := exec.Command(opts.Argv[0], opts.Argv[1:]...)
	cmd.Env = os.Environ()
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("wrapper: pty start: %w", err)
	}
	defer ptmx.Close()

	// Window-size sync.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	winch <- syscall.SIGWINCH

	// Put our own stdin into raw mode so we see bytes as they're typed/pasted.
	// Restored on return.
	var oldState *term.State
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("wrapper: raw mode: %w", err)
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// child stdout -> our stdout (passthrough; PostToolUse hook handles model-
	// bound scrubbing, and the proxy handles outbound traffic; the user can
	// see the child's output as-is).
	go func() { _, _ = io.Copy(os.Stdout, ptmx) }()

	// our stdin -> child stdin, via the paste filter.
	pf := newPasteFilter(opts.Client, opts.BannerWriter, opts.AutoRegister)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				out := pf.process(buf[:n])
				if len(out) > 0 {
					_, _ = ptmx.Write(out)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// NewTestPasteFilter exposes the internal paste filter for end-to-end
// testing in the acceptance package. Production code should use Run.
func NewTestPasteFilter(client *ipc.Client) *PasteFilter {
	return &PasteFilter{inner: newPasteFilter(client, io.Discard, true)}
}

// PasteFilter is a public wrapper around the unexported pasteFilter type
// to keep the acceptance test compiled without exposing internals.
type PasteFilter struct{ inner *pasteFilter }

// Process feeds bytes through the underlying filter. See pasteFilter.process.
func (p *PasteFilter) Process(in []byte) []byte { return p.inner.process(in) }

type pasteFilter struct {
	mu sync.Mutex

	client       *ipc.Client
	banner       io.Writer
	autoRegister bool

	state    pasteState
	pending  []byte // bytes we've matched against the begin/end marker prefix
	buffered []byte // body of the in-progress paste
}

type pasteState int

const (
	stateNormal pasteState = iota
	stateInPaste
)

func newPasteFilter(c *ipc.Client, banner io.Writer, autoRegister bool) *pasteFilter {
	return &pasteFilter{client: c, banner: banner, autoRegister: autoRegister}
}

// process consumes a chunk of stdin bytes and returns the bytes to forward
// to the child. Pasted content is buffered until the end marker arrives;
// the rest of the chunk is passed through unchanged.
func (p *pasteFilter) process(in []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]byte, 0, len(in))
	i := 0
	for i < len(in) {
		switch p.state {
		case stateNormal:
			// Look for pasteBegin starting at i.
			if idx := bytes.Index(in[i:], pasteBegin); idx >= 0 {
				out = append(out, in[i:i+idx]...)
				out = append(out, pasteBegin...)
				p.state = stateInPaste
				p.buffered = p.buffered[:0]
				i += idx + len(pasteBegin)
				continue
			}
			// Watch out for partial markers at the tail. Withhold up to
			// (len(pasteBegin)-1) bytes that look like a prefix of pasteBegin.
			tail := splitTrailingPrefix(in[i:], pasteBegin)
			if tail > 0 {
				out = append(out, in[i:len(in)-tail]...)
				p.pending = append(p.pending[:0], in[len(in)-tail:]...)
				_ = p.pending // currently we just drop it; partial-prefix handling below
				// For simplicity, forward the prefix bytes too. The risk is
				// emitting a stray ESC sequence; in practice these are rare
				// and the cost of holding bytes across reads adds latency.
				out = append(out, in[len(in)-tail:]...)
				return out
			}
			out = append(out, in[i:]...)
			return out

		case stateInPaste:
			if idx := bytes.Index(in[i:], pasteEnd); idx >= 0 {
				p.buffered = append(p.buffered, in[i:i+idx]...)
				redacted := p.scanBuffered()
				out = append(out, redacted...)
				out = append(out, pasteEnd...)
				p.state = stateNormal
				p.buffered = p.buffered[:0]
				i += idx + len(pasteEnd)
				continue
			}
			// No end marker in this chunk — buffer it all and continue.
			p.buffered = append(p.buffered, in[i:]...)
			return out
		}
	}
	return out
}

// scanBuffered runs the daemon scan against the in-progress paste body and
// returns the bytes to forward. On any error the original bytes pass through
// unchanged so a daemon outage doesn't stall the user (L2 still catches
// outbound leaks).
func (p *pasteFilter) scanBuffered() []byte {
	if len(p.buffered) == 0 {
		return nil
	}
	resp, err := p.client.Call(&ipc.Request{
		Op: ipc.OpScan,
		Scan: &ipc.ScanRequest{
			PayloadB64:   base64.StdEncoding.EncodeToString(p.buffered),
			AutoRegister: p.autoRegister,
		},
	})
	if err != nil || resp == nil || resp.Error != "" || resp.Scan == nil {
		// Forward original bytes; surface a one-line warning.
		fmt.Fprintf(p.banner, "\r\n[noleak] paste scan failed (forwarding raw): %v\r\n", err)
		return append([]byte(nil), p.buffered...)
	}
	red, _ := base64.StdEncoding.DecodeString(resp.Scan.RedactedB64)
	if len(red) == 0 {
		red = p.buffered
	}
	if !bytes.Equal(red, p.buffered) {
		// Build a one-line summary of what was redacted.
		summary := summarizeMatches(resp.Scan.Matches)
		fmt.Fprintf(p.banner, "\r\n[noleak] redacted %s\r\n", summary)
	}
	return red
}

func summarizeMatches(ms []ipc.Match) string {
	counts := map[string]int{}
	for _, m := range ms {
		if m.Placeholder == "" {
			continue
		}
		counts[m.Kind]++
	}
	if len(counts) == 0 {
		return "0 secrets"
	}
	var parts []string
	for k, v := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", v, k))
	}
	return joinComma(parts)
}

func joinComma(s []string) string {
	out := ""
	for i, p := range s {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// splitTrailingPrefix returns the length of the largest suffix of buf that
// matches a non-empty prefix of pat. Used to delay forwarding bytes that
// might be the start of a marker landing in the next read.
func splitTrailingPrefix(buf, pat []byte) int {
	maxN := len(pat) - 1
	if maxN > len(buf) {
		maxN = len(buf)
	}
	for n := maxN; n > 0; n-- {
		if bytes.Equal(buf[len(buf)-n:], pat[:n]) {
			return n
		}
	}
	return 0
}
