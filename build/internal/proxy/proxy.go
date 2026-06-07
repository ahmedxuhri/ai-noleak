// Package proxy is the L2 local API proxy. It listens on a loopback address,
// scans request and response bodies via the in-process vault+detector, and
// forwards the (possibly redacted) traffic to the upstream Anthropic-
// compatible endpoint configured by the user.
//
// Design choices:
//
//   - Mask-and-forward on miss: detections that haven't been seen before are
//     auto-registered and substituted with their generated placeholders. The
//     request still reaches the upstream so the conversation doesn't stall.
//
//   - Streaming-safe: server-sent-event (SSE) responses (Anthropic's default
//     for /v1/messages with stream:true) are scanned chunk-by-chunk. Headers
//     are flushed immediately; bodies are line-buffered.
//
//   - Auth pass-through: the agent CLI's upstream auth token is forwarded
//     unchanged. The proxy never sees decrypted vault material.
//
// See SPEC.md §5 (L2).
package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"noleak/internal/detect"
	"noleak/internal/vault"
)

// Config bundles the proxy's runtime parameters.
type Config struct {
	// ListenAddr is the loopback bind address, e.g. "127.0.0.1:9999".
	ListenAddr string
	// Upstream is the absolute URL of the real API target, e.g.
	// "https://proxy.example" or "https://api.anthropic.com".
	Upstream string
	// Vault and Detector are shared with the daemon's IPC server.
	Vault        vault.Vault
	Detector     *detect.Detector
	MasterSecret []byte
	// AutoRegisterMinConf is the confidence floor at which detections are
	// auto-registered into the vault during scans. Detections below this are
	// reported but not persisted.
	AutoRegisterMinConf float64
	// Notify, if set, is called on every detection event in this proxy. The
	// callback runs synchronously on the request goroutine; keep it cheap
	// (e.g. push to a channel for an async notifier).
	Notify func(Event)
	// RequestLog, if set, fires once per proxied request (before body scan
	// or after upstream response, whichever provides the data needed). Used
	// by the CLI to surface a per-request audit line so silent detection
	// sessions are unambiguous about whether the proxy is on the path.
	RequestLog func(RequestEvent)
}

// Event describes a single detection that occurred while proxying a request
// or response. Surfaced via Config.Notify.
type Event struct {
	When        time.Time
	Direction   string // "request" or "response"
	Kind        string
	Placeholder string
	Source      string
	Confidence  float64
	Path        string
	Method      string
}

// RequestEvent is fired once per proxied request, regardless of whether the
// detector found anything. Lets operators verify the proxy is on the path
// during silent debugging sessions.
type RequestEvent struct {
	When         time.Time
	Method       string
	Path         string
	UpstreamPath string
	Status       int
}

// Server is the proxy. Construct with New, run with Listen+Serve.
type Server struct {
	cfg     Config
	upstrm  *url.URL
	httpSrv *http.Server
	mu      sync.Mutex
	ln      net.Listener
	stopped atomic.Bool
}

// New validates the config and returns a Server ready to Listen.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("proxy: ListenAddr required")
	}
	if cfg.Upstream == "" {
		return nil, errors.New("proxy: Upstream required")
	}
	if cfg.Vault == nil || cfg.Detector == nil || len(cfg.MasterSecret) == 0 {
		return nil, errors.New("proxy: Vault, Detector, and MasterSecret required")
	}
	if cfg.AutoRegisterMinConf == 0 {
		cfg.AutoRegisterMinConf = 0.85
	}
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse upstream: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("proxy: Upstream must be absolute (scheme + host)")
	}
	if !strings.HasPrefix(cfg.ListenAddr, "127.") && !strings.HasPrefix(cfg.ListenAddr, "[::1]") && !strings.HasPrefix(cfg.ListenAddr, "localhost:") {
		// Hard refusal — the proxy is local-trust by design. SPEC §2 trust zones.
		return nil, fmt.Errorf("proxy: ListenAddr %q must bind loopback only", cfg.ListenAddr)
	}
	return &Server{cfg: cfg, upstrm: u}, nil
}

// Listen begins accepting connections. The returned listener is also stored
// internally so Serve can use it.
func (s *Server) Listen() (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen: %w", err)
	}
	s.ln = ln
	return ln, nil
}

// Addr returns the bound address of the proxy listener (useful when
// ListenAddr was given as port 0). Empty string before Listen.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Serve runs the HTTP loop until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ln := s.ln
	if ln == nil {
		return errors.New("proxy: Serve called before Listen")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}()
	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// joinPaths composes upstream base path and incoming request path while
// collapsing duplicate prefixes. If the incoming path already starts with
// the base, the base is not prepended (handles the common case where users
// configure ANTHROPIC_BASE_URL with the same /v1 prefix that the upstream
// host already advertises).
func joinPaths(base, incoming string) string {
	if base == "" || base == "/" {
		return incoming
	}
	bt := strings.TrimRight(base, "/")
	// If incoming already starts with the base prefix (with or without
	// trailing slash), don't double it.
	if incoming == bt || strings.HasPrefix(incoming, bt+"/") {
		return incoming
	}
	if !strings.HasPrefix(incoming, "/") {
		incoming = "/" + incoming
	}
	return bt + incoming
}

// handle serves a single proxied request. Body bytes flow:
//
//	client -> read body fully -> scan+redact -> forward to upstream
//	upstream -> stream chunks -> per-chunk scan+redact -> client
//
// Streaming on the response side keeps SSE alive; streaming on the request
// side is rejected in v0 because Anthropic's request bodies are bounded JSON.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// Build the upstream URL: keep path/query, but anchor under the upstream
	// base path so callers can use either:
	//   ANTHROPIC_BASE_URL=http://127.0.0.1:9999/v1 + proxy_upstream=https://api.example
	//   ANTHROPIC_BASE_URL=http://127.0.0.1:9999    + proxy_upstream=https://api.example/v1
	// Both forms compose to a single canonical /v1/messages on the upstream.
	out := *r.URL
	out.Scheme = s.upstrm.Scheme
	out.Host = s.upstrm.Host
	out.Path = joinPaths(s.upstrm.Path, r.URL.Path)

	// Read+scan the request body. If the client sent it encoded (gzip),
	// decode → scan+redact → re-encode in the same encoding so the upstream
	// gets exactly the wire format it expects.
	var body []byte
	clientEncoding := r.Header.Get("Content-Encoding")
	if r.Body != nil {
		buf, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "proxy: read request body: "+err.Error(), http.StatusBadGateway)
			return
		}
		decoded, err := decodeBody(buf, clientEncoding)
		if err != nil {
			http.Error(w, "proxy: decode request: "+err.Error(), http.StatusBadGateway)
			return
		}
		redacted := s.scanAndRedact(decoded, "request", r.URL.Path, r.Method)
		encoded, err := encodeBody(redacted, clientEncoding)
		if err != nil {
			http.Error(w, "proxy: encode request: "+err.Error(), http.StatusBadGateway)
			return
		}
		body = encoded
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, out.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "proxy: build upstream request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(upstreamReq.Header, r.Header)
	upstreamReq.Header.Set("Host", s.upstrm.Host)
	upstreamReq.Host = s.upstrm.Host
	if clientEncoding != "" && clientEncoding != "identity" {
		// We re-encoded the redacted body in the same encoding the client
		// sent. Tell the upstream so it decodes correctly.
		upstreamReq.Header.Set("Content-Encoding", clientEncoding)
	}

	resp, err := http.DefaultClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, "proxy: upstream call: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if s.cfg.RequestLog != nil {
		s.cfg.RequestLog(RequestEvent{
			When:   time.Now(),
			Method: r.Method, Path: r.URL.Path, UpstreamPath: out.Path,
			Status: resp.StatusCode,
		})
	}

	// Decide streaming vs buffered based on content type.
	ct := resp.Header.Get("Content-Type")
	isStream := strings.Contains(ct, "text/event-stream") || strings.Contains(resp.Header.Get("Transfer-Encoding"), "chunked")

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if isStream {
		s.streamResponse(w, resp.Body, r.URL.Path, r.Method)
		return
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		// Client already got headers; best we can do is stop writing.
		return
	}
	// Decode the response body if upstream sent it encoded, redact, then
	// send back plain (Content-Encoding was stripped by copyHeaders, so
	// the client will treat the body as identity-encoded).
	respEncoding := resp.Header.Get("Content-Encoding")
	decoded, err := decodeBody(respBody, respEncoding)
	if err != nil {
		// Don't risk forwarding undecodable bytes — return early. Headers
		// are already written so the connection just closes here.
		return
	}
	redacted := s.scanAndRedact(decoded, "response", r.URL.Path, r.Method)
	_, _ = w.Write(redacted)
}

// streamResponse line-buffers chunks from the upstream, scans each line, and
// flushes redacted output to the client immediately. Keeps SSE alive.
func (s *Server) streamResponse(w http.ResponseWriter, body io.Reader, path, method string) {
	flusher, _ := w.(http.Flusher)
	br := bufio.NewReader(body)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			redacted := s.scanAndRedact(line, "response", path, method)
			_, _ = w.Write(redacted)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// scanAndRedact runs the layered detector against payload, auto-registers
// high-confidence hits, fires Notify callbacks, and returns the redacted
// payload. Bytes are returned as-is when no hits are found.
func (s *Server) scanAndRedact(payload []byte, direction, path, method string) []byte {
	if len(payload) == 0 {
		return payload
	}
	// Sync the AC stage with the live vault on every scan. SetExactValues is
	// a no-op when nothing changed (the underlying matcher rebuild is cheap
	// for the vault sizes this tool is designed for).
	s.cfg.Detector.SetExactValues(values(s.cfg.Vault))

	matches := s.cfg.Detector.Scan(payload)
	if len(matches) == 0 {
		return payload
	}

	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		val := string(payload[m.Start:m.End])
		var ph string
		switch {
		case m.Source == "ac":
			ph = vault.MakePlaceholder(val, s.cfg.MasterSecret)
			s.cfg.Vault.MarkUse(ph)
		case m.Confidence >= s.cfg.AutoRegisterMinConf:
			e, err := s.cfg.Vault.Register(val, m.Kind, "auto:proxy:"+m.Source, nil, s.cfg.MasterSecret)
			if err == nil {
				ph = e.Placeholder
			}
		default:
			continue
		}
		if ph == "" {
			continue
		}
		spans = append(spans, span{m.Start, m.End, ph})
		if s.cfg.Notify != nil {
			s.cfg.Notify(Event{
				When: time.Now(), Direction: direction,
				Kind: m.Kind, Placeholder: ph, Source: m.Source,
				Confidence: m.Confidence, Path: path, Method: method,
			})
		}
	}
	if len(spans) == 0 {
		return payload
	}
	return rewrite(payload, spans)
}

func rewrite(input []byte, spans []span) []byte {
	// Resolve overlap: prefer earlier-start, then longer span.
	sortSpans(spans)
	cursor := -1
	out := make([]byte, 0, len(input))
	pos := 0
	for _, sp := range spans {
		if sp.start < cursor {
			continue
		}
		out = append(out, input[pos:sp.start]...)
		out = append(out, []byte(sp.ph)...)
		pos = sp.end
		cursor = sp.end
	}
	out = append(out, input[pos:]...)
	return out
}

type span struct {
	start, end int
	ph         string
}

func sortSpans(s []span) {
	// insertion sort — typical request body has few hits
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func less(a, b span) bool {
	if a.start != b.start {
		return a.start < b.start
	}
	return (a.end - a.start) > (b.end - b.start)
}

func values(v vault.Vault) []string {
	bs := v.Values()
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

// copyHeaders mirrors src into dst, skipping hop-by-hop headers per RFC 7230.
//
// Also strips Content-Length unconditionally: redaction changes the body
// length, so the original client-supplied Content-Length is wrong. We let
// the Go http client recompute it from the new body. Forgetting this caused
// "400 invalid JSON: unexpected end of JSON input" on Anthropic — upstream
// expected N bytes but only N-deltaRedaction arrived.
//
// Content-Encoding is stripped here. When the body IS encoded (e.g. gzip)
// handle() decodes, redacts, and re-encodes inside the same encoding —
// then sets Content-Encoding back on the outgoing request explicitly. For
// un-encoded bodies the header is absent on both sides.
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		switch strings.ToLower(k) {
		case "connection", "proxy-connection", "keep-alive", "te", "trailer",
			"transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization",
			"content-length", "content-encoding":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// decodeBody returns the plaintext form of body given the (possibly empty)
// Content-Encoding header. Supported: identity, gzip. Unknown encodings
// return an error so the proxy fails-fast rather than silently forwarding
// garbage that downstream can't decode.
func decodeBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(io.LimitReader(gr, 64<<20))
	}
	return nil, fmt.Errorf("unsupported Content-Encoding: %q", encoding)
}

// encodeBody re-applies an encoding to plaintext bytes. Inverse of decodeBody.
func encodeBody(plain []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return plain, nil
	case "gzip":
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(plain); err != nil {
			return nil, fmt.Errorf("gzip write: %w", err)
		}
		if err := gw.Close(); err != nil {
			return nil, fmt.Errorf("gzip close: %w", err)
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("unsupported Content-Encoding: %q", encoding)
}

// EncodeBody is exposed for callers that want to ScanRedact a payload outside
// of the HTTP path (e.g. tests).
func (s *Server) EncodeBody(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
