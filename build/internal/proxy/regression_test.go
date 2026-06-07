package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/vault"
)

// TestProxy_ContentLengthMatchesRedactedBody is a regression test for the
// "400 invalid JSON: unexpected end of JSON input" bug observed in live
// Anthropic API traffic. When the proxy redacts a credential out of a
// request body the body shrinks; we must NOT forward the client's original
// Content-Length header (which counts the unredacted body) — otherwise
// upstream waits for bytes that never come and the JSON parser truncates.
//
// The test posts a body whose redacted length differs from the original,
// captures what the upstream actually receives, and asserts:
//
//   - Upstream-received body length equals the redacted body length.
//   - If a Content-Length header arrived, its value matches that length too.
//   - The original credential bytes do not appear in the received body.
func TestProxy_ContentLengthMatchesRedactedBody(t *testing.T) {
	rec := struct {
		mu      sync.Mutex
		body    []byte
		headers http.Header
	}{}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.body = body
		rec.headers = r.Header.Clone()
		rec.mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:   "127.0.0.1:0",
		Upstream:     upstream.URL,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	// Body with a known-format credential. Length-from-redaction will differ
	// from original because @TOKEN_<6 hex>@ is shorter than a Stripe key.
	credential := "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
	original := `{"messages":[{"role":"user","content":"hi my key is ` + credential + ` thanks"}]}`

	req, err := http.NewRequest("POST", "http://"+srv.Addr()+"/v1/messages", strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Explicitly set the original Content-Length, the way Claude Code does.
	req.ContentLength = int64(len(original))
	req.Header.Set("Content-Length", strconv.Itoa(len(original)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if len(rec.body) == 0 {
		t.Fatal("upstream received empty body")
	}
	if bytes.Contains(rec.body, []byte(credential)) {
		t.Fatalf("upstream received raw credential: %s", rec.body)
	}
	// Critical assertion: the received body should be SHORTER than the
	// original (because redaction shrunk it) and Content-Length, if present,
	// should match the actual received length.
	if len(rec.body) >= len(original) {
		t.Fatalf("expected redacted body to be shorter than original (%d) but got %d",
			len(original), len(rec.body))
	}
	if cl := rec.headers.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil {
			t.Fatalf("upstream got malformed Content-Length: %q", cl)
		}
		if n != len(rec.body) {
			t.Fatalf("Content-Length mismatch: header says %d, actual body is %d bytes",
				n, len(rec.body))
		}
	}
}

// TestProxy_RejectsUnsupportedEncoding asserts the proxy fails fast when
// the client sends a Content-Encoding it can't decode. Forwarding such a
// body after redaction would either silently corrupt the stream or land
// at upstream as gibberish; 502 with a clear error is the safe default.
//
// (The successful-gzip round-trip path is covered in gzip_test.go.)
func TestProxy_RejectsUnsupportedEncoding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:   "127.0.0.1:0",
		Upstream:     upstream.URL,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	// "br" (brotli) is a real encoding that we deliberately don't support.
	req, _ := http.NewRequest("POST", "http://"+srv.Addr()+"/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Encoding", "br")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on unsupported encoding, got %d", resp.StatusCode)
	}
}

// quickProxy stands up a lightweight proxy + capturing upstream for the
// targeted-flag tests below.
func quickProxy(t *testing.T) (string, func() string, func()) {
	t.Helper()
	var captured string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:   "127.0.0.1:0",
		Upstream:     upstream.URL,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)
	teardown := func() { cancel(); upstream.Close() }
	getCaptured := func() string {
		mu.Lock()
		defer mu.Unlock()
		return captured
	}
	return srv.Addr(), getCaptured, teardown
}

// TestProxy_PostgresAtInPasswordRedacted is a regression test for the bug
// found in live testing: the original connstring regex stopped at the
// first `@` after the user-colon, leaving the trailing `@ssw0rd123@host`
// portion exposed when the password itself contained `@`.
func TestProxy_PostgresAtInPasswordRedacted(t *testing.T) {
	addr, captured, teardown := quickProxy(t)
	defer teardown()

	// Build a postgres connection string whose password contains `@`.
	pw := "p" + "@" + "ssw0rd123"
	connStr := "postgresql://user:" + pw + "@db.example.com:5432/mydb"
	body := `{"q":"connect via ` + connStr + `"}`

	resp, err := http.Post("http://"+addr+"/q", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := captured()
	if strings.Contains(got, pw) {
		t.Fatalf("password leaked through: %s", got)
	}
	if !strings.Contains(got, "user") {
		t.Fatalf("redaction was too aggressive — expected username in upstream body: %s", got)
	}
	if !strings.Contains(got, "db.example.com") {
		t.Fatalf("redaction was too aggressive — expected host in upstream body: %s", got)
	}
}

var _ = fmt.Sprintf
