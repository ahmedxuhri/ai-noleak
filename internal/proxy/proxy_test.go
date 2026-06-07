package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/vault"
)

// upstreamReceived captures what the proxy forwarded — used to assert that
// secrets never reached the upstream in plaintext.
type upstreamReceived struct {
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

func (u *upstreamReceived) record(body string, h http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bodies = append(u.bodies, body)
	u.headers = append(u.headers, h.Clone())
}

func newProxyForTest(t *testing.T, upstreamHandler http.HandlerFunc) (*Server, *httptest.Server, *upstreamReceived) {
	t.Helper()
	rec := &upstreamReceived{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(string(body), r.Header)
		upstreamHandler(w, r)
	}))
	t.Cleanup(upstream.Close)

	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:   "127.0.0.1:0",
		Upstream:     upstream.URL,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	return srv, upstream, rec
}

func TestProxy_RequestBodyRedacted(t *testing.T) {
	srv, _, rec := newProxyForTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	addr := srv.ln.Addr().String()
	secret := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	body := `{"messages":[{"role":"user","content":"my key is ` + secret + ` be careful"}]}`
	resp, err := http.Post("http://"+addr+"/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.bodies) != 1 {
		t.Fatalf("expected 1 upstream call, got %d", len(rec.bodies))
	}
	if strings.Contains(rec.bodies[0], secret) {
		t.Fatalf("upstream received plaintext secret:\n%s", rec.bodies[0])
	}
	if !strings.Contains(rec.bodies[0], "@TOKEN_") {
		t.Fatalf("expected placeholder in upstream body, got:\n%s", rec.bodies[0])
	}
}

func TestProxy_PreservesConfiguredAuthHeaders(t *testing.T) {
	srv, _, rec := newProxyForTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	srv.cfg.PreserveHeaders = []string{"authorization", "x-upstream-auth"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	req, err := http.NewRequest("POST", "http://"+srv.Addr()+"/v1/messages", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer proxy-auth-token")
	req.Header.Set("X-Upstream-Auth", "proxy-auth-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if got := rec.headers[0].Get("Authorization"); got != "Bearer proxy-auth-token" {
		t.Fatalf("Authorization was not preserved, got %q", got)
	}
	if got := rec.headers[0].Get("X-Upstream-Auth"); got != "proxy-auth-token" {
		t.Fatalf("X-Upstream-Auth was not preserved, got %q", got)
	}
}

func TestProxy_PassthroughTokenExemptFromRedaction(t *testing.T) {
	secret := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	var captured string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:        "127.0.0.1:0",
		Upstream:          upstream.URL,
		Vault:             vault.NewMemory(),
		Detector:          detect.New(detect.Options{}),
		MasterSecret:      master,
		PassthroughTokens: []string{secret},
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

	body := `{"upstream_proxy_token":"` + secret + `"}`
	resp, err := http.Post("http://"+srv.Addr()+"/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(captured, secret) {
		t.Fatalf("passthrough token was redacted or dropped: %s", captured)
	}
	if strings.Contains(captured, "@TOKEN_") {
		t.Fatalf("passthrough token should not be replaced with placeholder: %s", captured)
	}
}

func TestProxy_ResponseBodyRedacted(t *testing.T) {
	srv, _, _ := newProxyForTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"echo":"AKIAIOSFODNN7EXAMPLE"}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	addr := srv.ln.Addr().String()
	resp, err := http.Post("http://"+addr+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if bytes.Contains(respBytes, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("client received plaintext secret in response: %s", respBytes)
	}
}

func TestProxy_RequestLogFailureIncludesRedactedSnippet(t *testing.T) {
	responseSecret := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token ` + responseSecret + `"}`))
	}))
	defer upstream.Close()

	var events []RequestEvent
	var mu sync.Mutex
	master, _ := vault.NewMasterSecret()
	srv, err := New(Config{
		ListenAddr:   "127.0.0.1:0",
		Upstream:     upstream.URL,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
		RequestLog: func(ev RequestEvent) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, ev)
		},
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

	resp, err := http.Post("http://"+srv.Addr()+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected upstream status to pass through, got %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(responseSecret)) {
		t.Fatalf("client received raw secret in failure body: %s", body)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected one request log event, got %d", len(events))
	}
	if events[0].Status != http.StatusUnauthorized {
		t.Fatalf("expected 401 event, got %+v", events[0])
	}
	if events[0].ErrorSnippet == "" {
		t.Fatalf("expected non-empty failure snippet")
	}
	if strings.Contains(events[0].ErrorSnippet, responseSecret) {
		t.Fatalf("failure snippet leaked raw secret: %q", events[0].ErrorSnippet)
	}
	if !strings.Contains(events[0].ErrorSnippet, "@TOKEN_") {
		t.Fatalf("expected redacted placeholder in failure snippet, got %q", events[0].ErrorSnippet)
	}
}

func TestProxy_RejectsNonLoopbackBind(t *testing.T) {
	master, _ := vault.NewMasterSecret()
	_, err := New(Config{
		ListenAddr:   "0.0.0.0:9999",
		Upstream:     "http://example.test",
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
	})
	if err == nil {
		t.Fatal("expected error binding non-loopback")
	}
}

func TestProxy_StreamingResponseRedacted(t *testing.T) {
	srv, _, _ := newProxyForTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher, _ := w.(http.Flusher)
		// SSE-shaped chunks. The middle chunk carries a synthetic GitHub PAT.
		_, _ = w.Write([]byte("event: message\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("event: done\n\n"))
		flusher.Flush()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	resp, err := http.Post("http://"+srv.ln.Addr().String()+"/v1/messages?stream=true",
		"application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")) {
		t.Fatalf("plaintext PAT leaked through stream: %s", body)
	}
	if !bytes.Contains(body, []byte("@TOKEN_")) {
		t.Fatalf("expected placeholder in streamed response, got: %s", body)
	}
}
