package proxy

import (
	"bytes"
	"compress/gzip"
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

// TestProxy_GzipRequestRedacted asserts that a gzip-encoded request body
// containing a credential is decoded, redacted, and re-encoded such that
// the upstream receives valid gzip whose plaintext contains the placeholder
// (not the original credential).
//
// The unsupported-encoding case (e.g. brotli) is covered in
// regression_test.go via TestProxy_RejectsUnsupportedEncoding.
func TestProxy_GzipRequestRedacted(t *testing.T) {
	var (
		mu        sync.Mutex
		gotEnc    string
		gotPlain  []byte
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotEnc = r.Header.Get("Content-Encoding")
		raw, _ := io.ReadAll(r.Body)
		if gotEnc == "gzip" {
			gr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			gotPlain, _ = io.ReadAll(gr)
		} else {
			gotPlain = raw
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	master, _ := vault.NewMasterSecret()
	srv, _ := New(Config{
		ListenAddr: "127.0.0.1:0", Upstream: upstream.URL,
		Vault: vault.NewMemory(), Detector: detect.New(detect.Options{}),
		MasterSecret: master,
	})
	srv.Listen()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	credential := "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
	plain := `{"q":"my key is ` + credential + `"}`

	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	gw.Write([]byte(plain))
	gw.Close()

	req, _ := http.NewRequest("POST", "http://"+srv.Addr()+"/v1/messages", bytes.NewReader(gzipBuf.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if gotEnc != "gzip" {
		t.Fatalf("upstream did not receive gzip-encoded body; Content-Encoding=%q", gotEnc)
	}
	if bytes.Contains(gotPlain, []byte(credential)) {
		t.Fatalf("plaintext credential leaked through gzip path: %s", gotPlain)
	}
	if !bytes.Contains(gotPlain, []byte("@TOKEN_")) {
		t.Fatalf("expected placeholder in upstream plaintext, got: %s", gotPlain)
	}
}

// TestProxy_GzipResponseRedacted asserts that a gzipped response body from
// upstream is decoded, redacted, and delivered to the client as plain text
// (no Content-Encoding header) — the client transparently sees the
// redacted plaintext.
func TestProxy_GzipResponseRedacted(t *testing.T) {
	credential := "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		gw.Write([]byte(`{"echo":"key=` + credential + `"}`))
		gw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(buf.Bytes())
	}))
	defer upstream.Close()

	master, _ := vault.NewMasterSecret()
	srv, _ := New(Config{
		ListenAddr: "127.0.0.1:0", Upstream: upstream.URL,
		Vault: vault.NewMemory(), Detector: detect.New(detect.Options{}),
		MasterSecret: master,
	})
	srv.Listen()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(20 * time.Millisecond)

	resp, err := http.Post("http://"+srv.Addr()+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("client received Content-Encoding %q (should be stripped — body was decoded)", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte(credential)) {
		t.Fatalf("plaintext credential leaked through gzipped response: %s", body)
	}
	if !bytes.Contains(body, []byte("@TOKEN_")) {
		t.Fatalf("expected placeholder in response body, got: %s", body)
	}
}

// TestProxy_UnsupportedEncodingReturns502 was moved to regression_test.go
// to keep all client-error contract tests in one place. The duplicate has
// been removed. (See TestProxy_RejectsUnsupportedEncoding.)
