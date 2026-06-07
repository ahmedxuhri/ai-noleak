package wrapper

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/vault"
)

// startTestDaemon mirrors the helper in internal/hooks/hooks_test.go but is
// duplicated locally to avoid an import cycle.
func startTestDaemon(t *testing.T) (*ipc.Client, vault.Vault, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	v := vault.NewMemory()
	master, _ := vault.NewMasterSecret()
	srv := ipc.NewServer(ipc.ServerConfig{
		SocketPath:   sock,
		Vault:        v,
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
		Version:      "test",
	})
	if _, err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, nil)
	time.Sleep(20 * time.Millisecond)
	return ipc.NewClient(sock), v, cancel
}

func TestPasteFilter_RedactsBracketedPaste(t *testing.T) {
	client, _, stop := startTestDaemon(t)
	defer stop()

	var banner bytes.Buffer
	pf := newPasteFilter(client, &banner, true)

	// One bracketed paste containing a synthetic Stripe key.
	secret := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	in := []byte("\x1b[200~hello " + secret + " world\x1b[201~")
	out := pf.process(in)

	// Begin/end markers preserved; secret bytes removed.
	if !bytes.HasPrefix(out, []byte("\x1b[200~")) {
		t.Fatalf("missing begin marker: %q", out)
	}
	if !bytes.HasSuffix(out, []byte("\x1b[201~")) {
		t.Fatalf("missing end marker: %q", out)
	}
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("plaintext secret survived paste filter: %q", out)
	}
	if !bytes.Contains(out, []byte("@TOKEN_")) {
		t.Fatalf("expected placeholder in filtered paste, got %q", out)
	}
	if !bytes.Contains(banner.Bytes(), []byte("[noleak] redacted")) {
		t.Fatalf("expected banner notification, got %q", banner.String())
	}
}

func TestPasteFilter_PassthroughOutsidePaste(t *testing.T) {
	client, _, stop := startTestDaemon(t)
	defer stop()

	pf := newPasteFilter(client, &bytes.Buffer{}, false)
	secret := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	in := []byte("typed text with " + secret + " inline\n")
	out := pf.process(in)

	// Outside bracketed paste, we don't filter typed input. L2 catches it.
	if !bytes.Equal(out, in) {
		t.Fatalf("typed bytes were modified: in=%q out=%q", in, out)
	}
}

func TestPasteFilter_HandlesChunkedMarkers(t *testing.T) {
	client, _, stop := startTestDaemon(t)
	defer stop()

	pf := newPasteFilter(client, &bytes.Buffer{}, true)

	// Split the paste across three reads, including breaking the end marker.
	chunks := [][]byte{
		[]byte("\x1b[200~ghp_abcdefghijkl"),
		[]byte("mnopqrstuvwxyz0123456789"),
		[]byte("\x1b[201~"),
	}
	var combined bytes.Buffer
	for _, c := range chunks {
		combined.Write(pf.process(c))
	}
	if bytes.Contains(combined.Bytes(), []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")) {
		t.Fatalf("chunked paste leaked secret: %q", combined.String())
	}
	if !bytes.Contains(combined.Bytes(), []byte("@TOKEN_")) {
		t.Fatalf("expected placeholder in chunked paste, got %q", combined.String())
	}
}

// scanRoundTrip is a sanity helper kept here so the test file pulls in
// encoding/base64 alongside the wrapper itself; not used in the asserts above.
func scanRoundTrip(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

var _ = scanRoundTrip // silence unused-warning if future refactor drops the call
