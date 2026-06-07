package ipc

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/vault"
)

func newTestServer(t *testing.T) (*Client, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")

	master, _ := vault.NewMasterSecret()
	srv := NewServer(ServerConfig{
		SocketPath:   sock,
		Vault:        vault.NewMemory(),
		Detector:     detect.New(detect.Options{}),
		MasterSecret: master,
		Version:      "test",
	})
	if _, err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, nil)
	// Brief settle so the listener is ready before tests dial.
	time.Sleep(20 * time.Millisecond)

	return NewClient(sock), cancel
}

func TestServer_HealthAndRegister(t *testing.T) {
	c, stop := newTestServer(t)
	defer stop()

	resp, err := c.Call(&Request{Op: OpHealth})
	if err != nil || resp.Error != "" || resp.Health == nil {
		t.Fatalf("health: err=%v resp=%+v", err, resp)
	}
	if resp.Health.VaultEntries != 0 {
		t.Fatalf("expected empty vault, got %d entries", resp.Health.VaultEntries)
	}

	regResp, err := c.Call(&Request{Op: OpRegister, Register: &RegisterRequest{
		Value: "synthetic-secret-XYZ", Kind: "test", Bindings: []string{"api.test"},
	}})
	if err != nil || regResp.Error != "" || regResp.Register == nil {
		t.Fatalf("register: err=%v resp=%+v", err, regResp)
	}
	ph := regResp.Register.Placeholder
	if ph == "" {
		t.Fatal("empty placeholder")
	}

	resResp, err := c.Call(&Request{Op: OpResolve, Resolve: &ResolveRequest{Placeholder: ph, DestHost: "api.test"}})
	if err != nil || resResp.Error != "" || resResp.Resolve.Value != "synthetic-secret-XYZ" {
		t.Fatalf("resolve: err=%v resp=%+v", err, resResp)
	}

	resResp2, _ := c.Call(&Request{Op: OpResolve, Resolve: &ResolveRequest{Placeholder: ph, DestHost: "evil.example"}})
	if resResp2.Error == "" {
		t.Fatal("expected error on binding mismatch")
	}
}

func TestServer_ScanWithAutoRegister(t *testing.T) {
	c, stop := newTestServer(t)
	defer stop()

	body := []byte(`set TELEGRAM_BOT_TOKEN=1234567890:AAH-DEADBEEFcafebabe0123456789abcdefGHI for the bot`)
	resp, err := c.Call(&Request{Op: OpScan, Scan: &ScanRequest{
		PayloadB64:   base64.StdEncoding.EncodeToString(body),
		AutoRegister: true,
	}})
	if err != nil || resp.Error != "" || resp.Scan == nil {
		t.Fatalf("scan: err=%v resp=%+v", err, resp)
	}
	if len(resp.Scan.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	redacted, _ := base64.StdEncoding.DecodeString(resp.Scan.RedactedB64)
	if containsBytes(redacted, []byte("AAH-DEADBEEFcafebabe0123456789abcdefGHI")) {
		t.Fatalf("redacted output still contains original token bytes:\n%s", redacted)
	}

	// A second scan of the same body should now hit the AC stage and produce
	// the same placeholder (deterministic).
	resp2, _ := c.Call(&Request{Op: OpScan, Scan: &ScanRequest{
		PayloadB64:   base64.StdEncoding.EncodeToString(body),
		AutoRegister: false,
	}})
	if len(resp2.Scan.Matches) == 0 {
		t.Fatal("expected AC re-match")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
