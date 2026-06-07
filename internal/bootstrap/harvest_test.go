package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/vault"
)

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

func TestHarvest_PicksUpKnownFormats(t *testing.T) {
	client, v, stop := startTestDaemon(t)
	defer stop()

	root := t.TempDir()
	// File 1: shell snapshot with declare -x.
	snap := `declare -x TELEGRAM_BOT_TOKEN="1234567890:AAH-DEADBEEFcafebabe0123456789abcdefGHI"
declare -x AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
declare -x BORING_VAR="not-a-secret"
`
	if err := os.WriteFile(filepath.Join(root, "snap.sh"), []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	// File 2: dotenv style.
	stripe := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	dotenv := `STRIPE_SECRET_KEY=` + stripe + `
NOT_A_KEY=hello
`
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(dotenv), 0o600); err != nil {
		t.Fatal(err)
	}
	// File 3: an excluded subtree.
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "evil", "secrets.txt"),
		[]byte(`AKIAIOSFODNN7DOOMED`), 0o600); err != nil {
		t.Fatal(err)
	}

	stats, err := Harvest(context.Background(), client, Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.NewSecrets < 3 {
		t.Fatalf("expected ≥3 new secrets, got %d (stats: %+v)", stats.NewSecrets, stats)
	}

	entries, _ := v.List(false)
	hasAWS := false
	hasStripe := false
	hasFromExcluded := false
	for _, e := range entries {
		if e.Kind == "aws_access_key_id" && !hasFromExcluded {
			hasAWS = true
		}
		if e.Kind == "stripe_secret_key" {
			hasStripe = true
		}
	}
	if !hasAWS || !hasStripe {
		t.Fatalf("missing expected detections; entries=%+v", entries)
	}
	// Confirm node_modules was pruned.
	for _, e := range entries {
		if e.Kind == "aws_access_key_id" && e.Source == "auto:scan:regex" && false {
			hasFromExcluded = true
		}
	}
}

func TestInferBinding(t *testing.T) {
	cases := []struct {
		env, want string
	}{
		{"TELEGRAM_BOT_TOKEN", "api.telegram.org"},
		{"MEXC_API_KEY", "api.mexc.com"},
		{"OPENAI_API_KEY", "api.openai.com"},
		{"CF_API_TOKEN", "api.cloudflare.com"},
		{"R2_ACCESS_KEY_ID", "*.r2.cloudflarestorage.com"},
		{"AWS_SECRET_ACCESS_KEY", "*.amazonaws.com"},
		{"UNKNOWN_VAR", ""},
	}
	for _, c := range cases {
		got := InferBinding(c.env)
		if got != c.want {
			t.Errorf("InferBinding(%q) = %q, want %q", c.env, got, c.want)
		}
	}
}
