package watch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"noleak/internal/detect"
	"noleak/internal/ipc"
	"noleak/internal/vault"
)

func startTestDaemon(t *testing.T) (*ipc.Client, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	master, _ := vault.NewMasterSecret()
	srv := ipc.NewServer(ipc.ServerConfig{
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
	time.Sleep(20 * time.Millisecond)
	return ipc.NewClient(sock), cancel
}

func TestWatcher_PurgesNewFile(t *testing.T) {
	client, stop := startTestDaemon(t)
	defer stop()

	dir := t.TempDir()
	w := New(client, func(string, ...any) {})
	w.AddRule(Rule{Path: dir, Action: ActionPurge})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	target := filepath.Join(dir, "snap.sh")
	if err := os.WriteFile(target, []byte(`export FOO=bar`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("file was not purged within deadline: %s", target)
}

func TestWatcher_RedactsModifiedFile(t *testing.T) {
	client, stop := startTestDaemon(t)
	defer stop()

	dir := t.TempDir()
	w := New(client, func(string, ...any) {})
	w.AddRule(Rule{Path: dir, Action: ActionRedact})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	target := filepath.Join(dir, "history")
	body := []byte("# previous lines\nuser ran: curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n")
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(target)
		if err == nil && !bytes.Contains(got, []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")) && bytes.Contains(got, []byte("@TOKEN_")) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	got, _ := os.ReadFile(target)
	t.Fatalf("file was not redacted within deadline. contents: %q", got)
}
