package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileVault_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ms := []byte("master-secret-fixture")
	e, err := v.Register("real-tg-token", "telegram_bot_token", "test", []string{"api.telegram.org"}, ms)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode()&0o077 != 0 {
		t.Fatalf("vault file mode is too permissive: %v", st.Mode())
	}

	// Reopen with the same key — entries should reload.
	v2, err := OpenFile(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer v2.Close()
	got, err := v2.Lookup(e.Placeholder)
	if err != nil {
		t.Fatalf("lookup after reopen: %v", err)
	}
	if got.Value != "real-tg-token" {
		t.Fatalf("value lost across reopen: %q", got.Value)
	}
}

func TestFileVault_BadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	good := make([]byte, 32)
	for i := range good {
		good[i] = byte(i)
	}
	v, _ := OpenFile(path, good)
	ms := []byte("ms")
	v.Register("v", "k", "s", nil, ms)
	v.Close()

	bad := make([]byte, 32)
	for i := range bad {
		bad[i] = 0xff
	}
	if _, err := OpenFile(path, bad); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestFileVault_DebouncedSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	key := make([]byte, 32)

	v, _ := OpenFile(path, key)
	defer v.Close()
	ms := []byte("ms")

	// Burst of registrations.
	for i := 0; i < 50; i++ {
		v.Register(fmt.Sprintf("v%02d", i), "k", "s", nil, ms)
	}
	// Wait long enough for the debounce to fire.
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("debounced save did not produce a file: %v", err)
	}
}
