package keymgr

import (
	"path/filepath"
	"testing"
)

func TestPassphrase_Deterministic(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, ".noleak")

	a, err := Resolve(ModePassphrase, dataDir, []byte("hunter2-correct-horse"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(ModePassphrase, dataDir, []byte("hunter2-correct-horse"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("same passphrase, same salt should derive the same key")
	}
}

func TestPassphrase_DifferentPassphrasesDiffer(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, ".noleak")

	a, _ := Resolve(ModePassphrase, dataDir, []byte("alpha"))
	b, _ := Resolve(ModePassphrase, dataDir, []byte("beta"))
	if string(a) == string(b) {
		t.Fatal("different passphrases collided")
	}
}

func TestLibsecret_NotImplemented(t *testing.T) {
	_, err := Resolve(ModeLibsecret, t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected libsecret to return not-implemented error")
	}
}
