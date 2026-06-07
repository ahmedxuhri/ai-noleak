package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// fileVault persists the in-memory map to a single encrypted blob on disk.
// The blob layout is:
//
//   magic(8) | version(1) | nonce(12) | ciphertext(...)
//
// The ciphertext is AES-256-GCM(plaintext_json, key, nonce) where
// plaintext_json is an array of Entry records. Every mutation writes the
// blob atomically (temp file + rename + chmod 0600) so a crash mid-write
// can't corrupt the file.
//
// fileVault wraps memoryVault for the in-memory operations themselves; this
// keeps the lookup/binding logic in one place and limits the persistence
// layer to load + dump.
type fileVault struct {
	*memoryVault
	path        string
	key         []byte
	mu          sync.Mutex // serializes disk writes; orthogonal to memoryVault.mu
	dirty       bool
	saveDelay   time.Duration
	saveTimer   *time.Timer
	closing     bool
}

const (
	fileMagic   = "NLKVAULT"
	fileVersion = byte(1)
	keySize     = 32 // AES-256
	nonceSize   = 12
)

// OpenFile loads an existing vault from disk or creates an empty one.
// `key` must be exactly 32 bytes — the master key sourced from libsecret
// or a passphrase-derived key. The caller is responsible for keying.
func OpenFile(path string, key []byte) (Vault, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("vault: key must be %d bytes, got %d", keySize, len(key))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("vault: mkdir: %w", err)
	}

	mv := &memoryVault{
		byPH:    make(map[string]*Entry),
		byValue: make(map[string]string),
	}
	fv := &fileVault{
		memoryVault: mv,
		path:        path,
		key:         append([]byte(nil), key...),
		saveDelay:   100 * time.Millisecond,
	}

	if err := fv.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return fv, nil
}

// load reads + decrypts the on-disk blob into the in-memory maps. Returns
// os.ErrNotExist if the file isn't there yet (fresh install).
func (f *fileVault) load() error {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}
	if len(raw) < len(fileMagic)+1+nonceSize {
		return errors.New("vault: file truncated")
	}
	if string(raw[:len(fileMagic)]) != fileMagic {
		return errors.New("vault: bad magic")
	}
	off := len(fileMagic)
	if raw[off] != fileVersion {
		return fmt.Errorf("vault: unsupported version %d", raw[off])
	}
	off++
	nonce := raw[off : off+nonceSize]
	off += nonceSize
	ciphertext := raw[off:]

	plaintext, err := decryptGCM(f.key, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("vault: decrypt: %w", err)
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return fmt.Errorf("vault: unmarshal: %w", err)
	}
	f.memoryVault.mu.Lock()
	defer f.memoryVault.mu.Unlock()
	for i := range entries {
		e := entries[i]
		copy := e
		f.memoryVault.byPH[copy.Placeholder] = &copy
		f.memoryVault.byValue[copy.Value] = copy.Placeholder
		f.memoryVault.order = append(f.memoryVault.order, copy.Placeholder)
		if copy.ID > f.memoryVault.nextID {
			f.memoryVault.nextID = copy.ID
		}
	}
	return nil
}

// save serializes the current state and writes it atomically.
func (f *fileVault) save() error {
	f.memoryVault.mu.RLock()
	entries := make([]Entry, 0, len(f.memoryVault.byPH))
	for _, ph := range f.memoryVault.order {
		if e, ok := f.memoryVault.byPH[ph]; ok {
			entries = append(entries, *e)
		}
	}
	f.memoryVault.mu.RUnlock()

	plaintext, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("vault: marshal: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("vault: nonce: %w", err)
	}
	ciphertext, err := encryptGCM(f.key, nonce, plaintext)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}

	out := make([]byte, 0, len(fileMagic)+1+nonceSize+len(ciphertext))
	out = append(out, []byte(fileMagic)...)
	out = append(out, fileVersion)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, ".noleak-vault-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, f.path)
}

// markDirty schedules a debounced save. We coalesce bursts of writes (e.g.
// a bootstrap harvest registering 200 secrets) into a few save calls.
func (f *fileVault) markDirty() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing {
		return
	}
	f.dirty = true
	if f.saveTimer != nil {
		f.saveTimer.Reset(f.saveDelay)
		return
	}
	f.saveTimer = time.AfterFunc(f.saveDelay, func() {
		f.mu.Lock()
		f.dirty = false
		f.saveTimer = nil
		f.mu.Unlock()
		_ = f.save() // logged at the daemon level; nothing else to do here
	})
}

// Wrapper methods. Each delegates to memoryVault and then markDirty.

func (f *fileVault) Register(value, kind, source string, bindings []string, ms []byte) (*Entry, error) {
	e, err := f.memoryVault.Register(value, kind, source, bindings, ms)
	if err == nil {
		f.markDirty()
	}
	return e, err
}

func (f *fileVault) Bind(ph string, hosts []string) error {
	if err := f.memoryVault.Bind(ph, hosts); err != nil {
		return err
	}
	f.markDirty()
	return nil
}

func (f *fileVault) Unbind(ph string, hosts []string) error {
	if err := f.memoryVault.Unbind(ph, hosts); err != nil {
		return err
	}
	f.markDirty()
	return nil
}

func (f *fileVault) SetStatus(ph string, s Status) error {
	if err := f.memoryVault.SetStatus(ph, s); err != nil {
		return err
	}
	f.markDirty()
	return nil
}

func (f *fileVault) Rotate(ph, newValue string) error {
	if err := f.memoryVault.Rotate(ph, newValue); err != nil {
		return err
	}
	f.markDirty()
	return nil
}

func (f *fileVault) Delete(ph string) error {
	if err := f.memoryVault.Delete(ph); err != nil {
		return err
	}
	f.markDirty()
	return nil
}

func (f *fileVault) Close() error {
	f.mu.Lock()
	f.closing = true
	if f.saveTimer != nil {
		f.saveTimer.Stop()
	}
	dirty := f.dirty
	f.mu.Unlock()
	if dirty {
		if err := f.save(); err != nil {
			return err
		}
	}
	return f.memoryVault.Close()
}

// encryptGCM wraps AES-256-GCM with the caller-provided nonce.
func encryptGCM(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func decryptGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
