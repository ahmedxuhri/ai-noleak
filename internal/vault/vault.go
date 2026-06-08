// Package vault is the secret store. The on-disk encryption backend is chosen
// at install time (SQLCipher when libsqlcipher-dev is available; pure-Go
// AES-GCM blob fallback otherwise). This package defines the storage-agnostic
// interface and an in-memory implementation used for tests and development.
//
// See SPEC.md §4.
package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Status mirrors SPEC.md §7 lifecycle.
type Status string

const (
	StatusPendingReview  Status = "pending_review"
	StatusAccepted       Status = "accepted"
	StatusRotationNeeded Status = "rotation_needed"
	StatusRejected       Status = "rejected"
	StatusArchived       Status = "archived"
)

// Entry is one credential the vault knows about.
type Entry struct {
	ID           int64
	Placeholder  string
	Value        string
	Kind         string
	Source       string
	Bindings     []string
	Status       Status
	RegisteredAt time.Time
	RotationDue  time.Time
	Uses         int
}

// Vault is the storage interface every backend must satisfy.
//
// Concurrency: implementations must be safe for concurrent use across the
// daemon's goroutines. Reads dominate; a single global RWMutex is fine for
// the in-memory and AES-GCM-blob backends.
type Vault interface {
	// Register inserts a new value-bound entry. If the value is already known,
	// returns the existing placeholder unchanged (idempotent). Auto-derived
	// placeholders use BLAKE2b of (value || master_secret), so the same value
	// always lands on the same placeholder for a given vault.
	Register(value, kind, source string, bindings []string, masterSecret []byte) (*Entry, error)

	// Lookup returns the entry behind a placeholder (with Value populated)
	// or ErrNotFound. Uses counter is NOT incremented; call MarkUse separately
	// for that.
	Lookup(placeholder string) (*Entry, error)

	// Resolve returns the real Value behind a placeholder iff destHost matches
	// at least one of the entry's bindings. Returns ErrBindingMismatch if not.
	Resolve(placeholder, destHost string) (string, error)

	// Bind appends host patterns to an entry. Idempotent; existing entries kept.
	Bind(placeholder string, hosts []string) error
	// Unbind removes host patterns. No-op for hosts that aren't bound.
	Unbind(placeholder string, hosts []string) error

	// SetStatus updates the lifecycle state. Used by the review TUI.
	SetStatus(placeholder string, s Status) error

	// Rotate atomically swaps the value, archiving the old one for forensic
	// retention. The placeholder is preserved to keep references stable.
	Rotate(placeholder, newValue string) error

	// Delete removes the entry entirely. Cannot be undone.
	Delete(placeholder string) error

	// List returns all entries (Value blanked) in registration order.
	List(includeArchived bool) ([]Entry, error)

	// Values returns every active value as raw bytes. The detector AC stage
	// needs this set to stay current; the daemon rebuilds the AC on every
	// mutation. Implementations must clone defensively.
	Values() [][]byte

	// MarkUse increments the per-entry use counter. Cheap, fire-and-forget.
	MarkUse(placeholder string)

	// Close releases backing resources. Subsequent calls return ErrClosed.
	Close() error

	// MasterSecret returns the vault's stable master secret used to derive placeholders.
	MasterSecret() []byte
}

var (
	ErrNotFound        = errors.New("vault: placeholder not found")
	ErrBindingMismatch = errors.New("vault: destination not bound to placeholder")
	ErrClosed          = errors.New("vault: closed")
)

// makePlaceholder derives the deterministic short placeholder from value
// bytes and the vault's master secret. Same vault + same value always yields
// the same placeholder.
func makePlaceholder(value string, masterSecret []byte) string {
	h, _ := blake2b.New256(masterSecret)
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return "@TOKEN_" + hex.EncodeToString(sum[:3]) + "@"
}

// MakePlaceholder is the package-public wrapper for callers that need to
// compute a placeholder without inserting (e.g., the proxy's auto-register
// path).
func MakePlaceholder(value string, masterSecret []byte) string {
	return makePlaceholder(value, masterSecret)
}

// NewMasterSecret returns a freshly-generated 32-byte secret suitable for
// seeding the placeholder hash. The vault stores it on disk under the same
// encryption envelope as its values.
func NewMasterSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("vault: master secret: %w", err)
	}
	return buf, nil
}

type memoryVault struct {
	mu           sync.RWMutex
	byPH         map[string]*Entry
	byValue      map[string]string // value -> placeholder
	order        []string          // insertion order for List
	closed       bool
	nextID       int64
	masterSecret []byte
}

// NewMemory constructs an empty in-memory vault.
func NewMemory() Vault {
	ms, _ := NewMasterSecret()
	return &memoryVault{
		byPH:         make(map[string]*Entry),
		byValue:      make(map[string]string),
		masterSecret: ms,
	}
}

func (v *memoryVault) Register(value, kind, source string, bindings []string, ms []byte) (*Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrClosed
	}
	if existing, ok := v.byValue[value]; ok {
		entry := v.byPH[existing]
		// Merge new bindings.
		entry.Bindings = mergeBindings(entry.Bindings, bindings)
		return cloneEntry(entry), nil
	}
	v.nextID++
	ph := makePlaceholder(value, ms)
	e := &Entry{
		ID:           v.nextID,
		Placeholder:  ph,
		Value:        value,
		Kind:         kind,
		Source:       source,
		Bindings:     append([]string(nil), bindings...),
		Status:       StatusPendingReview,
		RegisteredAt: time.Now().UTC(),
	}
	v.byPH[ph] = e
	v.byValue[value] = ph
	v.order = append(v.order, ph)
	return cloneEntry(e), nil
}

func (v *memoryVault) Lookup(ph string) (*Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneEntry(e), nil
}

func (v *memoryVault) Resolve(ph, host string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return "", ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return "", ErrNotFound
	}
	for _, pat := range e.Bindings {
		if matchHost(pat, host) {
			return e.Value, nil
		}
	}
	return "", ErrBindingMismatch
}

func (v *memoryVault) Bind(ph string, hosts []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return ErrNotFound
	}
	e.Bindings = mergeBindings(e.Bindings, hosts)
	return nil
}

func (v *memoryVault) Unbind(ph string, hosts []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return ErrNotFound
	}
	out := e.Bindings[:0]
	skip := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		skip[h] = true
	}
	for _, b := range e.Bindings {
		if !skip[b] {
			out = append(out, b)
		}
	}
	e.Bindings = out
	return nil
}

func (v *memoryVault) SetStatus(ph string, s Status) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return ErrNotFound
	}
	e.Status = s
	return nil
}

func (v *memoryVault) Rotate(ph, newValue string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return ErrNotFound
	}
	delete(v.byValue, e.Value)
	e.Value = newValue
	v.byValue[newValue] = ph
	return nil
}

func (v *memoryVault) Delete(ph string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	e, ok := v.byPH[ph]
	if !ok {
		return ErrNotFound
	}
	delete(v.byValue, e.Value)
	delete(v.byPH, ph)
	for i, p := range v.order {
		if p == ph {
			v.order = append(v.order[:i], v.order[i+1:]...)
			break
		}
	}
	return nil
}

func (v *memoryVault) List(includeArchived bool) ([]Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	out := make([]Entry, 0, len(v.order))
	for _, ph := range v.order {
		e := v.byPH[ph]
		if !includeArchived && e.Status == StatusArchived {
			continue
		}
		safe := *e
		safe.Value = ""
		out = append(out, safe)
	}
	return out, nil
}

func (v *memoryVault) Values() [][]byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([][]byte, 0, len(v.byPH))
	for _, e := range v.byPH {
		if e.Status == StatusRejected || e.Status == StatusArchived {
			continue
		}
		out = append(out, []byte(e.Value))
	}
	return out
}

func (v *memoryVault) MarkUse(ph string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.byPH[ph]; ok {
		e.Uses++
	}
}

func (v *memoryVault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	v.byPH = nil
	v.byValue = nil
	v.order = nil
	return nil
}

func (v *memoryVault) MasterSecret() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.masterSecret
}

func cloneEntry(e *Entry) *Entry {
	out := *e
	out.Bindings = append([]string(nil), e.Bindings...)
	return &out
}

func mergeBindings(existing, add []string) []string {
	seen := make(map[string]bool, len(existing)+len(add))
	out := existing[:0:cap(existing)]
	for _, b := range existing {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	for _, b := range add {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

// matchHost decides whether a binding pattern matches a destination host.
// Supported syntaxes:
//   - exact: "api.telegram.org"
//   - subdomain wildcard: "*.r2.cloudflarestorage.com" (matches any single
//     leading label or none).
func matchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:]
		if len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix {
			return true
		}
		// also match the bare suffix without a leading label
		if host == pattern[2:] {
			return true
		}
	}
	return false
}
