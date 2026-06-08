// Package watch is the L5 sensitive-path watcher. It registers fsnotify
// callbacks on directories that frequently leak secrets in plaintext (env
// snapshots from Codex, shell history, agent transcripts, etc.) and acts on
// each new or modified file:
//
//   - "purge" paths: the file is deleted on detection. Used for env-dump
//     directories where there is no information worth keeping (the file is
//     a snapshot of $ENV that will be recreated on next launch anyway).
//
//   - "redact" paths: the file is scanned via noleakd, and any match is
//     replaced in place with the daemon-issued placeholder.
//
// Defaults follow SPEC.md §5 L5. Users add to or override the list via
// ~/.noleak/watch.yaml at install time.
package watch

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"noleak/internal/ipc"
)

// Action names what the watcher does to a matched file.
type Action string

const (
	ActionPurge  Action = "purge"
	ActionRedact Action = "redact"
)

// Rule binds a directory (recursive) to an Action.
type Rule struct {
	Path   string
	Action Action
}

// DefaultRules returns the v0 hardcoded list. Paths that don't exist on the
// host are skipped at AddRule time, not here.
func DefaultRules(homeDir string) []Rule {
	return []Rule{
		// Env snapshot directories: pure waste, purge.
		{filepath.Join(homeDir, ".codex", "shell_snapshots"), ActionPurge},
		{filepath.Join(homeDir, ".codex", ".tmp"), ActionPurge},
		{filepath.Join(homeDir, ".claude", "shell-snapshots"), ActionPurge},

		// Shell history: keep, redact.
		{filepath.Join(homeDir, ".bash_history"), ActionRedact},
		{filepath.Join(homeDir, ".zsh_history"), ActionRedact},

		// Agent transcripts: keep, redact (model context replay risk).
		{filepath.Join(homeDir, ".claude", "projects"), ActionRedact},

		// Agent log dirs: keep, redact.
		{filepath.Join(homeDir, ".openclaw", "logs"), ActionRedact},
		{filepath.Join(homeDir, ".cursor", "logs"), ActionRedact},
	}
}

// Watcher is the running daemon. Construct with New, drive with Run.
type Watcher struct {
	client  *ipc.Client
	logger  func(format string, args ...any)
	mu      sync.Mutex
	rules   []Rule
	debounce map[string]time.Time
}

// New constructs a Watcher with a logger (defaults to stderr if nil).
func New(client *ipc.Client, logger func(string, ...any)) *Watcher {
	if logger == nil {
		logger = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "noleak-watch: "+format+"\n", args...)
		}
	}
	return &Watcher{
		client:   client,
		logger:   logger,
		debounce: make(map[string]time.Time),
	}
}

// AddRule appends a rule. Non-existent paths are skipped silently — the
// agent CLI may not have run yet on this host.
func (w *Watcher) AddRule(r Rule) {
	if _, err := os.Stat(r.Path); err != nil {
		w.logger("skip rule (path missing): %s", r.Path)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rules = append(w.rules, r)
}

// Run blocks until ctx is cancelled or a fatal error occurs.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	rules := append([]Rule(nil), w.rules...)
	w.mu.Unlock()

	if len(rules) == 0 {
		w.logger("no watch paths active; watcher is idle")
		<-ctx.Done()
		return nil
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch: fsnotify: %w", err)
	}
	defer fsw.Close()

	for _, r := range rules {
		if err := fsw.Add(r.Path); err != nil {
			w.logger("watch add %s: %v", r.Path, err)
			continue
		}
		w.logger("watching %s (%s)", r.Path, r.Action)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-fsw.Events:
			if !ok {
				return errors.New("watch: events channel closed")
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}
			if strings.Contains(filepath.Base(ev.Name), ".noleak-tmp-") {
				continue
			}
			if w.shouldDebounce(ev.Name) {
				continue
			}
			rule := w.ruleFor(ev.Name, rules)
			if rule == nil {
				continue
			}
			w.handle(*rule, ev.Name)
		case err, ok := <-fsw.Errors:
			if !ok {
				return errors.New("watch: errors channel closed")
			}
			w.logger("fsnotify error: %v", err)
		}
	}
}

// shouldDebounce returns true if the path was handled within the debounce
// window. fsnotify can emit multiple events for a single write; we don't
// want to scan/purge a file repeatedly in tight loops.
func (w *Watcher) shouldDebounce(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if last, ok := w.debounce[path]; ok && time.Since(last) < 500*time.Millisecond {
		return true
	}
	w.debounce[path] = time.Now()
	return false
}

func (w *Watcher) ruleFor(path string, rules []Rule) *Rule {
	bestLen := -1
	var best *Rule
	for i := range rules {
		r := &rules[i]
		if path == r.Path || strings.HasPrefix(path, r.Path+string(filepath.Separator)) {
			if len(r.Path) > bestLen {
				bestLen = len(r.Path)
				best = r
			}
		}
	}
	return best
}

func (w *Watcher) handle(rule Rule, path string) {
	switch rule.Action {
	case ActionPurge:
		if err := os.Remove(path); err != nil {
			w.logger("purge %s: %v", path, err)
			return
		}
		w.logger("purged %s", path)
	case ActionRedact:
		if err := w.redact(path); err != nil {
			w.logger("redact %s: %v", path, err)
		}
	}
}

// redact reads path, sends it to the daemon for scanning, and overwrites
// the file with the redacted bytes if any matches were found. The write is
// atomic-ish: temp file + rename.
func (w *Watcher) redact(path string) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	resp, err := w.client.Call(&ipc.Request{
		Op: ipc.OpScan,
		Scan: &ipc.ScanRequest{
			PayloadB64:   base64.StdEncoding.EncodeToString(data),
			AutoRegister: true,
		},
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("scan: %s", resp.Error)
	}
	if resp.Scan == nil || len(resp.Scan.Matches) == 0 {
		return nil
	}
	red, err := base64.StdEncoding.DecodeString(resp.Scan.RedactedB64)
	if err != nil {
		return fmt.Errorf("decode redacted: %w", err)
	}
	if err := atomicWrite(path, red); err != nil {
		return err
	}
	w.logger("redacted %s (%d matches)", path, len(resp.Scan.Matches))
	return nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<20))
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".noleak-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
