// Package bootstrap implements the first-run scope-3 disk harvest.
//
// Scope (SPEC.md §8):
//   - $HOME (selective subdirs only — full home walk is too noisy)
//   - /etc, /srv, /var/log when running as root
//
// For each candidate file we read up to MaxFileSize bytes, run the daemon
// scan with auto_register=true, and infer bindings from filename / context.
// Results land in vault status=pending_review for the user to curate via
// `noleak review`.
package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"noleak/internal/ipc"
)

// MaxFileSize is the per-file byte ceiling. Anything larger is skipped to
// avoid stalls on huge logs / archives. Most credentials live in small
// config files; logs over this size are rotated and we'll catch new entries
// via the L5 watcher anyway.
const MaxFileSize = 4 << 20 // 4 MiB

// Stats accumulates harvest progress for end-of-run reporting.
type Stats struct {
	FilesScanned int
	FilesSkipped int
	BytesScanned int64
	NewSecrets   int
	Errors       int
}

// Options configures a Harvest run.
type Options struct {
	// Roots is the explicit list of paths to walk. If empty, DefaultRoots is
	// used (selects scope-3 entries that exist on this host).
	Roots []string
	// Excludes is a list of basename patterns that prune entire subtrees on
	// match. Defaults applied additively if Excludes is non-nil.
	Excludes []string
	// Progress, if non-nil, is called periodically with the running Stats.
	Progress func(s Stats)
	// Logger receives one-line warnings (defaults to stderr).
	Logger func(format string, args ...any)
}

// DefaultRoots returns the v0 scope. Includes /etc, /srv, /var/log only if
// the process is running as root.
func DefaultRoots(homeDir string) []string {
	roots := []string{
		filepath.Join(homeDir, ".codex"),
		filepath.Join(homeDir, ".claude"),
		filepath.Join(homeDir, ".openclaw"),
		filepath.Join(homeDir, ".cursor"),
		filepath.Join(homeDir, ".gemini"),
		filepath.Join(homeDir, ".config"),
		filepath.Join(homeDir, ".npmrc"),
		filepath.Join(homeDir, ".docker"),
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
	}
	// Project-level dotenv files. Walk $HOME root non-recursively for these.
	envFiles, _ := filepath.Glob(filepath.Join(homeDir, ".env*"))
	roots = append(roots, envFiles...)

	if os.Geteuid() == 0 {
		roots = append(roots, "/etc", "/srv", "/var/log")
	}

	out := roots[:0]
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// DefaultExcludes prunes high-noise / no-secrets-here directories.
var DefaultExcludes = []string{
	"node_modules", ".cache", ".git", ".svn", ".hg",
	"dist", "build", "target", "out", "vendor",
	"__pycache__", ".venv", "venv", "env",
	"site-packages",
}

// Harvest walks the configured roots and ingests detections into the vault
// via the daemon. Returns the final Stats and the first fatal error
// encountered (per-file errors are logged but don't abort).
func Harvest(ctx context.Context, client *ipc.Client, opts Options) (*Stats, error) {
	if client == nil {
		return nil, errors.New("bootstrap: nil ipc client")
	}
	if opts.Logger == nil {
		opts.Logger = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "bootstrap: "+f+"\n", a...) }
	}
	if opts.Progress == nil {
		opts.Progress = func(Stats) {}
	}
	roots := opts.Roots
	if len(roots) == 0 {
		home, _ := os.UserHomeDir()
		roots = DefaultRoots(home)
	}
	excludes := append([]string(nil), DefaultExcludes...)
	excludes = append(excludes, opts.Excludes...)
	excludeSet := make(map[string]struct{}, len(excludes))
	for _, e := range excludes {
		excludeSet[e] = struct{}{}
	}

	stats := &Stats{}
	lastProgress := time.Now()

	for _, root := range roots {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			if walkErr != nil {
				stats.Errors++
				opts.Logger("walk %s: %v", p, walkErr)
				return nil
			}
			if d.IsDir() {
				if _, skip := excludeSet[d.Name()]; skip {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				stats.Errors++
				return nil
			}
			if info.Size() > MaxFileSize {
				stats.FilesSkipped++
				return nil
			}
			data, err := readBounded(p, MaxFileSize)
			if err != nil {
				// Permission errors on /etc, /var/log subdirs are common; don't
				// spam. We tally and move on.
				stats.Errors++
				return nil
			}
			stats.FilesScanned++
			stats.BytesScanned += int64(len(data))

			n, err := scanFile(client, p, data)
			if err != nil {
				stats.Errors++
				opts.Logger("scan %s: %v", p, err)
				return nil
			}
			stats.NewSecrets += n

			if time.Since(lastProgress) > 500*time.Millisecond {
				opts.Progress(*stats)
				lastProgress = time.Now()
			}
			return nil
		})
		if err != nil {
			return stats, err
		}
	}
	opts.Progress(*stats)
	return stats, nil
}

// scanFile sends one file's bytes to the daemon and returns the count of
// matches reported. The daemon handles auto-registration; we don't have to
// do anything with the redacted bytes here — the harvester is read-only.
func scanFile(client *ipc.Client, path string, data []byte) (int, error) {
	resp, err := client.Call(&ipc.Request{
		Op: ipc.OpScan,
		Scan: &ipc.ScanRequest{
			PayloadB64:   base64.StdEncoding.EncodeToString(data),
			AutoRegister: true,
		},
	})
	if err != nil {
		return 0, err
	}
	if resp.Error != "" {
		return 0, errors.New(resp.Error)
	}
	if resp.Scan == nil {
		return 0, nil
	}
	registered := 0
	for _, m := range resp.Scan.Matches {
		if m.Placeholder != "" {
			registered++
		}
	}
	return registered, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// InferBinding suggests a binding host for a credential whose env var name
// suggests its provider. Returns the empty string when no inference is
// possible (caller should leave bindings unset and let `noleak review`
// prompt the user).
func InferBinding(envVar string) string {
	up := strings.ToUpper(envVar)
	switch {
	case strings.HasPrefix(up, "TELEGRAM_") || strings.HasPrefix(up, "TG_"):
		return "api.telegram.org"
	case strings.HasPrefix(up, "MEXC_"):
		return "api.mexc.com"
	case strings.HasPrefix(up, "BINANCE_"):
		return "api.binance.com"
	case strings.HasPrefix(up, "OPENAI_") || up == "CHATGPT_API_KEY":
		return "api.openai.com"
	case strings.HasPrefix(up, "ANTHROPIC_"):
		return "api.anthropic.com"
	case strings.Contains(up, "GEMINI") || strings.Contains(up, "GOOGLE_"):
		return "*.googleapis.com"
	case strings.HasPrefix(up, "DEEPSEEK_"):
		return "api.deepseek.com"
	case strings.HasPrefix(up, "AZURE_"):
		return "*.openai.azure.com"
	case strings.HasPrefix(up, "CF_") || strings.HasPrefix(up, "CLOUDFLARE_"):
		return "api.cloudflare.com"
	case strings.HasPrefix(up, "R2_"):
		return "*.r2.cloudflarestorage.com"
	case strings.HasPrefix(up, "AWS_"):
		return "*.amazonaws.com"
	case strings.HasPrefix(up, "STRIPE_"):
		return "api.stripe.com"
	case strings.HasPrefix(up, "GITHUB_") || strings.HasPrefix(up, "GH_"):
		return "api.github.com"
	}
	return ""
}
