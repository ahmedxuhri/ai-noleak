// Package detect is the layered scan engine: Aho-Corasick exact-match against
// the value list, regex pattern set, entropy filter, context heuristics.
//
// See SPEC.md §4 hot-path scan and §6.
//
// The detector is stateless during Scan; mutating the value list rebuilds
// the AC automaton under a write lock. Scan is safe for concurrent callers.
package detect

import (
	"sync"

	"github.com/cloudflare/ahocorasick"
)

// Match is one hit found in input. Offsets are byte positions into the input
// passed to Scan. Kind names a category ("telegram_bot_token", "ac_exact", ...).
// Source identifies which engine produced it ("ac", "regex", "entropy", "context").
// Confidence is in [0,1]; callers may threshold it. Auto-registration uses ≥0.85.
type Match struct {
	Start, End int
	Kind       string
	Source     string
	Confidence float64
}

// Options configures a Detector at construction time.
type Options struct {
	// EntropyMinLen is the minimum candidate length subjected to entropy scoring.
	// Strings shorter than this are skipped by the entropy stage. Default 20.
	EntropyMinLen int
	// EntropyThreshold is the minimum Shannon entropy (bits/char) at which a
	// candidate is reported by the entropy stage. Default 4.0.
	EntropyThreshold float64
	// DisableContext skips the context heuristic stage. Default false.
	DisableContext bool
}

// Detector is the layered scan engine. Construct with New, mutate the
// exact-match value list with SetExactValues, scan input with Scan.
type Detector struct {
	opts Options

	mu     sync.RWMutex
	values [][]byte
	ac     *ahocorasick.Matcher
}

// New constructs a Detector. The returned value is ready for Scan; calling
// Scan before SetExactValues simply skips the AC stage.
func New(opts Options) *Detector {
	if opts.EntropyMinLen == 0 {
		opts.EntropyMinLen = 20
	}
	if opts.EntropyThreshold == 0 {
		opts.EntropyThreshold = 4.0
	}
	return &Detector{opts: opts}
}

// SetExactValues replaces the AC value list. Empty values are dropped.
// Rebuilding is O(sum of value lengths); callers should batch.
func (d *Detector) SetExactValues(values []string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bs := make([][]byte, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		bs = append(bs, []byte(v))
	}
	d.values = bs
	if len(bs) == 0 {
		d.ac = nil
		return
	}
	d.ac = ahocorasick.NewMatcher(bs)
}

// Scan runs all enabled stages over input and returns deduplicated matches
// sorted by Start offset. Overlapping matches are kept; the caller resolves
// overlap policy (longest-wins is the daemon's default).
func (d *Detector) Scan(input []byte) []Match {
	if len(input) == 0 {
		return nil
	}

	var out []Match

	d.mu.RLock()
	ac := d.ac
	values := d.values
	d.mu.RUnlock()

	if ac != nil {
		for _, hit := range ac.Match(input) {
			v := values[hit]
			start := indexOf(input, v)
			for start >= 0 {
				out = append(out, Match{
					Start:      start,
					End:        start + len(v),
					Kind:       "ac_exact",
					Source:     "ac",
					Confidence: 1.0,
				})
				next := indexOf(input[start+len(v):], v)
				if next < 0 {
					break
				}
				start = start + len(v) + next
			}
		}
	}

	out = append(out, scanRegex(input)...)
	out = append(out, scanEntropy(input, d.opts.EntropyMinLen, d.opts.EntropyThreshold)...)
	if !d.opts.DisableContext {
		out = append(out, scanContext(input)...)
	}

	return dedup(out)
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func dedup(in []Match) []Match {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[[3]int]bool, len(in))
	out := in[:0]
	for _, m := range in {
		key := [3]int{m.Start, m.End, hashKind(m.Kind)}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

func hashKind(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	return h
}
