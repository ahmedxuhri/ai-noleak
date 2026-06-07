package detect

import "math"

// scanEntropy walks input, identifies candidate runs of credential-shaped
// characters (alphanum plus the small set of separators commonly used in
// tokens), and reports each run whose Shannon entropy is at or above the
// configured threshold and length floor.
//
// We deliberately exclude `.` and `/` here — JWTs and base64-padded blobs
// contain them, but those formats are already covered by dedicated patterns.
// Keeping entropy candidates narrow keeps false-positive rate down.
func scanEntropy(input []byte, minLen int, threshold float64) []Match {
	if minLen <= 0 || threshold <= 0 {
		return nil
	}
	out := make([]Match, 0)

	start := -1
	for i := 0; i <= len(input); i++ {
		var c byte
		if i < len(input) {
			c = input[i]
		}
		if i < len(input) && isTokenByte(c) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			runLen := i - start
			if runLen >= minLen {
				ent := shannon(input[start:i])
				if ent >= threshold {
					out = append(out, Match{
						Start:      start,
						End:        i,
						Kind:       "high_entropy",
						Source:     "entropy",
						Confidence: confidenceFromEntropy(ent),
					})
				}
			}
			start = -1
		}
	}
	return out
}

func isTokenByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_' || c == '-' || c == '+' || c == '=':
		return true
	}
	return false
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// confidenceFromEntropy is a soft mapping; below threshold the entropy stage
// would not have emitted the match in the first place. We bound at 0.9 so
// regex-anchored hits with named formats still outrank generic high-entropy.
func confidenceFromEntropy(h float64) float64 {
	c := 0.5 + (h-4.0)/4.0
	if c < 0.5 {
		c = 0.5
	}
	if c > 0.9 {
		c = 0.9
	}
	return c
}
