package detect

import (
	"regexp"
	"strings"
)

// Context heuristics: catch credentials that don't match a named regex but
// occur in syntactic positions strongly associated with secrets. These elevate
// otherwise-borderline strings (and catch novel token formats while we wait
// for the gitleaks shell-out integration).
//
// Three positions:
//   1. shell `declare -x KEY=VALUE` (Codex/bash snapshot)
//   2. shell `KEY=VALUE` or `export KEY=VALUE` lines
//   3. JSON keys whose name signals secret-bearing values

var (
	// `declare -x KEY="VALUE"` — emitted by `set` / `export -p`.
	reDeclare = regexp.MustCompile(`(?m)^declare\s+-x\s+([A-Z][A-Z0-9_]{2,})="([^"]+)"`)

	// `export KEY=VALUE` and bare `KEY=VALUE` at line start. Quoted or unquoted.
	reExport = regexp.MustCompile(`(?m)^(?:export\s+)?([A-Z][A-Z0-9_]{2,})=(?:"([^"]+)"|'([^']+)'|([^\s#]+))`)

	// JSON key/value where the key signals a secret. Captures the value.
	reJSONSecret = regexp.MustCompile(`(?i)"([^"]*(?:key|token|secret|password|passwd|pwd|auth|credential|api[_-]?key|access[_-]?key|private[_-]?key|seed)[^"]*)"\s*:\s*"([^"]+)"`)
)

// secretishKeyHints names that, when seen in declare/export, raise the
// confidence on whatever value follows. Lowercase comparison.
var secretishKeyHints = []string{
	"key", "token", "secret", "password", "passwd", "pwd",
	"auth", "credential", "api_key", "apikey", "access_key",
	"accesskey", "private_key", "privatekey", "seed",
	"signing", "signature", "client_secret", "clientsecret",
	"refresh_token", "refreshtoken",
}

func scanContext(input []byte) []Match {
	out := make([]Match, 0)

	for _, m := range reDeclare.FindAllSubmatchIndex(input, -1) {
		key := string(input[m[2]:m[3]])
		valStart, valEnd := m[4], m[5]
		out = append(out, contextMatch(key, valStart, valEnd, "shell_export"))
	}

	for _, m := range reExport.FindAllSubmatchIndex(input, -1) {
		key := string(input[m[2]:m[3]])
		var valStart, valEnd int
		switch {
		case m[4] >= 0:
			valStart, valEnd = m[4], m[5]
		case m[6] >= 0:
			valStart, valEnd = m[6], m[7]
		case m[8] >= 0:
			valStart, valEnd = m[8], m[9]
		default:
			continue
		}
		out = append(out, contextMatch(key, valStart, valEnd, "shell_export"))
	}

	for _, m := range reJSONSecret.FindAllSubmatchIndex(input, -1) {
		valStart, valEnd := m[4], m[5]
		key := string(input[m[2]:m[3]])
		out = append(out, contextMatch(key, valStart, valEnd, "json_field"))
	}

	return out
}

func contextMatch(key string, valStart, valEnd int, source string) Match {
	conf := 0.7
	low := strings.ToLower(key)
	for _, hint := range secretishKeyHints {
		if strings.Contains(low, hint) {
			conf = 0.92
			break
		}
	}
	return Match{
		Start:      valStart,
		End:        valEnd,
		Kind:       "context_" + source,
		Source:     "context",
		Confidence: conf,
	}
}
