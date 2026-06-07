package detect

import (
	"strings"
	"testing"
)

// TestPatterns_TerminatorEdgeCases pins regex behavior at boundaries that
// previously failed (`\b` doesn't fire next to `_` because Go/RE2 treats
// `_` as a word character). Fixtures are built at runtime from short
// non-credential-shaped pieces so we don't accidentally write a string
// that gets caught by upstream redactors when this file is transmitted.
func TestPatterns_TerminatorEdgeCases(t *testing.T) {
	type sample struct {
		name string
		body string
		kind string
	}

	rep := strings.Repeat

	samples := []sample{
		// telegram_bot_token: \d{8,11}:[A-Za-z0-9_-]{35,46}
		{"telegram", "1234567890:" + rep("a", 36), "telegram_bot_token"},
		// cloudflare_api_token: cfut_[A-Za-z0-9]{32,128}
		{"cloudflare", "cfut_" + rep("a", 36), "cloudflare_api_token"},
		// aws_access_key_id: (AKIA|ASIA)[A-Z0-9]{16}
		{"aws", "AKIA" + rep("X", 16), "aws_access_key_id"},
		// stripe_secret_key: sk_(live|test|prod)_[A-Za-z0-9]{24,99}
		{"stripe", "sk_live_" + rep("a", 26), "stripe_secret_key"},
		// stripe_restricted_key: rk_(live|test)_[A-Za-z0-9]{24,99}
		{"stripe_rk", "rk_live_" + rep("a", 26), "stripe_restricted_key"},
		// github_pat_classic: ghp_[A-Za-z0-9]{36}
		{"gh_pat", "ghp_" + rep("a", 36), "github_pat_classic"},
		// github_oauth: gho_[A-Za-z0-9]{36}
		{"gh_oauth", "gho_" + rep("a", 36), "github_oauth"},
		// openai_legacy_key: sk-[A-Za-z0-9]{48}
		{"openai_legacy", "sk-" + rep("a", 48), "openai_legacy_key"},
		// google_api_key: AIza[A-Za-z0-9_-]{35}
		{"google_api", "AIza" + rep("a", 35), "google_api_key"},
		// twilio_api_key_sid: SK[0-9a-fA-F]{32}
		{"twilio_sid", "SK" + rep("a", 32), "twilio_api_key_sid"},
		// sendgrid_api_key: SG.[A-Za-z0-9_-]{16,32}.[A-Za-z0-9_-]{32,64}
		{"sendgrid", "SG." + rep("a", 22) + "." + rep("a", 43), "sendgrid_api_key"},
		// dockerhub_pat: dckr_pat_[A-Za-z0-9_-]{20,80}
		{"dockerhub", "dckr_pat_" + rep("a", 36), "dockerhub_pat"},
		// npm_token: npm_[A-Za-z0-9]{36,80}
		{"npm", "npm_" + rep("a", 36), "npm_token"},
		// heroku_api_key: HRKU-[A-Za-z0-9_-]{30,80}
		{"heroku", "HRKU-" + rep("a", 30), "heroku_api_key"},
		// square_token: sq0(atp|csp|idp)-[A-Za-z0-9_-]{22,60}
		{"square", "sq0atp-" + rep("a", 22), "square_token"},
		// newrelic_key: NRAL?-[A-Za-z0-9_-]{30,80}
		{"newrelic", "NRAL-" + rep("a", 30), "newrelic_key"},
		// gitlab_pat: glpat-[A-Za-z0-9_-]{20,40}
		{"gitlab", "glpat-" + rep("a", 24), "gitlab_pat"},
	}

	contexts := []struct {
		name   string
		format string
	}{
		{"eol", "tail %s"},
		{"trailing_space", "%s and more"},
		{"trailing_quote", `"%s"`},
		{"trailing_underscore_letter", "%s_X"},
		{"trailing_underscore_digits", "%s_999"},
		{"after_equals", "KEY=%s"},
		{"json_value", `"v":"%s"`},
	}

	d := New(Options{})

	for _, s := range samples {
		for _, c := range contexts {
			input := []byte(strings.Replace(c.format, "%s", s.body, 1))
			got := d.Scan(input)
			if !hasKindForBody(got, s.kind, []byte(s.body), input) {
				t.Errorf("[%s/%s] expected %s match for body %q in %q; got %v",
					s.name, c.name, s.kind, s.body, input, kindList(got))
			}
		}
	}
}

// TestPatterns_NoOverMatch — bounded patterns must not consume past the
// upper length bound.
func TestPatterns_NoOverMatch(t *testing.T) {
	d := New(Options{})
	overlong := "sk_live_" + strings.Repeat("a", 200)
	got := d.Scan([]byte(overlong))
	for _, m := range got {
		if m.Kind == "stripe_secret_key" {
			matched := overlong[m.Start:m.End]
			if len(matched) > len("sk_live_")+99 {
				t.Errorf("stripe match grew past upper bound: %d chars", len(matched))
			}
		}
	}
}

// hasKindForBody asserts a match whose span starts at body's position and
// fully contains it. The span may extend past body when the pattern's body
// charset includes the trailing context (e.g. Telegram allows `_`).
func hasKindForBody(matches []Match, kind string, body, input []byte) bool {
	bodyStart := indexOfBytes(input, body)
	if bodyStart < 0 {
		return false
	}
	for _, m := range matches {
		if m.Kind != kind {
			continue
		}
		if m.Start == bodyStart && m.End >= bodyStart+len(body) {
			return true
		}
	}
	return false
}

func indexOfBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func kindList(matches []Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Kind)
	}
	return out
}
