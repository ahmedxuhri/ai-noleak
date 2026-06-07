package detect

import "regexp"

// Pattern is one regex rule. Confidence is the score reported on a match;
// anchored, format-checksummed patterns score 1.0; loose ones score lower.
//
// Group selects which submatch group identifies the credential bytes within
// the regex match. 0 means the whole match. Use a positive group when the
// regex needs surrounding anchor text (e.g. "Authorization: Bearer X") but
// only X is the credential to redact.
type Pattern struct {
	Kind       string
	Re         *regexp.Regexp
	Confidence float64
	Group      int
}

// patterns is the v0 hardcoded set, derived from public format documentation.
// Asset-hierarchy priority (SPEC.md §2) drives ordering: crypto → telegram →
// cloud infra → account passwords → LLM provider → identifiers.
//
// Anchoring:
//
// We deliberately do NOT use `\b` at the start or end of these patterns.
// Go/RE2 treats `_` as a word character, so `\b` does NOT trigger between
// `[A-Za-z0-9]` and `_`. That breaks any pattern whose surrounding context
// includes underscores — e.g. `KEY=sk_live_xxx_X` would fail to match the
// Stripe key because the trailing `_X` doesn't form a boundary with the
// alphanumeric body. Instead, every pattern uses a bounded length so the
// match terminates naturally without relying on `\b`. False-positive
// over-matching is acceptable per SPEC.md §2 (we'd rather mask too much
// than miss a secret).
//
// Adding a pattern: bound greedy quantifiers with a sane max (`{n,m}`),
// not just a minimum (`{n,}`). Use the `Group` field if the regex needs
// surrounding anchor text but only the credential bytes should be redacted.
var patterns = []Pattern{
	// Telegram bot token — `<bot_id>:<35–46-char base64-ish>`. Length varies
	// across bot API versions, so we accept a small range.
	{
		Kind:       "telegram_bot_token",
		Re:         regexp.MustCompile(`\d{8,11}:[A-Za-z0-9_-]{35,46}`),
		Confidence: 0.99,
	},

	// Cloudflare API token — `cfut_` + 32+ chars.
	{
		Kind:       "cloudflare_api_token",
		Re:         regexp.MustCompile(`cfut_[A-Za-z0-9]{32,128}`),
		Confidence: 0.99,
	},

	// AWS access key ID — exactly 16 chars after AKIA/ASIA.
	{
		Kind:       "aws_access_key_id",
		Re:         regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`),
		Confidence: 1.0,
	},

	// Stripe secret keys (live + test + prod) and restricted keys.
	{
		Kind:       "stripe_secret_key",
		Re:         regexp.MustCompile(`sk_(live|test|prod)_[A-Za-z0-9]{24,99}`),
		Confidence: 1.0,
	},
	{
		Kind:       "stripe_restricted_key",
		Re:         regexp.MustCompile(`rk_(live|test)_[A-Za-z0-9]{24,99}`),
		Confidence: 1.0,
	},

	// GitHub personal access tokens.
	{
		Kind:       "github_pat_classic",
		Re:         regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		Confidence: 1.0,
	},
	{
		Kind:       "github_pat_finegrained",
		Re:         regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		Confidence: 1.0,
	},
	{
		Kind:       "github_oauth",
		Re:         regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		Confidence: 1.0,
	},
	{
		Kind:       "github_app",
		Re:         regexp.MustCompile(`(ghs|ghu|ghr)_[A-Za-z0-9]{36}`),
		Confidence: 1.0,
	},

	// OpenAI API keys (legacy + project-scoped).
	{
		Kind:       "openai_project_key",
		Re:         regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{40,250}`),
		Confidence: 0.98,
	},
	{
		Kind:       "openai_legacy_key",
		Re:         regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
		Confidence: 0.95,
	},

	// Google Cloud API key.
	{
		Kind:       "google_api_key",
		Re:         regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
		Confidence: 1.0,
	},

	// Slack tokens.
	{
		Kind:       "slack_token",
		Re:         regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,200}`),
		Confidence: 0.97,
	},

	// JSON Web Token (header.payload.signature, base64url).
	{
		Kind:       "jwt",
		Re:         regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		Confidence: 0.85,
	},

	// PEM-encoded private keys. The (?s) flag lets `.` match newlines.
	{
		Kind:       "pem_private_key",
		Re:         regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		Confidence: 1.0,
	},

	// Solana base58 private key (87–88 chars). Wallet seed candidate.
	{
		Kind:       "solana_private_key_base58",
		Re:         regexp.MustCompile(`[1-9A-HJ-NP-Za-km-z]{87,88}`),
		Confidence: 0.6,
	},

	// BIP39 mnemonic seed phrases — 12 or 24 lowercase ascii words.
	{
		Kind:       "bip39_mnemonic_candidate",
		Re:         regexp.MustCompile(`(?:[a-z]{3,8} ){11}[a-z]{3,8}|(?:[a-z]{3,8} ){23}[a-z]{3,8}`),
		Confidence: 0.7,
	},

	// Generic high-entropy bearer-style token after Authorization: Bearer.
	{
		Kind:       "auth_bearer_token",
		Re:         regexp.MustCompile(`(?i)authorization:\s*bearer\s+([A-Za-z0-9_\-\.=]{20,500})`),
		Confidence: 0.85,
		Group:      1,
	},

	// Twilio API key SID — `SK` + 32 hex.
	{
		Kind:       "twilio_api_key_sid",
		Re:         regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Confidence: 0.95,
	},

	// SendGrid API key — `SG.<id>.<secret>`. First segment can be longer
	// than 32 in newer keys; widen the upper bound. Real keys observed in
	// the wild span 16–~50 chars in the ID segment.
	{
		Kind:       "sendgrid_api_key",
		Re:         regexp.MustCompile(`SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{32,128}`),
		Confidence: 1.0,
	},

	// Docker Hub personal access token.
	{
		Kind:       "dockerhub_pat",
		Re:         regexp.MustCompile(`dckr_pat_[A-Za-z0-9_-]{20,80}`),
		Confidence: 1.0,
	},

	// npm token (granular tokens are `npm_` + 36 chars; legacy 64-char hex
	// tokens still appear in older configs).
	{
		Kind:       "npm_token",
		Re:         regexp.MustCompile(`npm_[A-Za-z0-9]{36,80}`),
		Confidence: 1.0,
	},

	// Heroku API key.
	{
		Kind:       "heroku_api_key",
		Re:         regexp.MustCompile(`HRKU-[A-Za-z0-9_-]{30,80}`),
		Confidence: 1.0,
	},

	// Square OAuth / sandbox personal access token.
	{
		Kind:       "square_token",
		Re:         regexp.MustCompile(`sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,60}`),
		Confidence: 1.0,
	},

	// New Relic license / API key.
	{
		Kind:       "newrelic_key",
		Re:         regexp.MustCompile(`NRAL?-[A-Za-z0-9_-]{30,80}`),
		Confidence: 0.95,
	},

	// GitLab personal access token.
	{
		Kind:       "gitlab_pat",
		Re:         regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,40}`),
		Confidence: 1.0,
	},

	// Database/queue connection-string password — captures the secret in
	// group 1, leaving username + host visible. Covers Mongo, Postgres,
	// MySQL, Redis, AMQP and similar URI schemes.
	//
	// The password greedy capture (`.*`) is intentional: passwords may
	// contain `@`, so we need to anchor on the *last* `@` before the host
	// (everything between user-colon and the next host-shaped run with no
	// `@`). RE2 finds the longest leftmost match, which gives us that
	// behavior without lookbehind.
	{
		Kind:       "connstring_password",
		Re:         regexp.MustCompile(`(?:mongodb|postgresql|postgres|mysql|redis|amqp)(?:\+srv)?://[^:@\s/]+:(.+)@[^@/?\s]+`),
		Confidence: 0.95,
		Group:      1,
	},

	// AWS secret access key — context-anchored. Pure-content detection of a
	// raw 40-char base64 blob would have catastrophic false positives, so we
	// only match when explicitly labeled as such. The label form covers
	// `aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY`, with `=` or `:` and
	// optional quotes.
	{
		Kind:       "aws_secret_access_key",
		Re:         regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Confidence: 0.97,
		Group:      1,
	},

	// HTTP Basic Auth — `Authorization: Basic <base64>` and the bare
	// `Basic <base64>` shape that often appears in code/comments.
	{
		Kind:       "http_basic_auth",
		Re:         regexp.MustCompile(`Basic\s+([A-Za-z0-9+/]{16,256}={0,2})`),
		Confidence: 0.85,
		Group:      1,
	},

	// PagerDuty API token — `u+` followed by alphanumerics. Loose match,
	// kept at moderate confidence because the prefix alone is uncommon.
	{
		Kind:       "pagerduty_token",
		Re:         regexp.MustCompile(`u\+[A-Za-z0-9]{20,80}`),
		Confidence: 0.85,
	},
}

func scanRegex(input []byte) []Match {
	out := make([]Match, 0)
	for _, p := range patterns {
		if p.Group == 0 {
			for _, loc := range p.Re.FindAllIndex(input, -1) {
				out = append(out, Match{
					Start: loc[0], End: loc[1],
					Kind: p.Kind, Source: "regex", Confidence: p.Confidence,
				})
			}
			continue
		}
		// Submatch path: emit the credential bytes only, not the surrounding anchor.
		for _, loc := range p.Re.FindAllSubmatchIndex(input, -1) {
			gStart, gEnd := loc[2*p.Group], loc[2*p.Group+1]
			if gStart < 0 {
				continue
			}
			out = append(out, Match{
				Start: gStart, End: gEnd,
				Kind: p.Kind, Source: "regex", Confidence: p.Confidence,
			})
		}
	}
	return out
}
