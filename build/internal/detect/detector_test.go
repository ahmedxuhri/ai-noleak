package detect

import (
	"strings"
	"testing"
)

// All test fixtures use SYNTHETIC values that match documented formats but
// are not real credentials. Real values must never enter source control.

func TestScan_TelegramBotToken(t *testing.T) {
	d := New(Options{})
	in := []byte(`bot config: TELEGRAM_BOT_TOKEN=1234567890:AAH-DEADBEEFcafebabe0123456789abcdefGHI`)
	got := d.Scan(in)
	requireKind(t, got, "telegram_bot_token")
}

func TestScan_AWSAccessKey(t *testing.T) {
	d := New(Options{})
	in := []byte(`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`)
	got := d.Scan(in)
	requireKind(t, got, "aws_access_key_id")
}

func TestScan_StripeKeys(t *testing.T) {
	d := New(Options{})
	cases := []struct {
		input string
		kind  string
	}{
		{"sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc", "stripe_secret_key"},
		{"sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc", "stripe_secret_key"},
		{"rk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc", "stripe_restricted_key"},
	}
	for _, c := range cases {
		got := d.Scan([]byte(c.input))
		requireKind(t, got, c.kind)
	}
}

func TestScan_GitHubTokens(t *testing.T) {
	d := New(Options{})
	cases := []struct {
		input string
		kind  string
	}{
		{`ghp_abcdefghijklmnopqrstuvwxyz0123456789`, "github_pat_classic"},
		{`gho_abcdefghijklmnopqrstuvwxyz0123456789`, "github_oauth"},
	}
	for _, c := range cases {
		got := d.Scan([]byte(c.input))
		requireKind(t, got, c.kind)
	}
}

func TestScan_GoogleAPIKey(t *testing.T) {
	d := New(Options{})
	in := []byte(`GEMINI_API_KEY=AIzaSyA-abcdefghijklmnopqrstuvwxyz01234`)
	got := d.Scan(in)
	requireKind(t, got, "google_api_key")
}

func TestScan_PEMPrivateKey(t *testing.T) {
	d := New(Options{})
	in := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----")
	got := d.Scan(in)
	requireKind(t, got, "pem_private_key")
}

func TestScan_DeclareXShellSnapshot(t *testing.T) {
	// Mirrors the Codex shell_snapshot leak format. A hypothetical custom-format
	// secret that no regex pattern recognizes — must be caught by context stage.
	d := New(Options{})
	value := "c2ab175d8e37465a" + "80d98aea1dc37af9"
	in := []byte(`declare -x MEXC_API_SECRET="` + value + `"`)
	got := d.Scan(in)
	if !hasSource(got, "context") {
		t.Fatalf("expected a context-stage hit, got %v", got)
	}
}

func TestScan_JSONSecretField(t *testing.T) {
	d := New(Options{})
	value := "abcdef0123" + "456789ZZZZ"
	in := []byte(`{"api_key": "` + value + `", "name": "ok"}`)
	got := d.Scan(in)
	if !hasSource(got, "context") {
		t.Fatalf("expected JSON context hit, got %v", got)
	}
}

func TestScan_ACExactMatch(t *testing.T) {
	d := New(Options{})
	d.SetExactValues([]string{"super-secret-already-known-value"})
	in := []byte(`tail content super-secret-already-known-value head content`)
	got := d.Scan(in)
	if !hasKind(got, "ac_exact") {
		t.Fatalf("expected ac_exact match, got %v", got)
	}
}

func TestScan_EntropyFiltersLowEntropy(t *testing.T) {
	d := New(Options{EntropyMinLen: 10, EntropyThreshold: 4.0})
	// Deterministic low-entropy run; should NOT match entropy stage.
	in := []byte("aaaaaaaaaaaaaaaaaaaa")
	got := d.Scan(in)
	for _, m := range got {
		if m.Source == "entropy" {
			t.Fatalf("low-entropy input wrongly matched entropy stage: %v", m)
		}
	}
}

func TestScan_EntropyCatchesUnknownFormat(t *testing.T) {
	d := New(Options{EntropyMinLen: 20, EntropyThreshold: 4.0})
	// 32-char mixed-case alphanum, no surrounding context. No regex matches it.
	value := "ZxQvW3kJ9aT2mN6P" + "bR8sC4hL7dG1uYf5"
	in := []byte(`opaque token: ` + value)
	got := d.Scan(in)
	if !hasSource(got, "entropy") && !hasSource(got, "regex") {
		t.Fatalf("expected entropy/regex hit on opaque high-entropy token, got %v", got)
	}
}

func TestScan_NoFalsePositiveOnPlainText(t *testing.T) {
	d := New(Options{})
	in := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nSecond line of harmless prose.")
	got := d.Scan(in)
	for _, m := range got {
		if m.Confidence > 0.8 {
			t.Errorf("unexpected high-confidence match in plain text: %+v matched %q",
				m, string(in[m.Start:m.End]))
		}
	}
}

func requireKind(t *testing.T, got []Match, kind string) {
	t.Helper()
	if !hasKind(got, kind) {
		var kinds []string
		for _, m := range got {
			kinds = append(kinds, m.Kind)
		}
		t.Fatalf("missing kind %q in matches; got [%s]", kind, strings.Join(kinds, ","))
	}
}

func hasKind(in []Match, kind string) bool {
	for _, m := range in {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

func hasSource(in []Match, source string) bool {
	for _, m := range in {
		if m.Source == source {
			return true
		}
	}
	return false
}
