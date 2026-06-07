package cliroot

// rotationURLs maps a credential kind (as classified by the detector) to the
// provider's rotation/revocation URL. Used by `noleak rotate-list` to fill
// the rotation_url column of the worksheet.
//
// These are deliberately the canonical rotation pages, not arbitrary docs.
// When a kind is missing from the table, rotate-list emits an empty URL
// rather than guessing.
var rotationURLs = map[string]string{
	"telegram_bot_token":         "https://t.me/BotFather  (revoke + /newbot)",
	"aws_access_key_id":          "https://console.aws.amazon.com/iam/home#/security_credentials",
	"stripe_secret_key":          "https://dashboard.stripe.com/apikeys",
	"stripe_restricted_key":      "https://dashboard.stripe.com/apikeys",
	"github_pat_classic":         "https://github.com/settings/tokens",
	"github_pat_finegrained":     "https://github.com/settings/personal-access-tokens",
	"github_oauth":               "https://github.com/settings/applications",
	"github_app":                 "https://github.com/settings/apps",
	"openai_legacy_key":          "https://platform.openai.com/api-keys",
	"openai_project_key":         "https://platform.openai.com/api-keys",
	"google_api_key":             "https://console.cloud.google.com/apis/credentials",
	"slack_token":                "https://api.slack.com/apps",
	"jwt":                        "(rotate at the issuing service; JWT itself is opaque)",
	"pem_private_key":            "(regenerate the keypair; rotate authorized_keys / known_hosts as needed)",
	"solana_private_key_base58":  "(generate new wallet; transfer assets; abandon old)",
	"bip39_mnemonic_candidate":   "(generate new wallet; transfer assets; abandon old)",
	"context_shell_export":       "(no provider — see env-var name to determine)",
	"context_json_field":         "(no provider — see source file to determine)",
	"high_entropy":               "(unknown format; manual identification required)",
}

// rotationURLFor returns the canonical rotation URL for a credential kind,
// or empty string if the kind has no entry.
func rotationURLFor(kind string) string {
	return rotationURLs[kind]
}
