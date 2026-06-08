# ai-noleak

> **Local secret-leak prevention for agentic AI CLIs.**

`ai-noleak` sits between your terminal and any AI API. It intercepts credentials, tokens, and keys **before they leave your machine** — replacing them with deterministic local placeholders (`@TOKEN_xxxx@`) across three independent protection layers.

---

## How It Works

```
Your Terminal
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  L1 · PTY Wrapper  (noleak run <cmd>)                   │
│       Strips secrets from bracketed-paste before shell  │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  L2 · HTTP Proxy  (noleak proxy)                        │
│       Scans & redacts outbound requests + AI responses  │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
             AI API  (OpenAI / Anthropic / …)
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  L5 · File Watcher  (noleak-watch)                      │
│       inotify scan of logs/history/snapshots on disk    │
└─────────────────────────────────────────────────────────┘
```

All three layers share a single local vault daemon (`noleakd`) that stores the placeholder↔secret mapping in memory (ephemeral) or encrypted on disk (passphrase mode).

---

## Quick Install (Linux VPS)

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
sh scripts/install.sh        # builds + installs to ~/.local/bin (or /usr/local/bin as root)
```

Requires **Go 1.22+**. The script creates `~/.noleak/config.yaml` on first run.

See [docs/install.md](docs/install.md) for the full step-by-step manual install guide.

---

## Quick Start

### 1 · Configure

Edit `~/.noleak/config.yaml` — set `proxy_upstream` to the base URL your agent CLI normally calls:

```yaml
proxy_listen: 127.0.0.1:9999
proxy_upstream: https://api.openai.com    # or your proxy endpoint
proxy_preserve_headers:
  - Authorization
  - X-Api-Key
  - Anthropic-Version
  - Anthropic-Beta
  - User-Agent
  - Accept
  - Content-Type
proxy_passthrough_tokens: []
```

> **`proxy_passthrough_tokens`** — only for upstream-proxy auth tokens that *must* reach the upstream. Never put provider keys, bot tokens, or user secrets here.

### 2 · Start Services

Start all three layers (vault daemon, HTTP proxy, and file watcher) concurrently in a single command:

```sh
# Ephemeral (in-memory, no passphrase — good for testing):
noleak start --ephemeral

# Persistent (prompt for passphrase, encrypted on disk):
noleak start
```

### 3 · Point Your AI CLI at the Proxy

Configure your agent CLI base URL to `http://127.0.0.1:9999/v1`.

**OpenAI Codex** (`~/.codex/config.toml`):
```toml
model = "gpt-4o"
model_provider = "openai-custom"
[providers.openai-custom]
name = "openai-custom"
base_url = "http://127.0.0.1:9999/v1"
env_key = "OPENAI_API_KEY"
```

**Claude Code**: set `ANTHROPIC_BASE_URL=http://127.0.0.1:9999/v1`

### 4 · Run the Health Check

```sh
noleak doctor
```

All checks should be green:
```
[ok] daemon health
[ok] proxy listen
[ok] proxy upstream
```

### 5 · Use the PTY Wrapper (optional)

Wrap your shell so bracketed-paste is filtered too:

```sh
noleak run bash
# or
noleak run codex
```

---

## Manual Testing

You can verify each protection layer without a real AI CLI.

### Test L2 — Proxy In-Transit Redaction

```sh
curl -s --max-time 10 \
  -X POST http://127.0.0.1:9999/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test-fake" \
  -d '{"model":"gpt-4o","input":"My AWS key is AKIAIOSFODNN7EXAMPLE","stream":true}'
```

The proxy log will show:
```
[proxy] request /v1/responses -> @TOKEN_xxxxxx@ (kind=aws_access_key_id, conf=1.00)
```
The raw key never reaches the upstream.

### Test L5 — On-Disk Watcher Redaction

To watch a custom test directory:

```sh
noleak start --ephemeral --redact ~/test-watch
# In another terminal:
echo "GitHub PAT: ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8" > ~/test-watch/leaked.txt
sleep 2
cat ~/test-watch/leaked.txt
# Output: GitHub PAT: @TOKEN_xxxxxx@
```

### Test L1 — PTY Paste Filter

```sh
printf "\x1b[200~ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8\x1b[201~\n" \
  | noleak run bash
# The secret is stripped before the shell receives it
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `noleakd --ephemeral` | Start vault daemon (in-memory) |
| `noleakd --pass-fd 0` | Start vault daemon (encrypted, reads passphrase from stdin) |
| `noleak proxy` | Start the HTTP interception proxy |
| `noleak run <cmd>` | Run a command inside the PTY wrapper |
| `noleak doctor` | Health-check all components |
| `noleak list` | List all registered token placeholders |
| `noleak review` | Interactively approve/reject pending tokens |
| `noleak-watch` | Start the on-disk file watcher/redactor |
| `noleak-watch --redact <paths>` | Watch additional comma-separated paths |
| `noleak-watch --purge <paths>` | Purge (delete) matching files instead of redacting |

---

## Build from Source

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
make build    # outputs to ./bin/
make test     # runs the Go test suite
```

---

## Documentation

| File | Contents |
|------|----------|
| [docs/install.md](docs/install.md) | Full manual VPS install guide |
| [docs/dogfood.md](docs/dogfood.md) | Step-by-step test transcript |
| [SPEC.md](SPEC.md) | Architecture and design spec |
| [FUTURE_WORK.md](FUTURE_WORK.md) | Known limitations and roadmap |

---

## Status

Working **v0 prototype** — all three protection layers (PTY wrapper, HTTP proxy, file watcher) are implemented and manually verified. See [FUTURE_WORK.md](FUTURE_WORK.md) for what's next.

## License

[Apache-2.0](LICENSE)
