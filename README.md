# ai-noleak

> **Local secret-leak prevention for agentic AI CLIs (like Claude Code, Cursor, OpenAI Codex).**

`ai-noleak` sits between your terminal and any AI API. It intercepts credentials, tokens, and API keys **before they leave your machine** — replacing them with deterministic local placeholders (`@TOKEN_xxxxxx@`) across three independent protection layers.

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
│  L2 · HTTP Proxy  (noleak start / noleak proxy)         │
│       Scans & redacts outbound requests + AI responses  │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
             AI API  (OpenAI / Anthropic / …)
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  L5 · File Watcher  (noleak-watch / noleak start)       │
│       inotify scan of logs/history/snapshots on disk    │
└─────────────────────────────────────────────────────────┘
```

All three layers share a single local vault daemon (`noleakd`) that stores the placeholder↔secret mapping in memory (ephemeral) or encrypted on disk (passphrase mode).

---

## Why This Matters

Agentic AI CLIs are extremely powerful because they write and execute shell commands to solve coding tasks. However, this gives them access to your environment variables, configuration files, and command history. 

It is very easy for an agent to accidentally read a file containing a secret (e.g. `.env`, `.git/config`, `.bash_history`), include it in its prompt context, and send it to an upstream provider or an untrusted proxy.

`ai-noleak` ensures that:
1. Pasted secrets are scrubbed before the shell executes them (**L1**).
2. Outbound HTTP requests to AI providers replace raw secrets with placeholders before leaving the machine (**L2**).
3. Temporary shell snapshots, logs, or history files written to disk are cleaned immediately (**L5**).

Upstream AI models only see placeholders like `@TOKEN_a9553f@`. If the model outputs the placeholder, `ai-noleak` translates it back to the real secret locally before returning it to the CLI. Your credentials never leak.

---

## Quick Install (Linux & macOS)

Install the prebuilt binary matching your OS and architecture with a single shell command:

```sh
curl -fsSL https://raw.githubusercontent.com/ahmedxuhri/ai-noleak/main/scripts/install.sh | sh
```

*This installs the binaries (`noleak`, `noleakd`, and `noleak-watch`) into `~/.local/bin` (or `/usr/local/bin` if run as root).*

---

## Quick Start

### 1 · Configure

Edit `~/.noleak/config.yaml` to set `proxy_upstream` to the API endpoint your AI CLI normally calls:

```yaml
proxy_listen: 127.0.0.1:9999
proxy_upstream: https://api.anthropic.com    # or https://api.openai.com
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

> **`proxy_passthrough_tokens`** — only for upstream auth tokens that *must* reach the endpoint. Never put provider API keys or account credentials here.

### 2 · Start Services

Start all three security layers (vault daemon, HTTP proxy, and file watcher) concurrently in a single command:

```sh
# Ephemeral Mode (in-memory only, no passphrase — best for testing):
noleak start --ephemeral

# Persistent Mode (encrypted on disk — prompts for master passphrase on startup):
noleak start
```

### 3 · Point Your AI CLI at the Proxy

Configure your agent CLI base URL to `http://127.0.0.1:9999/v1`.

**Claude Code**:
```sh
export ANTHROPIC_BASE_URL="http://127.0.0.1:9999/v1"
```

**OpenAI Codex** (`~/.codex/config.toml`):
```toml
model = "gpt-4o"
model_provider = "openai-custom"
[providers.openai-custom]
name = "openai-custom"
base_url = "http://127.0.0.1:9999/v1"
env_key = "OPENAI_API_KEY"
```

### 4 · Run the Health Check

Verify all services are running and correctly connected:

```sh
noleak doctor
```

Expected output:
```
[ok] config                   /root/.noleak/config.yaml
[ok] config validation        valid
[ok] socket                   /root/.noleak/sock
[ok] daemon health            version=0.1.0 unlocked=true vault_entries=0 pending_review=0
[ok] proxy listen             127.0.0.1:9999
[ok] proxy upstream           https://api.anthropic.com
...
```

---

## Manual Testing

You can verify all three protection layers without running a real AI CLI:

### Test L2 — Proxy Redaction
```sh
curl -s --max-time 10 \
  -X POST http://127.0.0.1:9999/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test-fake" \
  -d '{"model":"gpt-4o","input":"My AWS key is AKIAIOSFODNN7EXAMPLE","stream":true}'
```
The console logs of `noleak start` will output:
```
[proxy] request /v1/responses -> @TOKEN_xxxxxx@ (kind=aws_access_key_id, conf=1.00)
```

### Test L5 — On-Disk Watcher Redaction
Start `noleak start` specifying a test directory:
```sh
noleak start --ephemeral --redact ~/test-watch
```
In another terminal, write a secret:
```sh
echo "GitHub PAT: ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8" > ~/test-watch/leaked.txt
sleep 2
cat ~/test-watch/leaked.txt
# Output: GitHub PAT: @TOKEN_xxxxxx@
```

### Test L1 — PTY Paste Filter
```sh
printf "\x1b[200~ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8\x1b[201~\n" \
  | noleak run bash
# The raw secret is stripped before the shell receives it
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `noleak start` | Start daemon, proxy, and watcher concurrently |
| `noleak start --ephemeral` | Start all services in-memory (no passphrase) |
| `noleak run <cmd> [args...]` | Run an interactive CLI inside the L1 PTY wrapper |
| `noleak doctor` | Validate the configuration and check service health |
| `noleak list` | List all registered token placeholders |
| `noleak review` | Review and approve/dismiss pending harvest tokens |
| `noleak rotate <placeholder> <val>` | Update the value of an existing secret placeholder |
| `noleak delete <placeholder>` | Remove a secret from the local vault |

*Note: For advanced configurations, the individual components can also be run standalone via the separate binaries `noleakd` (vault daemon) and `noleak-watch` (file watcher).*

---

## Limitations & macOS Caveats

- **File Watcher (`noleak-watch`)**: The watcher monitors directory changes using filesystem events (driven by `fsnotify`). On macOS, this uses the FSEvents/kqueue subsystems. While fully functional, macOS file events can occasionally be coalesced or delayed by the operating system under high disk load. 
- **PTY Wrapper (`noleak run`)**: Designed for bracketed-paste interception. Raw keys typed character-by-character are not caught by the PTY wrapper (L1), but they are fully caught by the outbound proxy (L2) before leaving the machine.
- **Protocols**: The proxy supports JSON-based request bodies and SSE event streams. Requests utilizing non-standard compressed payloads other than `identity` and `gzip` (like `brotli` or `zstd`) will fail-open with a warning.

---

## Build from Source

If you prefer to compile the Go binaries manually:

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
make build    # outputs to ./bin/
make test     # runs the test suite
```

Requires Go 1.22+.

---

## Documentation

- [docs/install.md](docs/install.md) — Detailed manual install guide
- [docs/dogfood.md](docs/dogfood.md) — Walkthrough of validation transcript
- [SPEC.md](SPEC.md) — Architecture and design specification
- [FUTURE_WORK.md](FUTURE_WORK.md) — System limitations and development roadmap

---

## Status

Released **Beta (v0.1.0)**. Prebuilt binaries are fully supported for Linux (`amd64`, `arm64`, `arm`) and macOS (`amd64`, `arm64`).

## License

[Apache-2.0](LICENSE)
