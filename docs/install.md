# Installation Guide

Step-by-step installation instructions for Linux and macOS.

## Option A — Quick One-Line Release Installer (Recommended)

Download and install prebuilt binaries (`noleak`, `noleakd`, and `noleak-watch`) matching your operating system and CPU architecture:

```sh
curl -fsSL https://raw.githubusercontent.com/ahmedxuhri/ai-noleak/main/scripts/install.sh | sh
```

The script fetches the latest tag, extracts binaries, installs them to `~/.local/bin` (or `/usr/local/bin` if run as root), and creates a default `~/.noleak/config.yaml`.

---

## Option B — Compiling from Source Checkout

If you prefer to audit and compile the binaries directly on your machine:

### Prerequisites

- Go 1.22+ (`go version`)
- `git`
- `make`

If Go is not installed on your system:
```sh
# Quick Go install (adjust version/arch as needed)
curl -LO https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### 1. Clone and Build

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
sh scripts/install.sh
```

Binaries land in `./bin/`:

| Binary | Role |
|--------|------|
| `noleak` | Main CLI (proxy, run, doctor, list, review) |
| `noleakd` | Vault daemon |
| `noleak-watch` | On-disk file watcher/redactor |

### 2. Install Binaries

**As root** (system-wide):
```sh
install -m 0755 bin/noleak      /usr/local/bin/noleak
install -m 0755 bin/noleakd     /usr/local/bin/noleakd
install -m 0755 bin/noleak-watch /usr/local/bin/noleak-watch
```

**As a regular user** (user-local):
```sh
mkdir -p ~/.local/bin
install -m 0755 bin/noleak       ~/.local/bin/noleak
install -m 0755 bin/noleakd      ~/.local/bin/noleakd
install -m 0755 bin/noleak-watch ~/.local/bin/noleak-watch
# Make sure ~/.local/bin is in PATH:
export PATH="$HOME/.local/bin:$PATH"
```

### 3. Create Config Directory

```sh
mkdir -p ~/.noleak
chmod 700 ~/.noleak
```

### 4. Create Config File

```sh
cat > ~/.noleak/config.yaml << 'EOF'
proxy_listen: 127.0.0.1:9999
proxy_upstream: ""
proxy_preserve_headers:
  - Authorization
  - X-Api-Key
  - Anthropic-Version
  - Anthropic-Beta
  - User-Agent
  - Accept
  - Content-Type
proxy_passthrough_tokens: []
EOF
chmod 600 ~/.noleak/config.yaml
```

**Edit `proxy_upstream`** — set it to the base URL your agent CLI normally calls:

| Agent | Typical upstream |
|-------|-----------------|
| OpenAI Codex | `https://api.openai.com` |
| Claude Code | `https://api.anthropic.com` |
| Corporate proxy | `https://your-proxy.example.com/v1` |

> **`proxy_passthrough_tokens`** is only for upstream-proxy authentication material that *must* reach the upstream endpoint. Never put provider API keys, bot tokens, wallet keys, or user secrets here.

---

## 5. Start Services Concurrently

Instead of opening three separate terminals, start the vault daemon, HTTP proxy, and file watcher concurrently in a single foreground process:

**Ephemeral Mode (in-memory only, no passphrase, good for testing):**
```sh
noleak start --ephemeral
```

**Persistent Mode (prompts for passphrase, encrypted on disk):**
```sh
noleak start
```

For production use, you can run it inside `tmux`, `screen`, or a systemd user unit:

```sh
# tmux example
tmux new-session -d -s noleak-services 'noleak start'
```

---

## 6. Point Your Agent CLI at the Proxy

### OpenAI Codex (`~/.codex/config.toml`)

```toml
model = "gpt-4o"
model_provider = "openai-custom"

[providers.openai-custom]
name = "openai-custom"
base_url = "http://127.0.0.1:9999/v1"
env_key = "OPENAI_API_KEY"
```

### Claude Code

```sh
export ANTHROPIC_BASE_URL="http://127.0.0.1:9999/v1"
```

Or add to `~/.bashrc` / `~/.zshrc` for persistence.

## 7. Verify the Setup

```sh
noleak doctor
```

All checks should be green:
```
[ok] daemon health
[ok] proxy listen
[ok] proxy upstream
```

Then run a quick verification with a **synthetic** (fake) secret — never use real credentials for testing:

```sh
curl -s --max-time 10 \
  -X POST http://127.0.0.1:9999/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test-fake" \
  -d '{"model":"gpt-4o","input":"My AWS key is AKIAIOSFODNN7EXAMPLE","stream":true}'
```

The proxy output will log:
```
[proxy] request /v1/responses -> @TOKEN_xxxxxx@ (kind=aws_access_key_id, conf=1.00)
```

The raw value `AKIAIOSFODNN7EXAMPLE` must not appear in outbound traffic.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `daemon health` fails | `noleak start` has not been run, or socket file was removed. Run `noleak start --ephemeral`. |
| `proxy_upstream is empty` | Set `proxy_upstream` in `~/.noleak/config.yaml`. |
| Proxy log silent during agent use | Agent is bypassing the proxy. Fix the base URL setting. |
| `unsupported Content-Encoding` | Proxy supports `identity` and `gzip`. Disable brotli/zstd in the client. |
| Too many false-positive detections | Run `noleak review` to inspect and dismiss pending tokens. |
| Port 9999 already in use | Change `proxy_listen` in config to another port (e.g. `127.0.0.1:19999`). |
