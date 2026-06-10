# ai-noleak

> **Local redaction proxy for preventing AI coding agents from leaking your secrets.**

`ai-noleak` sits between your terminal and any AI API. It intercepts accidentally exposed local secrets, credentials, tokens, and API keys — replacing them with deterministic local placeholders (`@TOKEN_xxxxxx@`) across three independent protection layers before they can reach the upstream model.

---

## 30-Second Demo

```text
1. You run a command containing a secret:
$ claude "Write a script to upload backup.tar to S3 using AKIAIOSFODNN7EXAMPLE"

2. ai-noleak intercepts the outbound prompt to Anthropic and redacts the secret:
[proxy] POST /v1/messages -> Redacted aws_access_key_id (confidence=1.00)
        Replaced "AKIAIOSFODNN7EXAMPLE" with "@TOKEN_8f51a2@"

3. The upstream model receives the safe prompt:
"Write a script to upload backup.tar to S3 using @TOKEN_8f51a2@"

4. The model answers using the placeholder:
"Here is your script: export AWS_ACCESS_KEY_ID=@TOKEN_8f51a2@ ..."

5. ai-noleak translates the placeholder back to the real secret locally:
"Here is your script: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE ..."
```

---


## How It Works

```
Your Terminal
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 1 · Input (PTY Wrapper)                          │
│        Strips secrets from bracketed-paste before shell │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2 · Transport (HTTP Proxy)                       │
│        Scans & redacts outbound requests + AI responses │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
             AI API  (OpenAI / Anthropic / …)
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3 · Storage (File Watcher)                       │
│        inotify/kqueue scan of log & history files       │
└─────────────────────────────────────────────────────────┘
```

*Note: The layers correspond to L1 (Physical/TTY input), L2 (Data Link/Transport proxy), and L5 (Session/Application storage files) OSI-metaphor layers defined in the [SPEC.md](SPEC.md).*

All three layers share a single local vault daemon (`noleakd`) that stores the placeholder↔secret mapping in memory (ephemeral) or encrypted on disk (passphrase mode).

---

## Threat & Security Model

`ai-noleak` acts as a local HTTP reverse proxy. Unlike traditional MITM proxies that require installing a custom Root CA certificate to decrypt TLS traffic (which introduces high security risks), `ai-noleak` requires zero certificate installation. You simply point your AI CLI tools to `http://127.0.0.1:9999/v1` over plaintext HTTP locally. The proxy intercepts, scans, and redacts the plaintext requests in local memory, and then forwards the sanitized payload to the upstream provider (e.g. Anthropic or OpenAI) over a secure, encrypted outbound HTTPS connection.

`ai-noleak` addresses this threat model with the following controls:

- **100% Local Isolation**: No telemetry is ever sent. The proxy preserves the configured provider authorization keys so that upstream requests succeed, but unrelated local secrets and prompt content are redacted on local CPU cycles before leaving the host.
- **No TLS CA/MITM Needed**: By acting as a local reverse proxy rather than a network-wide TLS interceptor, `ai-noleak` does not require root privileges or custom root CA certificates. Plaintext traffic is only transmitted over the local loopback interface (`127.0.0.1`), meaning no unencrypted traffic leaves your machine.
- **Strict Peer UID Verification**: The vault daemon (`noleakd`) communicates with the proxy and wrapper via a Unix Domain Socket (UDS). Connections are validated at the kernel level using peer credentials checking (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). Only processes owned by the exact same User ID (UID) that started the daemon can query the vault.
- **Privilege Separation**: The intercepting HTTP proxy runs with read-only capabilities with respect to the vault database. It can query the AC state and check placeholder bindings, but it cannot dump the plaintext vault or modify secret values. Mutating commands (like `rotate`, `review`, and manual `add`) are restricted to direct client invocations.
- **Encryption at Rest**: When running in persistent mode (default), the vault file is encrypted with AES-256-GCM. The key is derived using Argon2id from a master passphrase prompted once at service startup.

---

## Why This Matters

Agentic AI CLIs write and run commands, grep files, and read logs. If you have active environment variables, `.env` files, `.git/config` credentials, or raw tokens in your command history, it is incredibly easy for an agent to accidentally read them, inject them into its prompt context, and send them upstream to an AI API or third-party proxy.

`ai-noleak` ensures that:
1. Pasted secrets are scrubbed before the shell executes them (**Layer 1**).
2. Outbound HTTP requests to AI providers replace raw secrets with placeholders before leaving the machine (**Layer 2**).
3. Temporary shell snapshots, logs, or history files written to disk are cleaned immediately (**Layer 3**).

Upstream AI models only see placeholders like `@TOKEN_a9553f@`. If the model outputs the placeholder, `ai-noleak` translates it back to the real secret locally before returning it to the CLI.

This prevents accidental leakage of unrelated local secrets into AI requests (the provider's own API key is preserved so that auth succeeds, but all other local secrets are redacted).

---

## Installation

### Quick Install (Linux & macOS)

You can install `ai-noleak` using one of the following methods:

#### Method A: Direct One-Liner (Fastest)
```sh
curl -fsSL https://raw.githubusercontent.com/ahmedxuhri/ai-noleak/main/scripts/install.sh | sh
```

#### Method B: Verified Installation (Recommended)
To audit the installation script and verify its integrity before execution:
```sh
# 1. Download the installer script
curl -fsSL -o install.sh https://raw.githubusercontent.com/ahmedxuhri/ai-noleak/main/scripts/install.sh

# 2. Verify the installer's checksum matches the official hash
echo "6a37d48892d15aa42c67a922cbfd71b35a220e8906b17673563ba0498e63b9f8  install.sh" | sha256sum -c -

# 3. Run the installer
sh install.sh && rm install.sh
```

*Note: Binaries (`noleak`, `noleakd`, and `noleak-watch`) are installed to `~/.local/bin` (or `/usr/local/bin` if run as root).*

### Build from Source (Alternative)

If you prefer to compile the Go binaries manually:

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
make build    # compiles binaries to ./bin/
make test     # runs the test suite
```

Requires Go 1.22+.

### Verifying Checksums
All prebuilt releases contain `SHA256SUMS.txt` matching the published binaries on the GitHub Releases page. You can verify downloaded tarballs using:
```sh
sha256sum -c SHA256SUMS.txt
```

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

## Interactive Demo

Here is what running `noleak start` looks like when an agent attempts to leak a key:

```text
$ noleak start --ephemeral
[noleakd] starting on /root/.noleak/sock (vault: ephemeral memory)
[proxy] listening on 127.0.0.1:9999 -> https://api.anthropic.com
[watcher] watching /root/.bash_history (redact)
[watcher] watching /root/.claude/projects (redact)

# In another terminal, an agent tries to call the API with an AWS key in the prompt:
$ curl -s -X POST http://127.0.0.1:9999/v1/responses \
    -d '{"prompt": "use AKIAIOSFODNN7EXAMPLE"}'

# noleak terminal immediately intercepts and redacts:
[proxy] 12:41:45 request /v1/responses -> @TOKEN_322a15@ (kind=aws_access_key_id, conf=1.00)
```

---

## Manual Testing

You can verify all three protection layers without running a real AI CLI:

### Test Layer 2 — Proxy Redaction
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

### Test Layer 3 — On-Disk Watcher Redaction
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

### Test Layer 1 — PTY Paste Filter
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
| `noleak run <cmd> [args...]` | Run an interactive CLI inside the Layer 1 PTY wrapper |
| `noleak doctor` | Validate the configuration and check service health |
| `noleak list` | List all registered token placeholders |
| `noleak review` | Review and approve/dismiss pending harvest tokens |
| `noleak rotate <placeholder> <val>` | Update the value of an existing secret placeholder |
| `noleak delete <placeholder>` | Remove a secret from the local vault |

*Note: For advanced configurations, the individual components can also be run standalone via the separate binaries `noleakd` (vault daemon) and `noleak-watch` (file watcher).*

---

## Limitations & macOS Caveats

- **File Watcher (`noleak-watch`)**: The watcher monitors directory changes using filesystem events (driven by `fsnotify`).
  - **Asynchronous Race Conditions**: The watcher is asynchronous. If an agent writes a secret to a temporary file (e.g. `temp.txt`) and immediately reads it back within milliseconds to send it upstream, the file on disk remains temporarily raw during that tiny window. While Layer 2 (HTTP Proxy) is synchronous and guarantees the secret is redacted on the wire before leaving the machine, the local file on disk is vulnerable to brief exposure.
  - **macOS FSEvents Delay & Coalescing**: Under heavy disk I/O, macOS may coalesce filesystem events or delay them by several seconds. If an AI agent writes a secret to a watched log file and immediately reads it back, Layer 3 (file watcher) might not react fast enough to redact it before the read occurs.
  - **Replay/Snapshot Vulnerability**: If the CLI tool does not persist snapshots directly to disk in a watched directory, or if it writes logs to directories outside the configured watch paths, Layer 3 cannot protect them. We strongly recommend configuring explicit directories using the `--redact <path>` flags if your agent writes logs to custom directories.
  - **Recommendation**: Do not rely on Layer 3 alone as a fallback for high-throughput, low-latency redaction. Always combine it with Layer 2 (outbound HTTP proxy) which intercepts secrets synchronously at the request level.
- **PTY Wrapper (`noleak run`)**: Designed for bracketed-paste interception.
  - **Strictly a Paste Protector**: The PTY wrapper only intercepts bracketed-paste sequences to prevent bulk clipboard pasting. Typing secrets manually character-by-character bypasses Layer 1. However, these typed secrets are still fully intercepted and redacted at Layer 2 (HTTP Proxy) before leaving the host.
- **PreToolUse Hook & Indirect Script Execution**:
  - **URL Extraction Limits**: The PreToolUse hook parses bash commands for target URLs (e.g. `curl https://api.github.com/...`) to determine which placeholders should be substituted back to real secrets. If an agent writes a Python script `leak.py` containing a placeholder and runs it via `python3 leak.py`, the bash command itself lacks the destination URL. Consequently, the placeholder remains unsubstituted, and the script's outbound request will fail. To resolve this, run commands directly so the destination is visible to the parser, or plan for a local resolver proxy.
- **Protocols**: The proxy supports JSON-based request bodies and SSE event streams. Requests utilizing unsupported content encodings (e.g. `brotli`, `zstd`, or `deflate`) are failed closed with an HTTP `502 Bad Gateway` to prevent silent redaction bypasses.
- **Placeholder Semantics**:
  - **Persistent Mode**: The vault derives a stable master secret once on first-run, encrypts it at rest within the vault file, and loads it on subsequent startups. This ensures deterministic placeholder generation remains stable across restarts.
  - **Ephemeral Mode** (`--ephemeral`): The master secret is kept strictly in-memory and generated fresh on every boot. Placeholders derived in ephemeral mode are only valid for that run and will change upon daemon restart.

---

---

## Trust but Verify (Auditing the Proxy)

Security tools should never be trusted blindly. Here is how you can verify and audit `ai-noleak` to ensure it performs exactly as documented:

### 1. Verify Local Isolation (Network Audit)
`ai-noleak` contains no telemetry, analytics, or phone-home calls. You can verify this by checking local socket listening states:
```sh
# Verify the daemon ONLY listens on a local Unix Domain Socket (not a TCP port)
ss -xlp | grep noleakd

# Verify the proxy only listens on local loopback (127.0.0.1:9999)
ss -tulpn | grep 9999
```
To audit outbound network connections, you can monitor the PID of the proxy. The only outbound connection established should be directly to your configured upstream AI provider endpoint (e.g., `api.anthropic.com` or `api.openai.com`) when a request is actively being forwarded:
```sh
# Monitor outbound network sockets opened by the proxy
lsof -i -a -p $(pgrep noleak)
```

### 2. Verify Encrypted Storage
When running in persistent mode, all vault entries are stored in `~/.noleak/vault.bin`. You can verify that this file is fully encrypted (using AES-256-GCM) and cannot be decrypted without your passphrase:
```sh
# Try reading the file; it should output binary garbage and contain no plaintext secrets
strings ~/.noleak/vault.bin
hexdump -C ~/.noleak/vault.bin
```

### 3. Audit the Source Code
The codebase is extremely lightweight (~4,000 lines of Go code), does not use any heavy external frameworks, and relies almost entirely on the Go standard library (with the exception of `fsnotify`, `cobra`, `yaml`, and `x/crypto`). You can review the complete codebase at any time, run tests, and compile it yourself to guarantee the binaries match:
```sh
# Clone and build it yourself
make build
```

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
