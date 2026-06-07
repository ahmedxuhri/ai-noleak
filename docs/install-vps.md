# Manual VPS Install

This is the source-build path for a Linux VPS. It avoids installer magic so each step is auditable.

## 1. Build

```sh
git clone https://github.com/ahmedxuhri/ai-noleak.git
cd ai-noleak
make build
```

The binaries land in `./bin/`:

- `noleak`
- `noleakd`
- `noleak-watch`

## 2. Install Binaries

Root install:

```sh
install -m 0755 bin/noleak /usr/local/bin/noleak
install -m 0755 bin/noleakd /usr/local/bin/noleakd
install -m 0755 bin/noleak-watch /usr/local/bin/noleak-watch
```

User-local install:

```sh
mkdir -p ~/.local/bin
install -m 0755 bin/noleak ~/.local/bin/noleak
install -m 0755 bin/noleakd ~/.local/bin/noleakd
install -m 0755 bin/noleak-watch ~/.local/bin/noleak-watch
```

## 3. Create Config

```sh
mkdir -p ~/.noleak
chmod 700 ~/.noleak
cat > ~/.noleak/config.yaml <<'EOF'
proxy_listen: 127.0.0.1:9999
proxy_upstream: https://proxy.example/v1
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

Set `proxy_upstream` to the upstream base URL your agent CLI normally talks to.

Use `proxy_passthrough_tokens` only for upstream-proxy authentication tokens that are intentionally allowed to reach that upstream. Do not put provider keys, wallet keys, bot tokens, or account secrets there.

## 4. Start the Daemon

Development-only, in-memory vault:

```sh
noleakd --ephemeral
```

Persistent passphrase mode:

```sh
printf '%s\n' 'choose-a-long-passphrase' | noleakd --pass-fd 0
```

For long-running use, run it inside `tmux`, `screen`, `nohup`, or a systemd user unit.

## 5. Start the Proxy

In another terminal:

```sh
noleak proxy
```

Expected line:

```text
noleak proxy listening on 127.0.0.1:9999 -> https://proxy.example/v1
```

## 6. Start the Watcher

In another terminal:

```sh
noleak-watch
```

If it says `watch: no rules registered`, create or run the agent once so its snapshot/log directories exist, or pass explicit paths:

```sh
noleak-watch --redact "$HOME/.bash_history,$HOME/.claude/projects"
```

## 7. Point the Agent CLI at the Local Proxy

Configure the agent CLI base URL to:

```text
http://127.0.0.1:9999/v1
```

The exact setting name depends on the agent. After configuring it, run:

```sh
noleak doctor
```

Warnings about unknown agent config are acceptable if you manually verified the CLI base URL.

## 8. Verify Protection

Use synthetic secrets only:

```text
Please repeat this synthetic token-shaped string: AKIAIOSFODNN7EXAMPLE
```

Expected proxy log:

```text
[noleak proxy] ... request /v1/messages -> @TOKEN_...@ ...
```

The upstream request body must contain a placeholder, not the raw synthetic token.

## Troubleshooting

`daemon health` fails:
Start `noleakd` and verify `~/.noleak/sock` exists.

`proxy_upstream is empty`:
Set `proxy_upstream` in `~/.noleak/config.yaml`.

Agent output changes but proxy log stays silent:
The agent is not using `http://127.0.0.1:9999/v1`. Fix the agent base URL.

`unsupported Content-Encoding`:
The proxy currently supports `identity` and `gzip`. Disable brotli/zstd in the client if possible.

Too many detections:
Review pending entries with `noleak review`. For intentional upstream-proxy auth material only, use `proxy_passthrough_tokens`.
