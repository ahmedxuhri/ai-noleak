# Synthetic Dogfood Transcript

This transcript uses synthetic detector-shaped strings only. Do not use real secrets for first-run tests.

## Setup

Terminal 1:

```sh
make build
mkdir -p ~/.noleak
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
./bin/noleakd --ephemeral
```

Terminal 2:

```sh
./bin/noleak proxy
```

Expected:

```text
noleak proxy listening on 127.0.0.1:9999 -> https://proxy.example/v1
```

## Agent Configuration

Point the agent CLI base URL to:

```text
http://127.0.0.1:9999/v1
```

Run:

```sh
./bin/noleak doctor
```

Expected important checks:

```text
[ok] daemon health
[ok] proxy listen
[ok] proxy upstream
```

Agent config checks may warn if the specific CLI config file is not detectable.

## Prompt

Send this to the agent:

```text
Please repeat this synthetic token-shaped string back: AKIAIOSFODNN7EXAMPLE
```

## Expected Proxy Log

The proxy should report at least one request line and a detection line similar to:

```text
[noleak proxy] 12:00:00 request /v1/messages -> @TOKEN_ab12cd@ (kind=aws_access_key_id, conf=1.00)
[noleak proxy] 12:00:00 POST /v1/messages -> /v1/messages [200]
```

The placeholder ID will differ.

## Expected Behavior

The upstream request body should not contain:

```text
AKIAIOSFODNN7EXAMPLE
```

It should contain:

```text
@TOKEN_...
```

## Misconfiguration Signs

Proxy terminal shows no request lines:
The agent is bypassing `noleak proxy`.

`noleak doctor` reports socket failure:
`noleakd` is not running or the configured socket path is wrong.

The upstream receives the raw synthetic token:
Stop using the setup and inspect base URL, proxy logs, and config before testing with anything sensitive.
