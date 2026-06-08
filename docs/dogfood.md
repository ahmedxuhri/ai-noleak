# Manual Test Transcript

A step-by-step walkthrough to verify all three protection layers are working. Uses **synthetic** (fake) secrets only — never test with real credentials.

## Prerequisites

- Services running concurrently via `noleak start --ephemeral`
- `noleak doctor` shows all green

---

## Test 1 — L1: PTY Paste Filter

The PTY wrapper strips secrets pasted via bracketed-paste escape sequences before the shell ever sees them.

### Steps

In your terminal, run:

```sh
printf "\x1b[200~ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8\x1b[201~\n" \
  | noleak run bash
```

### Expected

The shell receives an empty paste (or a redacted placeholder) — it does **not** execute or echo the raw PAT. The noleak wrapper logs a redaction event.

---

## Test 2 — L2: Proxy In-Transit Redaction

The HTTP proxy intercepts outbound requests and inbound AI responses, replacing secrets with placeholders.

### Setup

You need a mock upstream server running on port 58123, or you can point `proxy_upstream` at any echo/test endpoint. For a quick local mock:

```sh
# Simple Python mock that logs incoming bodies
python3 - << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, time
from socketserver import ThreadingMixIn

class H(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

class R(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(b'{"models":[{"id":"gpt-4o"}]}')
    def do_POST(self):
        n = int(self.headers.get('Content-Length',0))
        body = self.rfile.read(n)
        print("[MOCK RECEIVED]", body.decode())
        self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Connection','close'); self.end_headers()
        self.wfile.write(b'data: {"type":"response.completed"}\n\ndata: [DONE]\n\n')
    def log_message(self, *a): pass

H(('127.0.0.1', 58123), R).serve_forever()
EOF
```

### Steps

With `noleak proxy` running (forwarding to port 58123 or your real upstream), run:

```sh
curl -s --max-time 10 \
  -X POST http://127.0.0.1:9999/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test-fake" \
  -d '{"model":"gpt-4o","input":"My AWS key is AKIAIOSFODNN7EXAMPLE","stream":true}'
```

### Expected

**Start logs show:**
```
[proxy] 12:41:45 request /v1/responses -> @TOKEN_322a15@ (kind=aws_access_key_id, conf=1.00)
[proxy] 12:41:45 POST /v1/responses -> /v1/responses [200]
```

**Mock upstream receives** (body never contains the raw key):
```json
{"model":"gpt-4o","input":"My AWS key is @TOKEN_322a15@","stream":true}
```

The raw string `AKIAIOSFODNN7EXAMPLE` must not appear anywhere after the proxy.

---

## Test 3 — L5: On-Disk File Watcher

The file watcher monitors directories with `inotify` and rewrites files in-place to replace known secrets with placeholders.

### Setup

Ensure you run `noleak start` with the `--redact` flag pointing to the test directory:

```sh
mkdir -p ~/test-watch
noleak start --ephemeral --redact ~/test-watch
```

### Steps

In another terminal, write a file containing two known secrets:

```sh
echo "GitHub PAT: ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8 and AWS: AKIAIOSFODNN7EXAMPLE" \
  > ~/test-watch/leaked.txt
```

Wait 2 seconds, then read the file back:

```sh
sleep 2 && cat ~/test-watch/leaked.txt
```

### Expected

```
GitHub PAT: @TOKEN_2b8645@ and AWS: @TOKEN_322a15@
```

The start terminal logs:
```
[watcher] redacted /root/test-watch/leaked.txt (2 matches)
```

Both raw secrets are gone from disk.

---

## Checking the Vault

After running the tests, list all registered placeholders:

```sh
noleak list
```

Example output:
```
PLACEHOLDER          KIND                       STATUS         USES
@TOKEN_322a15@       aws_access_key_id          pending_review 1
@TOKEN_2b8645@       github_pat_classic         pending_review 3
@TOKEN_fc4ca5@       stripe_secret_key          pending_review 0
```

Review and approve or dismiss pending entries:

```sh
noleak review
```

---

## Misconfiguration Signs

| Sign | Meaning |
|------|---------|
| Proxy log shows no detection lines | Proxy not in the request path — check agent base URL |
| Raw secret appears in mock upstream body | Services not running or proxy bypassed |
| File not redacted after 5 seconds | Watcher not watching that directory — check `--redact` path |
| `noleak doctor` shows `[fail] daemon health` | `noleak start` has not been run |
