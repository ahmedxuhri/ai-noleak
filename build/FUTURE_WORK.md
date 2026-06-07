# Future Work — explicitly out of v0 scope

This document exists so the next person opening this repo (including future me) knows what is intentionally missing, and why. The v0 build is feature-complete against `SPEC.md` and ships a portable binary set. What's listed below is the **deployment and ergonomics layer** that turns a working tool into a product, but is orthogonal to the security guarantees the spec promises.

Do **not** treat any of these as deferred bugs. They are deferred features. Ship v0 first; revisit when usage data shows which one matters most.

---

## (3) Install script

A `install.sh` that:

- Detects host arch (`uname -m`) and OS (`uname -s`).
- Downloads the matching tarball from a GitHub Release URL.
- Verifies the signature (cosign or minisign — pick one and document the public key in the repo).
- Places `noleakd`, `noleak-watch`, `noleak` into `/usr/local/bin/` (or `~/.local/bin` for non-root).
- Optionally drops systemd user unit files (`~/.config/systemd/user/noleakd.service`, etc.) if `systemctl --user` is available; otherwise prints the equivalent `nohup` / `screen` invocation and exits.
- Runs `noleak init` for the bootstrap harvest.

Intentionally out of scope for v0 because:

- It depends on having a release pipeline (item 5).
- The current `make build` + manual copy works for a single VPS deployment.
- Adding it now would invite scope creep into "but on Alpine it should also do X" — better to ship v0, install on one or two real boxes, and learn what the script actually needs to handle.

**When to revisit:** when the same install steps have been done by hand on three or more VPSes and it's getting boring.

---

## (4) Deployment documentation

A `docs/install-vps.md` (and `docs/install-darwin.md` if macOS becomes relevant) covering:

- One-liner install via the script from item 3.
- Manual install for paranoid users (download tarball, verify signature, copy binaries, write unit file).
- How to set `ANTHROPIC_BASE_URL=http://127.0.0.1:9999/v1` for each agent CLI (Claude Code, Codex, Cursor, OpenClaw — each has a slightly different config file).
- How to migrate off Warden/Cloak (uninstall hooks, remove `~/.prismor`, remove the `warden` symlink).
- Troubleshooting: what to do when `noleakd` won't unlock, when the proxy returns 502, when the watcher reports "no rules registered."
- Rotation playbook for the existing on-disk leakage (i.e. the 165 detections the bootstrap surfaces on first run).

Intentionally out of scope for v0 because:

- Documentation written before deployment is fiction. We have not yet deployed `noleak` on a real VPS end-to-end. Anything I write today is informed by the test suite and the spec, not by the way the system actually behaves the first time it meets a user.
- Better written as a real session journal during the first deployment, then refactored into docs.

**When to revisit:** after the first real deployment, ideally with a second person walking through the steps and noting where they got confused.

---

## (5) CI build matrix

A GitHub Actions (or similar) workflow that:

- Builds `noleakd`, `noleak-watch`, `noleak` for `linux/amd64`, `linux/arm64`, `linux/armv7`.
- Runs `go vet`, `go test ./...`, and a fuzz target on the detector against a fixture corpus.
- Tags releases with semantic versions and uploads tarballs to the GitHub Releases page.
- Signs binaries (cosign or minisign) and publishes the public key in the repo.

Intentionally out of scope for v0 because:

- The repo is currently in a single VPS workspace, not a public GitHub project. Setting up CI for one developer's local copy is premature.
- `go build` works on the host. Cross-compilation works (`GOOS=linux GOARCH=arm64 go build ./...`) without CI infrastructure.

**When to revisit:** when the project moves to a public repo, or when more than one person is committing.

---

## Other work that is NOT in this list (and why)

These are sometimes confused for "future work" but are actually either done, deferred to v1, or out of scope by design:

| Item | Status |
|---|---|
| SQLCipher backend | Decided against. AES-GCM blob is sufficient at this scale and avoids CGO. |
| gzip request/response handling | **DONE** (was originally deferred). Decode-redact-recompress round-trip is implemented and tested. See `internal/proxy/proxy.go` `decodeBody`/`encodeBody` and `gzip_test.go`. |
| Multi-agent gRPC fan-out | Tracked separately as task #14, deferred until the first concrete multi-agent deployment. |
| 3s Esc-to-undo on paste | v1 polish; v0 substitutes immediately because L2 is the load-bearing defense. |
| Web dashboard | Spec §12 explicitly excludes it. |
| Provider-API rotation | Spec §12 — rotation worksheet is human-driven. |
| macOS / FreeBSD watcher | Linux-only by design (inotify); document as "Linux VPS tool". |
| Telegram-token-format-v2 detection | If a real false-negative shows up, add a regex. Don't pre-build for hypothetical formats. |

---

## Lessons from first live-traffic test (post-v0)

These came out of pointing the proxy at a real Claude Code session against `apistore.space` and pasting a list of 30 fake-credential samples. Not bugs left to fix — bugs we already fixed — but the *patterns* behind them are worth keeping.

### 1. Length-mutating proxies must own Content-Length

The proxy redacts secrets, which shrinks the body. Forwarding the client's original `Content-Length` header on top of a shorter body produced `400 invalid JSON: unexpected end of JSON input` from Anthropic. Eight turns in a row, because the failed turn replayed in conversation history. Fix lives in `copyHeaders` (strips `Content-Length`/`Content-Encoding`) plus a regression test that asserts upstream-received body length equals redacted body length.

**Generalize:** any proxy that mutates body bytes must compute `Content-Length` itself, never inherit it. Cheap test: assert lengths agree on the wire.

### 2. Brotli (and any future encoding) is fail-fast

We support `identity` and `gzip`. Anything else returns 502 with a clear message. Adding `br` (brotli), `zstd`, `deflate` would be a small encoder-table change in `proxy.go`. **When to revisit:** if a future agent CLI ships with brotli enabled by default and 502s become a deployment hazard. Right now Claude Code, Codex, Cursor, Windsurf all default to `gzip` or no encoding, so brotli support is YAGNI.

### 3. Test fixtures must be assembled at runtime

When this codebase passes through the noleak proxy itself (e.g. when an agent edits the test files), any *literal credential string* in source gets redacted to `@TOKEN_xxx@` before it lands. Tests written with literal credential bodies become self-redacted in transit and start asserting on placeholders.

Always build credential-shaped test bodies via `strings.Repeat`, `+` concatenation, or helper functions like the `mk()` in `connstring` tests. The source file should contain only fragments that, individually, do NOT match any credential regex.

This is also why several of my earlier edit loops appeared to "fail" — I was writing literals, the proxy was redacting them in transit, the next round-trip kept the placeholder. Once detected, the fix is mechanical; the lesson is to never trust a literal credential string in source code that an agent might transmit.

### 4. Stripe publishable / Twilio Auth Token / Datadog API key were intentionally NOT covered

These are either public by design (Stripe `pk_live_…`) or indistinguishable from arbitrary 32–40 char hex blobs without surrounding context (Twilio Auth Token, Datadog raw hex). Adding regexes for them would cause unacceptable false-positive rates on hashes, UUIDs, commit SHAs, etc. The right approach if they become a real concern: add a **labeled** detector (`(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*['"]?(<32hex>)`), the same shape as `aws_secret_access_key`.

### 5. Per-request log line is now the load-bearing operator UX

Without it, "no detections in this conversation" and "the proxy is bypassed" looked identical. Future operator-facing changes should preserve a per-request line at minimum; never go quieter than that.

---

## Items that emerged from live testing and are intentionally NOT new TODO

- **Gzipped streaming responses (SSE inside gzip).** Anthropic's `/v1/messages?stream=true` returns SSE; we don't currently decode-redact gzip-wrapped SSE because Anthropic doesn't gzip SSE in practice. If a future API surface does, the streaming path needs a decoding wrapper. Today it would surface as "client gets garbage on streaming" and the fix is local.
- **Bracketed-paste fallback.** Some terminals (raw `nc`, weird tmux configs) disable bracketed paste. The L1 wrapper currently just doesn't catch typed/non-bracketed pastes. The L2 proxy still catches whatever ends up in an outbound request, so security is preserved; only the user-facing paste banner goes silent. Could add a typing-detection path as v1 polish.
- **Watch debounce.** Currently 500 ms. Some agents emit several writes per second to a rotating log; a slow scan path could fall behind. Hasn't shown up in practice; benchmark before tightening.
