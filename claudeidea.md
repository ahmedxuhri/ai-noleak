This is a systems design problem, not a tool-picking problem. The brutal truth is that **secrets leak at 5 distinct boundaries** and most tools only guard 1-2 of them. To be bulletproof you need a guard at every single one.Here's the full attack map — 5 leak boundaries, and which tools own each one.Now here's the brutal build roadmap:

---

## What to actually do, in order

**Phase 1 — Don't reinvent what exists. Wire it.**

Fork `immunity-agent` (Cloak). Add `agent-vault` as the file I/O layer. You now have Boundaries 1, 2, 3, 4 half-covered in a weekend. Don't rewrite regex detection from scratch — Cloak's patterns are already hardened against real Stripe keys, AWS access keys, GitHub PATs, JWTs. Yours will miss edge cases for months.

**Phase 2 — Build your one genuine differentiator: approve-before-reveal.**

This is the gap nobody has filled properly. The flow is:
- Command runs → stdout captured
- If stdout contains any `@@SECRET:name@@` placeholder reference that would resolve to a real value before showing the user → **pause**
- Show: `"This output would expose SECRET_001 (stripe_key). Approve reveal? [y/N]"`
- Only on explicit `y` → decrypt and display in-terminal, never written to transcript

This is architecturally different from what Cloak does (Cloak scrubs automatically). Your gate is the differentiator.

**Phase 3 — OS Keychain backing.**

Replace file-encrypted vault with:
- macOS → `Keychain` via `security` CLI or `keytar` npm module
- Linux → `libsecret` / SecretService via `keytar`
- Windows → DPAPI via `keytar`

`keytar` is a single npm package that abstracts all three. This is one afternoon of work and immediately makes your vault stronger than every competitor's.

**Phase 4 — JSONL transcript scrubbing (the one nobody thinks about).**

Claude Code writes every conversation to `~/.claude/projects/*.jsonl`. If a real secret ever made it into context before your hooks fired, it's now on disk forever and gets re-sent to Anthropic on every new turn. You need a `PostSession` scrub that walks those files and replaces any real secret value with placeholders retroactively. Nobody has built this yet.

**Phase 5 — Boundary 5: HTTP proxy (optional but completes the shield).**

Wrap OneCLI or build a minimal `mitmproxy`-style local listener that intercepts outbound HTTP calls from the agent, confirms they don't contain real secret values in headers or body before forwarding. This is the network-layer defense.

---

## The one thing that makes you truly bulletproof vs everyone

The existing tools think about secrets as **values to hide**. You should think about them as **capabilities to gate**. The question isn't "did a secret leak?" — it's "did a secret get *used* without deliberate human intent?"

That reframe means: even a correctly-masked secret being unmasked at execution time should require intent signal from you. Cloak doesn't ask. OneCLI doesn't ask. HashiCorp Vault doesn't ask (at the per-command level). Your `approve-before-reveal` + `approve-before-execute` two-gate model is the only architecture that enforces that.

That's your moat. Everything else is plumbing.
