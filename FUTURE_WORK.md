# Future Work — explicitly out of v0.1.0 scope

This document outlines the deferred features and design choices for `ai-noleak`. The v0.1.0 release is feature-complete against the core specification, providing a robust, multi-layer secret leak prevention tool.

---

## completed in v0.1.0

The following items were originally listed as future work but have been fully implemented in the v0.1.0 release:

- **All-in-One Service Manager (`noleak start`)**: Simplifies the "3 terminals" friction by allowing the daemon, HTTP proxy, and watcher to be launched concurrently in a single command with multiplexed, prefixed logging.
- **Mac OS Support**: macOS (darwin/amd64 and darwin/arm64) is fully supported. Sockets now use `GetsockoptXucred` for same-UID peer credentials verification.
- **Prebuilt Release Installer**: An enhanced one-liner install script (`install.sh`) that auto-detects host OS/architecture and downloads signed/verified prebuilt binaries from GitHub Releases, falling back to source compilation if Go is present.
- **CI Build Matrix & Releases**: Automatic GitHub Actions workflows compile releases for Linux and macOS targets and publish them to GitHub Releases on tag pushes.

---

## v1.0 Roadmap — Deferred Features

The following items are orthogonal to the core security guarantees but would improve the ergonomics and robustness of the tool:

### (1) Web Dashboard / TUI Improvements
- A terminal-based user interface for `noleak review` to allow bulk acceptance, rejection, and modification of pending harvested secrets.
- Grouping pending secrets by source directory and token type for rapid sorting.

### (2) Native Package Managers
- Distributing `noleak` via package repositories like Homebrew (`brew`) for macOS, Apt (`.deb`), and Yum/Dnf (`.rpm`) for Linux, rather than relying solely on `curl | sh` scripts.

### (3) Automated Provider API Rotation
- While a manual rotation worksheet is printed as a CSV (`noleak rotate-list`), automatically triggering rotation via provider APIs (e.g. creating a new AWS key and calling IAM to disable the old one) is deferred to minimize the danger of state corruption.

### (4) Brotli and Zstandard compression support
- The proxy currently supports `identity` and `gzip` content encodings. If future AI agents default to Brotli (`br`) or Zstandard (`zstd`) for streaming, the proxy must be updated with native decoders to inspect outbound traffic.

### (5) Local Resolver Proxy / DNS Redirection
- To solve the limitation where the PreToolUse hook cannot determine destination hosts for indirect script executions (e.g. running `python3 leak.py` where the bash command itself lacks the target URL), we plan to introduce a local DNS resolver or transparent SOCKS/system-wide loopback proxy. This would allow `ai-noleak` to intercept outbound script connections dynamically and perform placeholder-to-secret substitution at the socket level.

---

## Lessons from live-traffic testing

These lessons were gathered by dogfooding `ai-noleak` against a real Claude Code session with 30+ fake credentials pasted:

1. **Length-mutating proxies must own Content-Length**: Redacting secrets shrinks request bodies. Forwarding the original `Content-Length` header on a shorter body results in HTTP 400 errors from endpoints. `ai-noleak` strips the client's `Content-Length` and recomputes it dynamically after sanitization.
2. **Brotli is fail-fast**: To prevent silent bypasses, any content-encoding other than `identity` or `gzip` returns an HTTP 502 with a clear explanation rather than passing raw traffic through.
3. **Assemble test fixtures at runtime**: To prevent the proxy from self-redacting tests in transit, literal test credentials must never be committed to source files. They must be constructed dynamically (e.g. string concatenation) in code.
4. **Stripe publishable/Twilio Auth tokens are excluded**: Generic hex keys of arbitrary lengths (without distinct prefixes like `sk_live_`) are indistinguishable from hashes or commit SHAs. Pre-building rules for them leads to high false-positive rates. They can be target-redacted by configuring explicit regexes in config.yaml.
