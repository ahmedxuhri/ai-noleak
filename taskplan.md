# Task Plan

## 1. Add `noleak doctor` — done

Build an operator confidence command that verifies the local installation is actually protecting traffic:

- daemon reachability and health
- socket path and permissions
- vault status and entry count
- proxy config presence
- loopback-only proxy bind
- upstream URL sanity
- watcher rules presence
- agent hook/config hints where detectable
- clear pass/warn/fail output

## 2. Add CI — done

Add GitHub Actions coverage for:

- `go test ./...`
- `go vet ./...`
- `gitleaks detect`
- build checks for Linux amd64 and arm64

## 3. Write Manual VPS Install Docs — done

Create copy-pasteable docs for a manual VPS install:

- build from source
- copy binaries
- create config
- start daemon/proxy/watch processes
- point an agent CLI at the local proxy
- verify noleak is on the request path
- troubleshoot common failures

## 4. Add Dogfood Transcript — done

Document one real local test flow using synthetic secrets only:

- exact setup commands
- synthetic prompt/body
- expected proxy log lines
- expected upstream-safe placeholder behavior
- what a bypass/misconfiguration looks like

## 5. Add Install Script / Release Prep — initial version done

After the manual path is proven, add deployment packaging:

- install script
- binary placement
- optional systemd user units
- release build workflow
- checksum/signature plan
