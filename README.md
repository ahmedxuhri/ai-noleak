# ai-noleak

Local secret-leak prevention for agentic AI CLIs running through untrusted upstream proxies.

`ai-noleak` is a Go prototype for a local vault, detector, PTY wrapper, hook layer, watcher, and HTTP proxy that replaces credential-like values with deterministic local placeholders before traffic leaves the machine.

See [SPEC.md](SPEC.md) for the architecture and [FUTURE_WORK.md](FUTURE_WORK.md) for current limitations and next work.

## Build

```sh
make build
make test
```

## Proxy Configuration

`noleak proxy` reads `~/.noleak/config.yaml`.

```yaml
proxy_listen: 127.0.0.1:9999
proxy_upstream: https://proxy.example/v1
proxy_preserve_headers:
  - Authorization
  - X-Api-Key
  - Anthropic-Version
  - Anthropic-Beta
proxy_passthrough_tokens:
  - exact-upstream-proxy-token-that-may-appear-in-request-bodies
```

`proxy_passthrough_tokens` is for upstream-proxy authentication material that is intentionally allowed to reach that upstream. Do not put provider keys, wallet material, bot tokens, or user account secrets there.

## Status

Working v0 prototype. The Go test suite is green locally. Deployment tooling, release CI, and full VPS install docs are future work.

## License

Apache-2.0.
