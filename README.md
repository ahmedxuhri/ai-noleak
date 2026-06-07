# ai-noleak

Local secret-leak prevention for agentic AI CLIs running through untrusted upstream proxies.

`ai-noleak` is a Go prototype for a local vault, detector, PTY wrapper, hook layer, watcher, and HTTP proxy that replaces credential-like values with deterministic local placeholders before traffic leaves the machine.

See [SPEC.md](SPEC.md) for the architecture and [build/FUTURE_WORK.md](build/FUTURE_WORK.md) for current limitations and next work.

## Build

```sh
cd build
make build
make test
```

## Status

Working v0 prototype. The Go test suite is green locally. Deployment tooling, release CI, and full VPS install docs are future work.

## License

Apache-2.0.
