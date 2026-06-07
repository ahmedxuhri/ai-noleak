# noleak

Local secret-leak prevention for agentic AI CLIs running through untrusted upstream proxies.

See [`../SPEC.md`](../SPEC.md) for the architecture.

## Build

```
make build      # produces bin/{noleakd,noleak-watch,noleak}
make vet
make test
```

## Status

Stage 1: project skeleton (this commit).

Subsequent stages per `SPEC.md` §13.
