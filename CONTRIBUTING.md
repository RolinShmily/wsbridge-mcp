# Contributing to wsbridge

Thank you for your interest in contributing to `wsbridge`.

## Engineering Principles

1. **Go ≥ 1.25, static builds** — every build passes with `CGO_ENABLED=0`. The module path is
   `github.com/RolinShmily/wsbridge-mcp`; `go.mod` must not be downgraded below 1.25.
2. **Frozen dependency allowlist** — only the 5 existing external dependencies are permitted:
   `modelcontextprotocol/go-sdk`, `go.etcd.io/bbolt`, `golang.org/x/crypto` (argon2 only),
   `pelletier/go-toml/v2`, and `kardianos/service` (service subcommand only). Everything else uses
   the Go standard library. No `cobra`, `gin`, `chi`, `fosite`, or similar.
3. **Zero unintended redirects** — `/mcp` and `/mcp/` must never emit `301`/`302`/`307`/`308`
   redirects (both routes are registered explicitly so `http.ServeMux` never auto-301s).
4. **Secret redaction** — passphrases, authorization codes, access/refresh tokens,
   `Authorization` headers, `code_verifier`, and tunnel tokens must never appear in logs
   (including `--debug-oauth`) or error responses.
5. **Test-driven, sandbox-first** — write unit tests or `tests/e2e` coverage alongside changes.
   Paths are validated through `os.Root`; never bypass the workspace sandbox. See
   [`docs/development.md`](docs/development.md) for the full spec.

## Development Workflow

Workspace follows `os.Root` (`internal/ws`). The MCP endpoint is the only interface a client
sees; the internal packages must keep their layering as documented in
[`docs/development.md`](docs/development.md#2-仓库结构与模块接口契约).

- New features and bug fixes go through a pull request (no template required).
- The OAuth grant model, token rotation, and the workspace sandbox are security boundaries —
  changes there need explicit attention in the review.
- CI runs on Linux, macOS, and Windows. Keep platform-conditional code behind build tags under
  `internal/`.

### Local verification

Before opening a pull request, run:

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

## Releases

- Version tags follow `v*` (`v0.1.3`, …). Pushing a `v*` tag triggers
  [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds with GoReleaser
  and publishes the GitHub Release.
- The release notes and changelog should note redirect or security-sensitive changes explicitly.

## Contact

- Author: RoL1n_SrP
- Email: contact@srprolin.com