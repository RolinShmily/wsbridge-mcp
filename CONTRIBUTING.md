# Contributing to wsbridge

Thank you for your interest in contributing to `wsbridge`!

## Engineering Principles

1. **Go >= 1.25 & Static Builds**: All builds must pass with `CGO_ENABLED=0`.
2. **Frozen Dependency Allowlist**: Only the 5 existing external dependencies are permitted (`modelcontextprotocol/go-sdk`, `go.etcd.io/bbolt`, `golang.org/x/crypto` for `argon2`, `pelletier/go-toml/v2`, and `kardianos/service`). Everything else uses the Go standard library.
3. **Zero Unintended Redirects**: `/mcp` and `/mcp/` must never emit HTTP `301`/`302`/`307`/`308` redirects.
4. **Secret Redaction**: Passphrases, authorization codes, access/refresh tokens, `Authorization` headers, `code_verifier`, and tunnel tokens must never appear in logs or error responses.
5. **Test-Driven Development**: Write unit or `e2e` tests alongside changes.

## Local Verification

Before opening a pull request, run:

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

## Contact

- Author: RoL1n_SrP
- Email: contact@srprolin.com
