## Summary

<!-- Briefly describe the change and link any related issue. -->

## Checklist

- [ ] `gofmt -l .` returns no unformatted files
- [ ] `go vet ./...` passes
- [ ] `go test -race -count=1 ./...` passes
- [ ] `CGO_ENABLED=0 go build ./cmd/wsbridge` succeeds
- [ ] No new external dependencies added outside the allowlist
- [ ] No secrets or tokens logged or exposed in error messages
