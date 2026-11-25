# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.3] - 2026-11-25

### Changed

- Adopted a full Go module path (`github.com/RolinShmily/wsbridge-mcp`), so the project is
  installable via `go install github.com/RolinShmily/wsbridge-mcp/cmd/wsbridge@latest` and
  indexable on pkg.go.dev.
- Consolidated `docs/` into four self-contained single-file specs (`architecture.md`,
  `development.md`, `reference.md`, `design.md`), replacing the 14-file subdirectory tree.
- Moved the end-to-end test client from `e2e/` to `tests/e2e`, the Go-idiomatic home for an
  external integration test package.
- Rewrote `CONTRIBUTING.md` around the frozen dependency allowlist, sandbox-first testing, and
  the tagged release flow.

### Removed

- The `skills/wsbridge-setup/` skill.
- GitHub issue report/feature templates and the pull request template, per the project's new
  minimal maintenance surface.

## [v0.1.2] - 2026-11-23

### Added
- Dynamic workspace mode: `wsbridge serve [dir]` defaults to the current working directory when no static `[[workspace]]` blocks are configured, and `wsbridge use [dir]` (with `--name` / `--show`) hot-switches the active workspace of a running server via an authenticated local-only loopback control plane (`control.json` + `active-workspace.json`) without dropping tunnels or OAuth sessions.
- Expanded built-in `run_check` commands (22 total) covering Git (`git_status`, `git_diff`, `git_log`), Go (`go_vet`, `go_test`, `go_build`), Node (`npm_lint`, `npm_test`, `npm_build`), Python (`pytest`, `ruff_check`, `mypy`, `uv_pytest`, `uv_ruff`, `uv_mypy`, `uv_lock_check`, `uv_pip_list`, `uv_pip_check`, `pip_list`, `pip_check`), and Rust (`cargo_check`, `cargo_test`), all enabled by default.
- Optional local permission cap (`max_perm` in `config.toml` and `wsbridge serve --max-perm`) that clamps effective permissions with `min(local_cap, grant_perm)`.

### Changed
- Simplified `wsbridge init` to configure only tunnel settings, `public_url`, `listen`, and the administrator passphrase.
- Simplified the OAuth consent page to default to full connection access (`check`, 30-day lifetime) with dynamic wildcard workspace grants (`*`) that seamlessly follow active directory switches.
- Marked `run_check` with `destructiveHint: true` so AI platforms prompt for confirmation before executing check commands as well as file edits/writes.

## [v0.1.1] - 2026-11-14

### Changed
- Streamlined interactive `wsbridge init` for managed `cloudflared` tunnels: prints the target `config.toml` path upfront and prompts once to paste the tunnel token directly (also extracts the token if pasting `cloudflared service install <token>`), saving it atomically to `cloudflared-token` with `0600` permissions.
- Added `omitempty` TOML tags to optional `Config` and `Tunnel` fields so generated `config.toml` files stay minimal and clean.

## [v0.1.0] - 2026-11-14

### Added
- Single static Go binary (`CGO_ENABLED=0`) for Linux, macOS, and Windows (`amd64` / `arm64`).
- Built-in OAuth 2.1 authorization server (`bbolt`, `Argon2id`, PKCE S256, DCR, refresh rotation with 30s grace window, replay revocation, and monochrome inline-SVG consent UI).
- `os.OpenRoot` workspace sandbox with symlink/traversal blocking, Windows reserved device/ADS guards, sensitive file denylist (`.git`, `.ssh`, `.env`, private keys), pre-write snapshots, and atomic writes.
- Seven MCP tools over Streamable HTTP (`/mcp` and `/mcp/`): `list_workspaces`, `get_file_tree`, `search_code`, `read_file`, `edit_file`, `write_file`, and `run_check` (fixed allowlist).
- Managed `cloudflared` tunnel subprocess (`[tunnel]`) with `Pdeathsig` parent-death binding on Linux, plus `wsbridge doctor` diagnostics and `wsbridge service` user-level daemon management.
- Interactive CLI onboarding in `wsbridge init` (`--non-interactive` supported) and multi-platform setup SOP skill in `skills/wsbridge-setup/SKILL.md`.
- Live platform verification completed for ChatGPT, Gemini, and Claude.
