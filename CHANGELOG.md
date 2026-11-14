# Changelog

All notable changes to this project will be documented in this file.

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
