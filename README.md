# wsbridge

**English** | [简体中文](README.zh-CN.md)

`wsbridge` is a single-user local workspace bridge distributed as a **single static Go binary (`CGO_ENABLED=0`)** for Windows, macOS, and Linux. It embeds an OAuth 2.1 authorization server and a Streamable HTTP MCP endpoint so **ChatGPT, Gemini, and Claude** can safely read, edit, and run whitelisted checks on selected local directories.

## Key Features

- **Single Static Binary**: Built with Go ≥ 1.25 (`CGO_ENABLED=0`), embedded `bbolt` storage, `Argon2id` passphrase hashing, and a streamlined zero-JS OAuth consent page.
- **Dynamic Workspace Switching**: `wsbridge serve` exposes the current working directory by default, and `wsbridge use [dir]` hot-switches the active workspace of a running daemon without dropping your tunnel or re-authorizing OAuth clients.
- **Built-in OAuth 2.1 + Connection-Scoped Permissions**: Supports PRM (`RFC 9728`), AS metadata (`RFC 8414`), DCR (`RFC 7591`), PKCE `S256`, refresh token rotation (30s grace window), and replay revocation. Permissions (`check` full access by default, `write`, or `read`) are controlled directly in the browser consent page; disconnect and reconnect anytime to change them.
- **`os.Root` Kernel Sandbox**: Uses Go `os.OpenRoot` to block path traversal and symlink escapes, guards against Windows reserved device names and ADS, and denies sensitive paths (`.git`, `.ssh`, `.env`, private keys).
- **Pre-Write Snapshots & Built-in Project Checks**: Captures an external snapshot before every write, requires `expected_sha256` on overwrites, and enables a fixed compile-time suite of project checks by default (`git_status`, `git_diff`, `git_log`, `go_vet`, `go_test`, `go_build`, `npm_lint`, `npm_test`, `npm_build`, `pytest`, `ruff_check`, `mypy`, `uv_pytest`, `uv_ruff`, `uv_mypy`, `uv_lock_check`, `uv_pip_list`, `uv_pip_check`, `pip_list`, `pip_check`, `cargo_check`, `cargo_test`).
- **Managed Tunneling**: Supervises `cloudflared` (`[tunnel]`, automatically stopped when `wsbridge` exits) as the primary option, with `tailscale funnel` as a secondary option.

## Quickstart

### 1. Build (or download from Releases)

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. Interactive Setup

Run `init` once to configure your tunnel (`cloudflared` or `tailscale funnel`), `public_url`, and administrator passphrase (no workspace locking required):

```bash
wsbridge init
```

For non-interactive / scripted setup:

```bash
wsbridge init --non-interactive
wsbridge passwd
```

### 3. Start, Switch Projects & Diagnose

```bash
# Start serving the current project directory:
cd /path/to/project-a
wsbridge serve

# In another terminal, hot-switch the active workspace anytime without reconnecting:
cd /path/to/project-b
wsbridge use

# Verify local config, managed tunnel, and public discovery:
wsbridge doctor --timeout 10s
```

Optional user-level background service (`systemd` / `launchd` / Windows Service):

```bash
wsbridge service install
wsbridge service start
# Then run `wsbridge use` from any project directory to switch what remote clients see.
```

### 4. Connect AI Platforms

Use the same MCP endpoint URL across all three platforms: `<public_url>/mcp` (for example, `https://bridge.example.com/mcp`).

| Platform | Entry Point | Notes |
| :--- | :--- | :--- |
| **ChatGPT** | `Settings → Connectors → Developer mode → Create custom connector` | Automatic DCR + PKCE; calls `/oauth/revoke` on reconnect |
| **Gemini** | `gemini.google.com → Settings → Connected Apps → Add a custom app` | Requires a personal Google account, `English` UI, and Keep Activity enabled |
| **Claude** | `Settings → Connectors → Add custom connector` | Explicit `/mcp` and `/mcp/` routes with zero `301` redirects |

## Common Commands

```bash
wsbridge grants list                  # List active and historical grants
wsbridge grants revoke <grant_id>     # Revoke a grant immediately
wsbridge grants revoke --all          # Revoke all grants
wsbridge grants prune                 # Clean up expired grants and stale DCR clients
wsbridge serve --debug-oauth          # Log redacted OAuth/MCP diagnostics
```

## Documentation & SOP Skill

- Architecture & spec index: [docs/README.md](docs/README.md)
- Live platform verification matrix: [docs/reference/04-platform-quirks-matrix.md](docs/reference/04-platform-quirks-matrix.md)
- Multi-platform setup SOP skill for agents: [skills/wsbridge-setup/SKILL.md](skills/wsbridge-setup/SKILL.md)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## License & Author

- License: [MIT](LICENSE)
- Author: RoL1n_SrP (`contact@srprolin.com`)
