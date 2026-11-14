# wsbridge

**English** | [简体中文](README.zh-CN.md)

`wsbridge` is a single-user local workspace bridge distributed as a **single static Go binary (`CGO_ENABLED=0`)** for Windows, macOS, and Linux. It embeds an OAuth 2.1 authorization server and a Streamable HTTP MCP endpoint so **ChatGPT, Gemini, and Claude** can safely read, edit, and run whitelisted checks on selected local directories.

## Key Features

- **Single Static Binary**: Built with Go ≥ 1.25 (`CGO_ENABLED=0`), embedded `bbolt` storage, `Argon2id` passphrase hashing, and a zero-JS monochrome OAuth consent page.
- **Built-in OAuth 2.1 + Grant Model**: Supports PRM (`RFC 9728`), AS metadata (`RFC 8414`), DCR (`RFC 7591`), PKCE `S256`, refresh token rotation (30s grace window), and replay revocation. Every token is scoped to explicit workspaces, permissions (`read` / `write` / `check`), and TTL.
- **`os.Root` Kernel Sandbox**: Uses Go `os.OpenRoot` to block path traversal and symlink escapes, guards against Windows reserved device names and ADS, and denies sensitive paths (`.git`, `.ssh`, `.env`, private keys).
- **Pre-Write Snapshots & Fixed Checks**: Captures an external snapshot before every write, requires `expected_sha256` on overwrites, and limits `run_check` to a fixed compile-time allowlist (`git_status`, `git_diff`, `go_vet`, `go_test`, `npm_lint`, `npm_test`).
- **Managed Tunneling**: Supervises `cloudflared` (`[tunnel]`, automatically stopped when `wsbridge` exits) as the primary option, with `tailscale funnel` as a secondary option.

## Quickstart

### 1. Build (or download from Releases)

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. Interactive Setup

Run `init` in an interactive terminal to configure your workspaces, permissions, tunnel (`cloudflared` or `tailscale funnel`), `public_url`, and administrator passphrase:

```bash
./wsbridge init
```

For non-interactive / scripted setup:

```bash
./wsbridge init --non-interactive
./wsbridge passwd
```

### 3. Start & Diagnose

```bash
./wsbridge serve
# In another terminal, verify local config, managed tunnel, and public discovery:
./wsbridge doctor --timeout 10s
```

Optional user-level background service (`systemd` / `launchd` / Windows Service):

```bash
./wsbridge service install
./wsbridge service start
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
