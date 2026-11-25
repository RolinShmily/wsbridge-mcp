# wsbridge

**English** | [简体中文](README.zh-CN.md)

## What is this?

`wsbridge` is a single-user local workspace bridge for **ChatGPT, Gemini, and Claude**. It runs as a **single static Go binary** (`CGO_ENABLED=0`) on Windows, macOS, and Linux, embedding:

- an **OAuth 2.1 authorization server** — so AI platforms can authenticate to your machine through their standard custom-connector flow (discovery → DCR → PKCE `S256` → consent page), no external IdP required;
- a **Streamable HTTP MCP endpoint** (`<public_url>/mcp`) — exposing a deliberately small toolset (read / search / edit / write / run built-in project checks) that the AI model can call safely against your current workspace;
- a **`os.Root` kernel sandbox** — blocks path traversal and symlink escapes, and denies sensitive files (`.git`, `.ssh`, `.env`, private keys) by default.

You stay in control: workspaces follow the directory where you run `wsbridge serve` (and hot-switch live with `wsbridge use`), and each connection's maximum permission is chosen on the browser consent page — change it anytime by disconnecting and reconnecting. **No shell access and no network tools are exposed.**

## What do you need?

- **Go ≥ 1.25** to build from source (or download a release binary from the Releases page).
- A **stable public HTTPS URL** — the platform clouds must reach you. Recommended options:
  - **Tailscale Funnel** (preferred): `tailscale funnel --bg 8787`
  - **Cloudflare Named Tunnel**: a fixed `cloudflared` subdomain
  - **ngrok static domain**: `ngrok http --domain=<static-domain> 8787`
  
  > Never use random temporary domains (e.g. `*.trycloudflare.com`): changing the URL invalidates every connected connector.

## How to use it

### 1. Build

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. Initialize once

`wsbridge init` configures your tunnel (`cloudflared` or `tailscale funnel`), `public_url`, and administrator passphrase:

```bash
wsbridge init
```

For non-interactive / scripted setup:

```bash
wsbridge init --non-interactive
wsbridge passwd
```

### 3. Serve, switch projects, and check

```bash
# Start serving the current project directory:
cd /path/to/project-a
wsbridge serve

# In another terminal, hot-switch the active workspace without reconnecting:
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

### 4. Connect an AI platform

Use the same MCP endpoint URL on all three platforms: `<public_url>/mcp` (e.g. `https://bridge.example.com/mcp`).

| Platform | Entry point | Notes |
| :--- | :--- | :--- |
| **ChatGPT** | `Settings → Connectors → Developer mode → Create custom connector` | Automatic DCR + PKCE; calls `/oauth/revoke` on reconnect |
| **Gemini** | `gemini.google.com → Settings → Connected Apps → Add a custom app` | Requires a personal Google account, `English` UI, and Keep Activity enabled |
| **Claude** | `Settings → Connectors → Add custom connector` | Explicit `/mcp` and `/mcp/` routes with zero `301` redirects |

### Common commands

```bash
wsbridge grants list                  # List active and historical grants
wsbridge grants revoke <grant_id>     # Revoke a grant immediately
wsbridge grants revoke --all          # Revoke all grants
wsbridge grants prune                 # Clean up expired grants and stale DCR clients
wsbridge serve --debug-oauth          # Log redacted OAuth/MCP diagnostics
```

## Documentation

The `docs/` directory holds four self-contained specs:

| File | What it covers |
| :--- | :--- |
| **[architecture.md](docs/architecture.md)** | System overview, OAuth 2.1 & Grant model, MCP/sandbox design, deployment & threat model |
| **[reference.md](docs/reference.md)** | OAuth endpoint messages, MCP tool schemas, CLI & `config.toml`, per-platform integration notes & test log |
| **[development.md](docs/development.md)** | Coding standards, repository/module contracts, testing & CI, M0–M7 milestones |
| **[design.md](docs/design.md)** | OAuth consent page UI & form contract |

See also: [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md)

## License & Author

- License: [MIT](LICENSE)
- Author: RoL1n_SrP (`contact@srprolin.com`)