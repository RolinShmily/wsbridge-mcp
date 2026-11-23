---
name: wsbridge-setup
description: Standard operating procedure for installing, configuring, tunneling, and connecting wsbridge (local MCP server) to ChatGPT, Gemini, and Claude across Linux, macOS, and Windows.
---

# wsbridge Setup & Connection SOP

Use this skill when guiding a user to install `wsbridge`, configure HTTPS tunneling, switch active workspaces seamlessly, and connect **ChatGPT**, **Gemini**, or **Claude** to their local machine.

## 1. Prerequisites

Ask or verify these 3 items up front:
1. **OS**: Linux, macOS, or Windows.
2. **Tunnel**:
   - **Option A (Preferred): `cloudflared`** Named Tunnel with a fixed domain (e.g. `https://bridge.example.com`) and tunnel token (pasted interactively into `wsbridge init`, saved to `0600` `cloudflared-token`, or supplied via `token_env`).
   - **Option B (Secondary): `tailscale funnel`** on a fixed `*.ts.net` domain (`tailscale funnel --bg 8787`).
   - Never use ephemeral `*.trycloudflare.com` domains; OAuth `issuer` and platform connectors bind to a fixed `public_url`.
3. **Administrator passphrase**: At least 10 characters (entered interactively by the user, never read or logged by the agent).

> Workspaces and permissions do **not** need to be configured during `init`: `wsbridge serve` exposes the current directory by default, `wsbridge use [dir]` hot-switches the active directory without dropping OAuth connections, and connection permissions are managed directly on the browser OAuth consent page.

## 2. Install / Build Binary

- **Linux / macOS**:
  ```bash
  CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
  ```
- **Windows (PowerShell)**:
  ```powershell
  $env:CGO_ENABLED="0"; go build -o wsbridge.exe .\cmd\wsbridge
  ```

## 3. Interactive CLI Onboarding

Run `wsbridge init` once in an interactive terminal. It guides the user through:
1. **Tunnel**:
   - `1) cloudflared` (managed by `wsbridge serve`; paste the Cloudflare tunnel token or full `cloudflared service install <token>` command — saved to `cloudflared-token` with `0600` permissions).
   - `2) tailscale funnel` (run `tailscale funnel --bg 8787` separately).
   - `3) none / custom reverse proxy`.
2. **Public HTTPS URL**: e.g. `https://bridge.example.com` (no trailing slash or path).
3. **Listen address**: default `127.0.0.1:8787`.
4. **Administrator passphrase**: prompted securely via hidden terminal input (`Argon2id` hash saved to `wsbridge.db`).

Non-interactive fallback: `wsbridge init --non-interactive` writes an example `config.toml`, followed by `wsbridge passwd`.

## 4. Start, Switch Projects & Verify

1. If using Tailscale Funnel, enable it first:
   ```bash
   tailscale funnel --bg 8787
   ```
2. Start `wsbridge` from any project directory (automatically starts and supervises `cloudflared` when `[tunnel] provider = "cloudflared"`):
   ```bash
   cd /path/to/project-a
   wsbridge serve
   ```
   Optional background service on Linux/macOS/Windows:
   ```bash
   wsbridge service install && wsbridge service start
   ```
3. Switch the active workspace anytime without restarting or reconnecting remote AI clients:
   ```bash
   cd /path/to/project-b
   wsbridge use
   # Or specify a path explicitly: wsbridge use /path/to/project-b
   # Inspect the currently active workspace: wsbridge use --show
   ```
4. Verify local & public OAuth/MCP discovery in another terminal:
   ```bash
   wsbridge doctor --timeout 10s
   ```
   All critical checks (`public PRM`, `public AS metadata`, `public /mcp`, `public /mcp/`, `public DCR`) must report `PASS` with zero HTTP `3xx` redirects.

## 5. Connect AI Platforms

MCP Endpoint URL for all three platforms: **`<public_url>/mcp`** (no Client ID / Client Secret required; DCR + PKCE S256 are automatic).

- **ChatGPT**:
  - `Settings -> Connectors -> Developer mode -> Create custom connector` -> paste `<public_url>/mcp`.
  - Complete the browser consent page: choose connection permission (**Full access (`check`)** by default, or `write` / `read`), lifetime (default 30 days), and enter the administrator passphrase.
- **Gemini**:
  - Requirements: **personal Google account**, UI language set to **English**, and **Keep Activity** enabled.
  - `gemini.google.com -> Settings -> Connected Apps -> Add a custom app` -> paste `<public_url>/mcp`.
  - Complete the browser consent page.
- **Claude**:
  - `Settings -> Connectors -> Add custom connector` -> paste `<public_url>/mcp`.
  - Complete the browser consent page.

> **Changing connection permissions**: Connection permissions follow whichever workspace is active (capped by any optional local `max_perm` or `serve --max-perm`). To change a connection's permission level, disconnect and reconnect in the AI platform.

## 6. Day-2 Operations

- Hot-switch active workspace: `wsbridge use [dir]` (defaults to `.`)
- Show active workspace: `wsbridge use --show`
- Temporarily cap local server permission: `wsbridge serve --max-perm read`
- Inspect active grants: `wsbridge grants list`
- Revoke a session immediately: `wsbridge grants revoke <grant_id>` (or `--all`)
- Prune expired grants & stale DCR clients: `wsbridge grants prune`
- Debug OAuth handshakes (secrets redacted): `wsbridge serve --debug-oauth`
