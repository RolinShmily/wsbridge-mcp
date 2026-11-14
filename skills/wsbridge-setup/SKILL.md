---
name: wsbridge-setup
description: Standard operating procedure for installing, configuring, tunneling, and connecting wsbridge (local MCP server) to ChatGPT, Gemini, and Claude across Linux, macOS, and Windows.
---

# wsbridge Setup & Connection SOP

Use this skill when guiding a user to install `wsbridge`, configure local workspaces and HTTPS tunneling, and connect **ChatGPT**, **Gemini**, or **Claude** to their local machine.

## 1. Prerequisites

Ask or verify these 4 items up front:
1. **OS**: Linux, macOS, or Windows.
2. **Workspaces**: Local directory path(s) and max permission (`read`, `write`, or `check`).
3. **Tunnel**:
   - **Option A (Preferred): `cloudflared`** Named Tunnel with a fixed domain (e.g. `https://bridge.example.com`) and tunnel token file (`0600`) or env var.
   - **Option B (Secondary): `tailscale funnel`** on a fixed `*.ts.net` domain (`tailscale funnel --bg 8787`).
   - Never use ephemeral `*.trycloudflare.com` domains; OAuth `issuer` and platform connectors bind to a fixed `public_url`.
4. **Administrator passphrase**: At least 10 characters (entered interactively by the user, never read or logged by the agent).

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

Run `wsbridge init` in an interactive terminal. It guides the user through:
1. **Workspace(s)**: name, directory path, `max_perm` (`read`/`write`/`check`), and optional `checks` (`git_status,git_diff`).
2. **Tunnel**:
   - `1) cloudflared` (managed by `wsbridge serve`; provide `token_file` or `env:VAR_NAME`).
   - `2) tailscale funnel` (run `tailscale funnel --bg 8787` separately).
   - `3) none / custom reverse proxy`.
3. **Public HTTPS URL**: e.g. `https://bridge.example.com` (no trailing slash or path).
4. **Listen address**: default `127.0.0.1:8787`.
5. **Administrator passphrase**: prompted securely via hidden terminal input (`Argon2id` hash saved to `wsbridge.db`).

Non-interactive fallback: `wsbridge init --non-interactive` writes an example `config.toml`, followed by `wsbridge passwd`.

## 4. Start & Verify

1. If using Tailscale Funnel, enable it first:
   ```bash
   tailscale funnel --bg 8787
   ```
2. Start `wsbridge` (automatically starts and supervises `cloudflared` when `[tunnel] provider = "cloudflared"`):
   ```bash
   wsbridge serve
   ```
   Optional background service on Linux/macOS/Windows:
   ```bash
   wsbridge service install && wsbridge service start
   ```
3. Verify local & public OAuth/MCP discovery in another terminal:
   ```bash
   wsbridge doctor --timeout 10s
   ```
   All critical checks (`public PRM`, `public AS metadata`, `public /mcp`, `public /mcp/`, `public DCR`) must report `PASS` with zero HTTP `3xx` redirects.

## 5. Connect AI Platforms

MCP Endpoint URL for all three platforms: **`<public_url>/mcp`** (no Client ID / Client Secret required; DCR + PKCE S256 are automatic).

- **ChatGPT**:
  - `Settings -> Connectors -> Developer mode -> Create custom connector` -> paste `<public_url>/mcp`.
  - Complete the browser consent page (select workspace, permission, TTL, and enter administrator passphrase).
- **Gemini**:
  - Requirements: **personal Google account**, UI language set to **English**, and **Keep Activity** enabled.
  - `gemini.google.com -> Settings -> Connected Apps -> Add a custom app` -> paste `<public_url>/mcp`.
- **Claude**:
  - `Settings -> Connectors -> Add custom connector` -> paste `<public_url>/mcp`.
  - Complete the browser consent page.

## 6. Day-2 Operations

- Inspect active grants: `wsbridge grants list`
- Revoke a session immediately: `wsbridge grants revoke <grant_id>` (or `--all`)
- Prune expired grants & stale DCR clients: `wsbridge grants prune`
- Debug OAuth handshakes (secrets redacted): `wsbridge serve --debug-oauth`
