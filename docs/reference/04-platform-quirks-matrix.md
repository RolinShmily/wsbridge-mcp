# 04. 三平台接入细节、已知坑点与实测记录矩阵

> **优先级顺序**：1. ChatGPT → 2. Gemini → 3. Claude。凡标注 `【待实测】` 的条目必须在对应里程碑（M3/M4/M5）中用真实账号验证，并将结果回写至本文档第 4 节。

---

## 1. ChatGPT（OpenAI）

- **接入路径**：网页端开启 `Settings → Security / Connectors → Developer mode` → `Apps & Connectors` → `Create custom connector`，填写 MCP URL（`<public_url>/mcp`）。
- **认证行为**：
  - 优先检查 `/.well-known/oauth-authorization-server` 中的 `client_id_metadata_document_supported`；若为 `false`，回退使用 `registration_endpoint`（RFC 7591 DCR）注册临时客户端；
  - 若支持 CIMD，`client_id` 为托管在 `chatgpt.com` 上的 HTTPS JSON URL（v2 适配）；
  - 授权请求与 Token 请求均携带 `resource=<public_url>/mcp`（RFC 8707）；
  - **关键坑点**：部分场景下 ChatGPT 发起授权请求时未显式申请 `offline_access` scope，若服务端不返回 `refresh_token`，1 小时后 `access_token` 过期会导致连接器直接失效且不会自动重连。因此 `wsbridge` **始终签发 `refresh_token`**。
- **工具确认机制 `【待实测】`**：Developer Mode 下默认依据工具 `annotations`（如 `destructiveHint: true`）决定是否在对话中弹出确认按钮。

---

## 2. Gemini（Google Spark 自定义应用）

- **接入路径**：`gemini.google.com` → `Settings` → `Connected Apps` → `Add a custom app` → 粘贴 `<public_url>/mcp`。
- **前置账号条件**：
  - 必须使用**个人 Google 账号**（Workspace 商业账号受管理员策略限制）；
  - 界面语言必须切换为 **English**；
  - 账号必须开启 **Keep Activity**（Gemini Apps Activity）。
- **认证行为**：
  - 严格依赖 RFC 9728（PRM）→ RFC 8414（AS 元数据）→ RFC 7591（DCR）→ PKCE S256；
  - DCR 注册时会一次性提交约 **6 个** `oauth-redirect*.googleusercontent.com` 回调地址（均已纳入默认白名单）；
  - 若服务端未暴露 DCR，Gemini 会降级要求用户手动填写 `Client ID` 与 `Client Secret`（本架构不走此降级路径）。
- **已知高风险坑点 `【已实测未复现】`**：
  - 社区论坛报告部分自定义 MCP 服务在浏览器完成同意页并 `302` 返回授权码后，Google 后端从未调用 `/oauth/token`，前端报错 `Cannot Complete Request`。
  - **M4 排查清单**：使用 `wsbridge serve --debug-oauth` 抓取完整交互，对照参考实现 `ghchinoy/spark-agent-tools` 逐项比对：
    1. `issuer` 是否与 `public_url` 逐字符一致（无多余斜杠）；
    2. `/.well-known/oauth-protected-resource` 与 `/.well-known/oauth-protected-resource/mcp` 的响应字段；
    3. `302` 回调 URL 中 `code`、`state`、`iss` 参数编码格式；
    4. 响应头 `Content-Type` 与 `Cache-Control`。

---

## 3. Claude（Anthropic Web / Desktop / Mobile / Cowork）

- **接入路径**：`claude.ai`（或 Claude 桌面端）→ `Settings` → `Connectors` → `Add custom connector`，输入 `<public_url>/mcp`。
- **认证行为**：
  - 统一由 Anthropic 云端托管运行时发起所有 MCP 请求（即使在桌面端或移动端操作，流量也来自 Anthropic 云端 IP）；
  - 回调地址主要为 `https://claude.ai/api/mcp/auth_callback`（部分工作区为 `claude.com`）；
  - 支持 DCR、CIMD 与预注册客户端，强制 PKCE S256 与 `resource` 参数。
- **已知关键坑点**：
  1. **跨主机或路径重定向丢失 `Authorization` 头**：Claude 托管运行时在遇到 `301`/`302` 重定向时会剥离 `Authorization` 头，导致后续请求全部 `401`。`wsbridge` 通过显式双注册 `/mcp` 与 `/mcp/` 彻底规避；
  2. **重复重连产生僵尸 Client**：用户每次在 Claude 界面点击断开并重新连接时，Claude 都会再次调用 `/oauth/register` 创建新的 `client_id`。`wsbridge` 的 24 小时未激活自动清理与 `200` 上限淘汰机制专门解决此问题。

---

## 4. 平台实测验收记录表（Agent 完成 M3/M4/M5 后回写）

| 里程碑 | 实测日期 | 平台与版本/入口 | 实测抓包特征（`client_id` / `redirect_uri` / `scope`） | 遇到的问题与最终解法 |
| :--- | :--- | :--- | :--- | :--- |
| **M3 ChatGPT** | 2026-11-14 | ChatGPT Web (`Settings → Connectors → Developer mode → Create custom connector`)；UA: `openai-connectors-oauth/1.0`, `openai-mcp/1.0.0` | `client_id=wsb_cli_207865b21092` (`ChatGPT`)；`redirect_uri=https://chatgpt.com/connector_platform_oauth_redirect`；`scope=offline_access mcp:tools`；`Mcp-Protocol-Version: 2026-07-28`（`server/discover` → `tools/list` → `tools/call`）；重连时会先调用 `/oauth/revoke` | 1. 同意页原 CSP `form-action 'self'` 在 Chromium 下拦截表单 POST 后的跨域 `302` 回调，移除 `form-action 'self'` 后恢复跳转；2. 有状态 MCP 传输不支持 `2026-07-28` 协议版本导致 `action discovery failed`，在 `StreamableHTTPOptions` 启用 `Stateless: true` 后完整通过 `list_workspaces` 与 `read_file` |
| **M4 Gemini** | 2026-11-14 | Gemini Web (`Settings → Connected Apps → Add a custom app`)；UA: `Google` | `client_id=wsb_cli_f149850be151` (`Google`)；DCR 一次提交 6 个 `oauth-redirect*.googleusercontent.com/{r,a}/...` 回调；`Mcp-Protocol-Version: 2025-11-25` | 一次通过 DCR、授权、换取 token 与 `get_file_tree` / `list_workspaces` / `read_file`；未出现 `/oauth/token` 未调用问题 |
| **M5 Claude** | 2026-11-14 | Claude Web (`Settings → Connectors → Add custom connector`)；UA: `Claude-User`, `X-Anthropic-Client: ClaudeAI` | `client_id=wsb_cli_7ffe3fba437a` (`Claude`)；`redirect_uri=https://claude.ai/api/mcp/auth_callback`；`scope=mcp:tools offline_access`；`Mcp-Protocol-Version: 2026-07-28`（`server/discover` → `tools/list` → `tools/call`） | 一次通过 DCR、授权、换取 token 与 `list_workspaces` / `get_file_tree` / `read_file`；`Stateless: true` 与 `/mcp`、`/mcp/` 无重定向双注册协同生效 |
