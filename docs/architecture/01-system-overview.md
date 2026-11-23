# 01. 系统总体架构（System Overview）

## 1. 背景与设计目标

网页端与桌面端 AI 助手（ChatGPT、Gemini、Claude）支持通过远程 MCP（Model Context Protocol）连接器调用外部工具，但官方托管连接器普遍要求 MCP 服务暴露在公网 HTTPS 地址上，且直接将本机文件系统暴露给云端模型存在严重的数据泄露与误操作风险。

`wsbridge` 的核心目标是提供一座**零外部依赖、默认最小权限、单进程运行**的本地安全桥梁：

1. **单静态二进制交付**：基于 Go ≥ 1.25 编译（`CGO_ENABLED=0`），无 C 依赖、无外部数据库进程、无外接 IdP，在 Windows、macOS、Linux 上拥有完全一致的行为。
2. **单端点统一接入**：对外仅暴露一个符合 MCP 规范的 Streamable HTTP 端点（`/mcp`），内建完整的 OAuth 2.1 授权服务（`/oauth/*` 与 `/.well-known/*`），使 ChatGPT、Gemini、Claude 均可直接通过自定义连接器完成“添加 URL → 浏览器授权 → 调用工具”闭环。
3. **动态工作区跟随与连接级权限（授权即 Grant）**：`wsbridge init` 仅配置公网 `public_url`、隧道与管理员口令，不再在全局配置写死工作区与权限；工作区默认跟随启动目录（`wsbridge serve [dir]`）并支持 `wsbridge use [dir]` 实时热切换不断连。连接的最大权限统一在浏览器同意页选择（默认全开 `check`，若本地显式配置了更低 `max_perm` 则取最小值），需要变更权限只需断开重连。
4. **小而稳的受限工具集**：仅提供读、搜、改、内置项目检查等不超过 8 个工具，**坚决不提供任意 shell 执行或通用网络请求工具**；所有写与检查工具均声明 `destructiveHint: true` 触发宿主确认。

### 非目标（Explicit Non-Goals）
- **多用户 SaaS 托管**：仅面向单机单用户（本机管理员通过统一口令授权）。
- **云端文件中转存储**：所有文件读写均在本地工作区直接完成，不上传至任何第三方存储。
- **桌面 GUI（v1 不做）**：v1 仅提供 CLI 与浏览器端 OAuth 同意页；v2 可考虑终端本机确认模式。
- **任意命令执行**：`run_check` 仅允许执行编译期内建的固定项目检查命令集合（覆盖 Git / Go / Node / Python `uv`/`pip`/`pytest`/`ruff`/`mypy` / Rust），默认全部开放。

---

## 2. 三平台协议交集约束

三大平台对自定义远程 MCP 连接器的支持细节各异（详见 `docs/reference/04-platform-quirks-matrix.md`），系统架构严格取三者的最大公约数：

| 维度 | ChatGPT (Developer Mode) | Gemini (Spark Custom App) | Claude (Web / Desktop / Mobile) | `wsbridge` 架构决策 |
| :--- | :--- | :--- | :--- | :--- |
| **MCP 传输** | Streamable HTTP | Streamable HTTP | Streamable HTTP | 仅实现 Streamable HTTP（`/mcp`） |
| **资源发现** | RFC 9728 (PRM) | RFC 9728 (PRM) | RFC 9728 (PRM) | 返回 `401` + `WWW-Authenticate: Bearer resource_metadata=...` |
| **元数据发现** | RFC 8414 / OIDC | RFC 8414 | RFC 8414 | 同时暴露 `/.well-known/oauth-authorization-server` 与 `openid-configuration` 别名 |
| **客户端注册** | 偏好 CIMD，支持 DCR | 依赖 RFC 7591 DCR | 支持 DCR / CIMD / 预注册 | **v1 以 DCR 为主**，元数据预留 CIMD 字段，v2 实现 CIMD |
| **授权安全** | PKCE S256 + `resource` | PKCE S256 | PKCE S256 + `resource` | 强制要求 PKCE `S256`；校验 RFC 8707 `resource` |
| **会话保持** | 未带 `offline_access` 易过期 | 标准 OAuth | 标准 OAuth | **服务端始终签发 `refresh_token`** 并支持轮换 |
| **重定向敏感度** | 常规 | 严格校验回调参数 | 跨主机重定向会丢 `Authorization` 头 | **全站 MCP 路径零重定向**（显式注册 `/mcp` 与 `/mcp/`） |

---

## 3. 系统逻辑架构与请求数据流

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    云端 AI 平台 (ChatGPT / Gemini / Claude)               │
│                 (发起 DCR 注册、浏览器跳转授权、携带 Bearer 调用 MCP)      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTPS (公网稳定域名: public_url)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             公网 HTTPS 反向隧道 (Tailscale Funnel / CF Tunnel / ngrok)    │
│                         (终止 TLS，转发至 127.0.0.1:8787)                 │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP (127.0.0.1)
                                     ▼
┌─────────────────────────── wsbridge 单进程 ──────────────────────────────┐
│  1. HTTP 网关层 (internal/httpx — 标准库 net/http)                        │
│     ├─ 安全中间件: 请求体上限(1MB) / 全链路超时 / 每令牌限流(120 req/min)   │
│     ├─ 脱敏日志中间件: 自动掩码 Authorization / code / refresh_token / 口令 │
│     └─ 路由分发 (禁止自动 301 重定向):                                    │
│         ├─ GET  /.well-known/* ──────────▶ OAuth 元数据 (PRM & AS)        │
│         ├─ ALL  /oauth/* ────────────────▶ 内置 OAuth 2.1 授权服务        │
│         └─ POST/GET/DELETE /mcp, /mcp/ ──▶ Bearer 鉴权中间件 ──▶ MCP 引擎 │
│                                                                         │
│  2. 身份与授权层 (internal/oauth + bbolt)                                │
│     ├─ 客户端动态注册表 (DCR, 域名白名单校验, 24h 未授权自动清理)           │
│     ├─ 授权码内存池 (32B 随机, 60s TTL, 单次有效, 重放级联撤销)             │
│     ├─ 同意页渲染与验证 (consent.html, CSRF, argon2id 口令, 5次锁定5分钟)  │
│     └─ 令牌与 Grant 存储 (bbolt: 仅存 Token SHA-256 哈希, 30s 轮换宽限期)   │
│                                                                         │
│  3. MCP 协议与工具层 (internal/mcpsrv + internal/tools)                  │
│     ├─ go-sdk Streamable HTTP Handler (DisableLocalhostProtection=true) │
│     ├─ Grant 权限拦截器: 校验目标 workspace 是否在授权列表及权限等级是否足够  │
│     └─ 受控工具集 (≤8个): list_workspaces / get_file_tree / search_code  │
│                          read_file / edit_file / write_file / run_check │
│                                                                         │
│  4. 工作区沙盒与审计层 (internal/ws + internal/audit)                     │
│     ├─ os.OpenRoot 句柄池: 内核级目录边界隔离，防路径穿越与符号链接逃逸       │
│     ├─ 敏感名单拦截 (.git, .env*, .ssh, 私钥等) & Windows 设备名/ADS 过滤  │
│     ├─ 写前外部快照 (<data_dir>/snapshots/) + 同目录临时文件原子 Rename     │
│     └─ 异步/同步 JSONL 审计日志 (<data_dir>/audit.jsonl)                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. 关键架构决策记录（ADR）

### ADR-01：内置轻量 OAuth 2.1 服务，拒绝外接 IdP
- **背景**：Auth0、Keycloak 或自建 Zitadel/Ory Hydra 部署复杂度远超工具本身，且无法原生表达“选定本地工作区 + 读写权限等级”的授权语义。
- **决策**：使用标准库 + `bbolt` + `golang.org/x/crypto/argon2` 自研约 800 行内置 OAuth 2.1 授权服务。
- **收益**：用户只需执行 `wsbridge init` 与 `wsbridge passwd` 即可拥有完整 OAuth 能力，零外部运维成本。

### ADR-02：不透明随机令牌 + SHA-256 哈希落盘
- **背景**：JWT 令牌在签发后难以即时撤销，且需要管理非对称签名私钥轮换。
- **决策**：`access_token` 与 `refresh_token` 均生成 32 字节密码学安全随机串（Base64URL 编码），`bbolt` 数据库中仅存储其 `SHA-256` 摘要。
- **收益**：支持通过 `wsbridge grants revoke` 毫秒级吊销指定会话；即使磁盘上的 `bbolt` 文件意外泄露，攻击者也无法还原出可用令牌。

### ADR-03：纯文本工具响应（TextContent Only）
- **背景**：不同网页端 AI 客户端对 MCP `structuredContent` 的解析支持程度不一，部分版本会忽略或报错。
- **决策**：所有工具均返回人类与大模型均易读的结构化纯文本（`mcp.TextContent`），包含清晰的行号、文件路径、SHA-256 摘要或统一 Diff 片段。

### ADR-04：利用 Go 1.25 `os.Root` 构建目录沙盒
- **背景**：传统的基于 `filepath.Clean` + `strings.HasPrefix` 的路径检查极易受到 TOCTOU（检查时间与使用时间差）符号链接攻击。
- **决策**：采用 Go 1.25 完善的 `os.OpenRoot` API（支持 `Root.Open`、`Root.ReadFile`、`Root.WriteFile`、`Root.Rename`、`Root.Stat` 等），由操作系统底层文件描述符机制（如 `openat` + `RESOLVE_BENEATH`）阻断一切逃逸。
