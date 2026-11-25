# wsbridge 系统架构与安全设计

> **调研基准时间**：2026-11 ｜ **目标语言**：Go ≥ 1.25（`CGO_ENABLED=0`） ｜ **平台优先级**：ChatGPT → Gemini → Claude
>
> 本文件是整个项目的**系统与安全架构唯一权威规格**。开发者/实现 Agent 在动手前必须通读本节全部内容。

## 目录导航

- [1. 系统总体架构](#1-系统总体架构)
  - [1.1 背景与设计目标](#11-背景与设计目标)
  - [1.2 明确的非目标（Non-Goals）](#12-明确的非目标non-goals)
  - [1.3 三平台协议交集约束](#13-三平台协议交集约束)
  - [1.4 系统逻辑架构与请求数据流](#14-系统逻辑架构与请求数据流)
  - [1.5 关键架构决策记录（ADR）](#15-关键架构决策记录adr)
- [2. 内置 OAuth 2.1 与 Grant 权限模型](#2-内置-oauth-21-与-grant-权限模型)
  - [2.1 核心概念模型](#21-核心概念模型)
  - [2.2 Issuer 强绑定原则](#22-issuer-强绑定原则)
  - [2.3 完整授权生命周期状态机](#23-完整授权生命周期状态机)
  - [2.4 `bbolt` 存储结构设计](#24-bbolt-存储结构设计wsbridgedb)
  - [2.5 Grant 权限计算规则](#25-grant-权限计算规则)
- [3. MCP 协议集成与工作区沙盒](#3-mcp-协议集成与工作区沙盒)
  - [3.1 Streamable HTTP 与鉴权上下文传递](#31-streamable-http-与鉴权上下文传递)
  - [3.2 工作区沙盒（`internal/ws`）](#32-工作区沙盒internalws)
  - [3.3 搜索隔离（`search_code` 双重校验）](#33-搜索隔离search_code-双重校验)
  - [3.4 原子写入、换行符保护与写前快照](#34-原子写入换行符保护与写前快照)
- [4. 部署架构、隧道选型与安全模型](#4-部署架构隧道选型与安全模型)
  - [4.1 公网隧道拓扑与稳定性要求](#41-公网隧道拓扑与稳定性要求)
  - [4.2 威胁模型与纵深防御矩阵](#42-威胁模型与纵深防御矩阵)
  - [4.3 自检诊断（`wsbridge doctor`）](#43-自检诊断wsbridge-doctor)
  - [4.4 审计日志规范](#44-审计日志规范auditjsonl)

---

## 1. 系统总体架构

### 1.1 背景与设计目标

网页端与桌面端 AI 助手（ChatGPT、Gemini、Claude）支持通过远程 MCP（Model Context Protocol）连接器调用外部工具，但官方托管连接器普遍要求 MCP 服务暴露在公网 HTTPS 地址上，且直接将本机文件系统暴露给云端模型存在严重的数据泄露与误操作风险。

`wsbridge` 的核心目标是提供一座**零外部依赖、默认最小权限、单进程运行**的本地安全桥梁：

1. **单静态二进制交付**：基于 Go ≥ 1.25 编译（`CGO_ENABLED=0`），无 C 依赖、无外部数据库进程、无外接 IdP，在 Windows、macOS、Linux 上拥有完全一致的行为。
2. **单端点统一接入**：对外仅暴露一个符合 MCP 规范的 Streamable HTTP 端点（`/mcp`），内建完整的 OAuth 2.1 授权服务（`/oauth/*` 与 `/.well-known/*`），使 ChatGPT、Gemini、Claude 均可直接通过自定义连接器完成"添加 URL → 浏览器授权 → 调用工具"闭环。
3. **动态工作区跟随与连接级权限（授权即 Grant）**：`wsbridge init` 仅配置公网 `public_url`、隧道与管理员口令，不再在全局配置写死工作区与权限；工作区默认跟随启动目录（`wsbridge serve [dir]`）并支持 `wsbridge use [dir]` 实时热切换不断连。连接的最大权限统一在浏览器同意页选择（默认全开 `check`，若本地显式配置了更低 `max_perm` 则取最小值），需要变更权限只需断开重连。
4. **小而稳的受限工具集**：仅提供读、搜、改、内置项目检查等不超过 8 个工具，**坚决不提供任意 shell 执行或通用网络请求工具**；所有写与检查工具均声明 `destructiveHint: true` 触发宿主确认。

### 1.2 明确的非目标（Non-Goals）

- **多用户 SaaS 托管**：仅面向单机单用户（本机管理员通过统一口令授权）。
- **云端文件中转存储**：所有文件读写均在本地工作区直接完成，不上传至任何第三方存储。
- **桌面 GUI（v1 不做）**：v1 仅提供 CLI 与浏览器端 OAuth 同意页；v2 可考虑终端本机确认模式。
- **任意命令执行**：`run_check` 仅允许执行编译期内建的固定项目检查命令集合（覆盖 Git / Go / Node / Python `uv`/`pip`/`pytest`/`ruff`/`mypy` / Rust），默认全部开放。

### 1.3 三平台协议交集约束

三大平台对自定义远程 MCP 连接器的支持细节各异（各平台接入路径、坑点与实测记录详见 `docs/reference.md`），系统架构严格取三者的最大公约数：

| 维度 | ChatGPT (Developer Mode) | Gemini (Spark Custom App) | Claude (Web / Desktop / Mobile) | `wsbridge` 架构决策 |
| :--- | :--- | :--- | :--- | :--- |
| **MCP 传输** | Streamable HTTP | Streamable HTTP | Streamable HTTP | 仅实现 Streamable HTTP（`/mcp`） |
| **资源发现** | RFC 9728 (PRM) | RFC 9728 (PRM) | RFC 9728 (PRM) | 返回 `401` + `WWW-Authenticate: Bearer resource_metadata=...` |
| **元数据发现** | RFC 8414 / OIDC | RFC 8414 | RFC 8414 | 同时暴露 `/.well-known/oauth-authorization-server` 与 `openid-configuration` 别名 |
| **客户端注册** | 偏好 CIMD，支持 DCR | 依赖 RFC 7591 DCR | 支持 DCR / CIMD / 预注册 | **v1 以 DCR 为主**，元数据预留 CIMD 字段，v2 实现 CIMD |
| **授权安全** | PKCE S256 + `resource` | PKCE S256 | PKCE S256 + `resource` | 强制要求 PKCE `S256`；校验 RFC 8707 `resource` |
| **会话保持** | 未带 `offline_access` 易过期 | 标准 OAuth | 标准 OAuth | **服务端始终签发 `refresh_token`** 并支持轮换 |
| **重定向敏感度** | 常规 | 严格校验回调参数 | 跨主机重定向会丢 `Authorization` 头 | **全站 MCP 路径零重定向**（显式注册 `/mcp` 与 `/mcp/`） |

### 1.4 系统逻辑架构与请求数据流

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

### 1.5 关键架构决策记录（ADR）

#### ADR-01：内置轻量 OAuth 2.1 服务，拒绝外接 IdP
- **背景**：Auth0、Keycloak 或自建 Zitadel/Ory Hydra 部署复杂度远超工具本身，且无法原生表达"选定本地工作区 + 读写权限等级"的授权语义。
- **决策**：使用标准库 + `bbolt` + `golang.org/x/crypto/argon2` 自研约 800 行内置 OAuth 2.1 授权服务。
- **收益**：用户只需执行 `wsbridge init` 与 `wsbridge passwd` 即可拥有完整 OAuth 能力，零外部运维成本。

#### ADR-02：不透明随机令牌 + SHA-256 哈希落盘
- **背景**：JWT 令牌在签发后难以即时撤销，且需要管理非对称签名私钥轮换。
- **决策**：`access_token` 与 `refresh_token` 均生成 32 字节密码学安全随机串（Base64URL 编码），`bbolt` 数据库中仅存储其 `SHA-256` 摘要。
- **收益**：支持通过 `wsbridge grants revoke` 毫秒级吊销指定会话；即使磁盘上的 `bbolt` 文件意外泄露，攻击者也无法还原出可用令牌。

#### ADR-03：纯文本工具响应（TextContent Only）
- **背景**：不同网页端 AI 客户端对 MCP `structuredContent` 的解析支持程度不一，部分版本会忽略或报错。
- **决策**：所有工具均返回人类与大模型均易读的结构化纯文本（`mcp.TextContent`），包含清晰的行号、文件路径、SHA-256 摘要或统一 Diff 片段。

#### ADR-04：利用 Go 1.25 `os.Root` 构建目录沙盒
- **背景**：传统的基于 `filepath.Clean` + `strings.HasPrefix` 的路径检查极易受到 TOCTOU（检查时间与使用时间差）符号链接攻击。
- **决策**：采用 Go 1.25 完善的 `os.OpenRoot` API（支持 `Root.Open`、`Root.ReadFile`、`Root.WriteFile`、`Root.Rename`、`Root.Stat` 等），由操作系统底层文件描述符机制（如 `openat` + `RESOLVE_BENEATH`）阻断一切逃逸。

---

## 2. 内置 OAuth 2.1 与 Grant 权限模型

> 各 HTTP 端点的完整请求/响应报文样例见 `docs/reference.md` 第 1 节。

### 2.1 核心概念模型

`wsbridge` 将标准 OAuth 2.1 授权流程与本地工作区访问控制深度融合，核心实体关系如下：

```text
[OAuth Client (DCR 注册)] 1 ──── * [Grant (用户授权实例)] 1 ──── * [Token (Access / Refresh)]
                                        │
                                        ├── 绑定 issuer (public_url)
                                        ├── 绑定 allowed_workspaces: map[name]Permission
                                        ├── 绑定 expires_at (授权总有效期)
                                        └── 绑定 revoked (是否已吊销)
```

### 2.2 Issuer 强绑定原则

- `issuer` 严格等于配置文件中的 `public_url`（去除末尾斜杠，例如 `https://my-box.tail1234.ts.net`）。
- 所有元数据端点、授权端点、令牌端点及 `resource`（`issuer + "/mcp"`）均由该 `issuer` 派生。
- **变更失效机制**：启动时校验 `bbolt` 中记录的 `system_meta.issuer` 是否与当前配置的 `public_url` 一致。若发生变更：
  1. 自动将旧 `issuer` 下所有历史 `Grant` 与 `Token` 标记为失效（或清空旧授权表）；
  2. 更新 `system_meta.issuer` 为新值；
  3. 在启动日志输出醒目 `WARN` 提示，告知用户需在 AI 平台重新连接。

### 2.3 完整授权生命周期状态机

#### 阶段一：资源发现与动态客户端注册（DCR）
1. AI 平台首次访问 `POST /mcp`（无令牌）→ 收到 `401 Unauthorized` 及响应头：
   `WWW-Authenticate: Bearer resource_metadata="https://<public_url>/.well-known/oauth-protected-resource/mcp"`
2. 平台请求 `GET /.well-known/oauth-protected-resource/mcp`（RFC 9728），获取 `authorization_servers: ["https://<public_url>"]`。
3. 平台请求 `GET /.well-known/oauth-authorization-server`（RFC 8414），获取 `registration_endpoint`、`authorization_endpoint`、`token_endpoint` 等元数据。
4. 平台调用 `POST /oauth/register`（RFC 7591）：
   - 校验 `token_endpoint_auth_method` 必须为 `"none"`（若省略则默认为 `"none"`）；
   - 校验 `redirect_uris` 非空且数量 ≤ 10；
   - 逐条校验 `redirect_uri`：协议必须为 `https`（回环地址 `localhost` / `127.0.0.1` / `[::1]` 允许 `http`），且 Host 必须命中白名单；
   - 若总数已达 `200` 上限，先清理超过 24 小时未产生任何有效 Grant 的僵尸 Client；若仍满则返回 `429` 或 `400`；
   - 生成随机 `client_id`（前缀 `wsb_cli_`）写入 `bbolt` 的 `clients` bucket，返回 `201 Created`。

#### 阶段二：用户同意页与授权码签发
1. 平台引导用户浏览器跳转至 `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...&resource=...&scope=...`。
2. 服务端执行前置参数校验（**任何一项失败均直接渲染错误页，绝不重定向至未验证的 `redirect_uri`**）：
   - `client_id` 必须存在于 `bbolt`；
   - `redirect_uri` 必须与该 Client 注册列表中的某一项**字节级完全一致**；
   - `response_type` 必须为 `"code"`；
   - `code_challenge_method` 必须为 `"S256"`，且 `code_challenge` 长度合法（43–128 字符 Base64URL）；
   - 若携带 `resource` 参数，其值必须严格等于 `public_url + "/mcp"`（否则返回 `invalid_target`）。
3. 服务端生成一次性 CSRF Token（写入内存或签名 Cookie，绑定当前表单会话），渲染 `consent.html`。
4. 用户在浏览器确认连接权限级别（默认全开 `check`）、授权有效期（默认 30 天）并提交本机管理员口令（`POST /oauth/authorize`）：
   - 校验防暴力破解锁定状态：连续口令错误达 **5 次**，全局锁定授权提交 **5 分钟**（返回 HTTP 429 与剩余秒数）；
   - 校验 CSRF Token；
   - 使用 `argon2.IDKey` 对比口令哈希；
   - 默认签发动态通配工作区授权（`workspaces: {"*": perm}`），使连接自动跟随本机当前活跃工作区（兼容历史显式指定工作区名的 Grant）；
   - 创建 `Grant` 持久化至 `bbolt`；将对应 `client_id` 标记为"已激活"（免受 24h 僵尸清理）；
   - 生成 **32 字节密码学随机授权码**（Base64URL 编码），存入**纯内存映射表**（不落盘），TTL = **60 秒**；
   - 返回 `302 Found` 重定向至 `redirect_uri?code=<CODE>&state=<STATE>&iss=<URL_ENCODED_ISSUER>`（遵循 RFC 9207）。

#### 阶段三：令牌换取与刷新轮换（含 30s 宽限期）
1. 平台后端调用 `POST /oauth/token`（`grant_type=authorization_code`）：
   - 原子取出并删除内存中的授权码记录；
   - **重放检测**：若该 `code` 已被标记为 `used`（在保留的 5 分钟已用黑名单窗口内再次出现），立即判定为重放攻击，**级联吊销该 `code` 此前签发的所有 Token 与对应 Grant**，返回 `400 invalid_grant`；
   - 校验 `client_id`、`redirect_uri` 与授权时完全一致；
   - 校验 `resource`（若提供）等于 `public_url + "/mcp"`；
   - 计算 `BASE64URL(SHA256(code_verifier)) == code_challenge`（常量时间比较 `subtle.ConstantTimeCompare`）；
   - 签发 `access_token`（TTL = **1 小时**）与 `refresh_token`（TTL = **30 天**），均生成 32 字节随机串，仅将 `SHA-256` 哈希存入 `bbolt` 的 `tokens` bucket；
   - **无论请求是否包含 `offline_access`，响应中始终返回 `refresh_token`**。
2. 平台后续调用 `POST /oauth/token`（`grant_type=refresh_token`）：
   - 计算传入 `refresh_token` 的 SHA-256 哈希并在 `bbolt` 中检索；
   - 检查关联 `Grant` 是否未过期且未被吊销；
   - **正常首次轮换**（`rotated_at` 为零值）：
     - 生成新一对 `(new_access_token, new_refresh_token)` 写入 `bbolt`；
     - 将旧 `refresh_token` 记录标记为 `rotated_at = now`，并记录 `replaced_by_access_hash` 与 `replaced_by_refresh_hash`（或短期内存缓存明文对 30 秒，仅用于应对网络抖动导致的并发重试）；
     - 立即使旧 `access_token` 失效，返回新令牌对。
   - **宽限期内并发重复刷新**（`now - rotated_at <= 30s`）：
     - 视为同一客户端并发请求竞态，不报错、不吊销，幂等返回该次轮换生成的同一对新令牌。
   - **宽限期外重放刷新**（`now - rotated_at > 30s`）：
     - 判定为令牌泄露重放，**立即吊销整个 `Grant` 及其名下所有令牌**，返回 `400 invalid_grant`。

### 2.4 `bbolt` 存储结构设计（`wsbridge.db`）

数据库文件位于 `<data_dir>/wsbridge.db`（文件权限 `0600`），按以下 Bucket 划分：

| Bucket 名称 | Key | Value (JSON 编码) | 说明 |
| :--- | :--- | :--- | :--- |
| `meta` | `"schema_version"`, `"issuer"`, `"admin_pass_hash"` | 字符串 / 字节 | 存储 Schema 版本、当前 `public_url`、argon2id 口令哈希 |
| `clients` | `client_id` (`wsb_cli_...`) | `ClientRecord` | `client_name`, `redirect_uris`, `application_type`, `created_at`, `activated` |
| `grants` | `grant_id` (`wsb_grt_...`) | `GrantRecord` | `client_id`, `client_name`, `scopes`, `workspaces` (权限映射), `created_at`, `expires_at`, `revoked` |
| `tokens` | `token_sha256_hex` | `TokenRecord` | `token_type` (`access`/`refresh`), `grant_id`, `client_id`, `resource`, `expires_at`, `rotated_at`, `revoked` |
| `audit_index` | 保留 | — | 审计日志主存为 JSONL 文件，不膨胀 `bbolt` |

**后台定期清理任务（GC Goroutine）**

服务启动后每 **10 分钟**运行一次后台清理事务：

1. 删除 `clients` 中 `activated == false` 且 `now - created_at > 24h` 的未完成注册客户端；
2. 删除 `tokens` 中 `expires_at < now` 且非宽限期内的过期令牌记录；
3. 标记 `grants` 中 `expires_at < now` 的授权为已过期（保留记录供 `grants list` 审计查看，支持 `grants prune` 物理清理）。

### 2.5 Grant 权限计算规则

权限严格遵循**全序集**：

```text
none (0) < read (1) < write (2) < check (3)
```

- 高级别权限自动包含低级别权限（例如 `check` 包含 `write` 与 `read`；`write` 包含 `read`）。
- 单次工具调用时的**有效权限（Effective Permission）**计算公式为：
  - 本地全局配置默认不设限制（等同 `check`）；如显式配置了更低的全局 `max_perm`、工作区 `max_perm` 或启动参数 `--max-perm`，则按两者最小值收敛：

  ```text
  EffectivePerm(w) = min(LocalMaxPerm(w), GrantPerm)
  ```

- 当 `Grant` 包含通配键 `"*"` 时，自动作用于服务端当前活跃的所有工作区（随 `wsbridge serve [dir]` 或 `wsbridge use [dir]` 实时变化，无需重连 OAuth）；如需更改连接权限，断开连接重新授权即可。
- 若当前无活跃工作区或 `EffectivePerm(w) < Tool.RequiredPerm`，则立即拒绝工具调用并返回清晰的权限或工作区提示。

---

## 3. MCP 协议集成与工作区沙盒

### 3.1 Streamable HTTP 与鉴权上下文传递

**SDK 配置要求**

使用 `github.com/modelcontextprotocol/go-sdk` 暴露 MCP 端点时，必须遵守以下配置：

- **关闭 Host 头校验**：设置 `DisableLocalhostProtection: true`。原因：云端平台经由 Tailscale Funnel / Cloudflare Tunnel / ngrok 访问本地时，HTTP 请求的 `Host` 头为公网域名（如 `my-box.tail1234.ts.net`），若开启 SDK 默认的 localhost 保护会直接返回 `403 Forbidden`。
- **传输端点双注册**：`/mcp` 与 `/mcp/` 必须分别显式注册到同一个 `mcp.StreamableHTTPHandler` 实例，彻底消除 `ServeMux` 的 301 重定向。
- **Bearer 鉴权包装器**：在进入 `StreamableHTTPHandler` 之前，由 `internal/mcpsrv` 的鉴权中间件执行：
  1. 提取 `Authorization: Bearer <token>`（缺失或格式错误返回 `401` + `WWW-Authenticate` 头）；
  2. 计算 `SHA-256(token)` 并查询 `bbolt`：验证令牌存在、类型为 `access`、未过期、未吊销；
  3. 校验令牌绑定的 `resource == public_url + "/mcp"`；
  4. 校验关联的 `Grant` 未过期且未吊销；
  5. 检查令牌级限流器（每令牌每分钟最多 120 次请求，超限返回 `429 Too Many Requests` + `Retry-After`）；
  6. 使用 SDK 的 `auth` 包将包含 `GrantID` 与 `ClientID` 的 `*auth.TokenInfo` 注入 `r.Context()`，供工具 Handler 通过请求的 `Extra.TokenInfo` 提取。

> **实现注意**：编码前务必检查 `go.mod` 锁定的 `go-sdk` 版本的 `mcp` 与 `auth` 包源码，确认 `StreamableHTTPHandler` 与 `TokenInfo` 的精确签名，严禁凭旧版本记忆编写。

### 3.2 工作区沙盒（`internal/ws`）

**Go 1.25 `os.Root` 句柄管理**
- 服务启动时为配置文件中的每个 `[[workspace]]` 打开一个 `*os.Root`（`os.OpenRoot(ws.Path)`），并在服务关闭时统一 `Close()`。
- 所有目录遍历、文件读取、文件写入、重命名与状态检查**必须且只能**通过对应工作区的 `*os.Root` 方法执行（`Root.Open`、`Root.ReadFile`、`Root.WriteFile`、`Root.Stat`、`Root.Remove`、`Root.Rename`），严禁拼接宿主机绝对路径后调用全局 `os.Open` / `os.ReadFile`。

**路径规范化与跨平台逃逸防御**

所有外部传入的 `path` 参数（默认为空字符串 `""` 或 `"."` 表示工作区根目录）在进入 `os.Root` 前必须经过 `ws.SanitizeRelPath(raw string)` 严格清洗：

1. **统一分隔符**：将 `\` 替换为 `/`；拒绝包含空字节 `\x00` 的路径。
2. **禁止绝对路径与盘符**：拒绝以 `/` 开头的路径；在所有平台（不仅限 Windows，防止跨平台配置混淆）拒绝包含冒号 `:` 的路径（同时阻断 Windows 盘符 `C:` 与 **NTFS 备用数据流 ADS** 如 `file.txt:Zone.Identifier`）。
3. **禁止父级穿越**：按 `/` 分割路径段，若任一段为 `".."`，直接拒绝。
4. **Windows 保留设备名拦截**：提取每个路径段去除扩展名后的基名并转大写，若命中 `CON`、`PRN`、`AUX`、`NUL`、`COM1`–`COM9`、`LPT1`–`LPT9`，直接拒绝。
5. **符号链接防御**：依赖 `os.Root` 底层阻断跳出根目录的符号链接；工具自身不提供创建符号链接的能力；遍历目录时跳过符号链接条目（`d.Type()&fs.ModeSymlink != 0`）。

**敏感文件默认屏蔽名单（Denylist）**

路径的任意层级目录名或文件名命中以下规则时，视为不可见且不可读写（列目录跳过，直接访问返回权限/不存在错误）：

- **默认内置规则**：
  - 目录/前缀：`.git`、`.ssh`、`.aws`
  - 环境与凭证文件：`.env`、`.env.*`、`.npmrc`、`.netrc`
  - 密钥与证书：`*.pem`、`*.key`、`*.p12`、`*.pfx`、`id_rsa`、`id_rsa.*`、`id_ed25519`、`id_ed25519.*`、`*.kdbx`
- **配置追加规则**：支持通过工作区或全局配置 `deny_patterns` 追加自定义 glob 规则。
- **不可覆盖红线**：`.git` 与 `.ssh` 为硬编码永久屏蔽项，任何配置均不可放行。

### 3.3 搜索隔离（`search_code` 双重校验）

`search_code` 采用 **`rg`（ripgrep）优先、纯 Go 并发遍历回退**策略：

1. **使用 `rg` 时**：
   - 工作目录固定为工作区路径，不跟随符号链接（默认不传 `-L`）；
   - 通过 `--glob` 参数排除默认重目录（`!node_modules/**`、`!dist/**`、`!build/**`、`!target/**`、`!__pycache__/**`、`!.venv/**`）及所有敏感名单 glob；
   - 设置 `--max-filesize 2M` 与 `20s` 上下文超时。
2. **Go 侧二次沙盒过滤（强制）**：
   - 由于外部 `rg` 进程不受 `os.Root` 文件描述符保护，Go 侧解析 `rg` 输出的每一条 `path:line:text` 后，**必须**再次调用 `ws.SanitizeRelPath` 与 `ws.IsDeniedPath` 进行校验，并确认路径未逃逸工作区，不合格条目直接丢弃。
3. **纯 Go 回退实现**：
   - 当宿主机未安装 `rg` 时，基于 `os.Root` 递归遍历文件，跳过二进制文件（前 512 字节含 `\x00` 或非有效 UTF-8 比例过高）与超 2MB 文件，逐行匹配正则表达式或字面量。

### 3.4 原子写入、换行符保护与写前快照

所有修改磁盘的工具（`edit_file`、`write_file`）均通过 `ws.AtomicWrite` 执行：

1. **文件大小上限**：单文件读取与写入上限均为 **2MB**（2,097,152 字节）。
2. **换行符与 BOM 检测**：
   - 读取原文件时检测是否存在 UTF-8 BOM（`\xEF\xBB\xBF`），写入时原样保留；
   - 扫描文件换行风格：若同时包含 `\r\n`（CRLF）与独立 `\n`（LF），判定为**混合换行符**，直接拒绝修改并返回提示（要求用户先统一文件换行格式，避免整文件 diff 污染）；
   - 若原文件为 CRLF，自动将编辑内容中的换行规范化为 CRLF 后再落盘。
3. **写前外部快照（Snapshot）**：
   - 若目标文件已存在，写入前先将其完整内容与权限复制至工作区外部目录：

     ```text
     <data_dir>/snapshots/<grant_id>/<YYYYMMDD-HHMMSS.mmm>/<workspace>/<rel_path>
     ```

   - 自动修剪该 `grant_id` 下的历史快照，仅保留最近 **20 份**（可通过配置 `max_snapshots_per_grant` 调整）。
4. **同目录原子重命名**：
   - 在目标文件所在的同一子目录内通过 `Root` 创建临时文件（命名如 `.wsbridge-tmp-<random>`），写入全部字节并 `Sync()`、`Close()`，继承原文件权限（新建文件默认 `0644`），最后调用 `Root.Rename` 原子替换目标文件；异常时清理临时文件。

---

## 4. 部署架构、隧道选型与安全模型

### 4.1 公网隧道拓扑与稳定性要求

由于 ChatGPT、Gemini、Claude 的工具调用均由**云端服务器**发起（而非用户本地浏览器直接请求 `127.0.0.1`），`wsbridge` 必须通过 HTTPS 反向隧道暴露至公网。

**公网 URL 稳定性铁律**

- `issuer`、DCR 注册的 `client_id`、用户签发的 `Grant` 以及 Token 均与 `public_url` 强绑定。
- **严禁在日常使用中使用随机临时域名**（如 Cloudflare Quick Tunnel `*.trycloudflare.com`），因为每次重启隧道域名都会改变，导致所有已绑定的 AI 平台连接器全部失效。

**推荐隧道方案对比**

| 方案 | 域名特征 | 配置要点 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **Tailscale Funnel**（首选） | 固定 `https://<node>.<tailnet>.ts.net` | `tailscale funnel --bg 8787`；零公网 IP 要求，自动签发 Let's Encrypt 证书 | 个人开发机、家庭服务器（Linux/macOS/Windows） |
| **Cloudflare Named Tunnel** | 自有二级域名 `https://ws.example.com` | `cloudflared tunnel run` 指向 `http://127.0.0.1:8787`；关闭任何强制重定向页面规则 | 已有 Cloudflare 托管域名的用户 |
| **ngrok 静态域名** | 免费/付费固定 `*.ngrok-free.app` | `ngrok http --domain=<static-domain> 8787` | 快速跨网络验证 |

> **关键配置提醒**：无论使用何种隧道，务必确保隧道层**不会对 `/.well-known/*` 或 `/mcp` 返回 301/302 重定向（如 HTTP→HTTPS 跳转或末尾斜杠补全）**，否则 Claude 云端运行时会丢弃 `Authorization` 头。

### 4.2 威胁模型与纵深防御矩阵

| 威胁类别 | 攻击向量 | 防御机制 |
| :--- | :--- | :--- |
| **公网扫描与 DoS** | 恶意爬虫枚举端点或发送超大请求体耗尽内存 | 1. 进程默认仅监听 `127.0.0.1:8787`；<br>2. 除元数据与 `/oauth/*` 外所有路径强制 Bearer 校验；<br>3. 全局请求体硬限制 `1MB`（`http.MaxBytesReader`）；<br>4. 读写与空闲超时（`ReadHeaderTimeout: 10s`, `IdleTimeout: 120s`）；<br>5. 每令牌限流 `120 req/min`。 |
| **授权页钓鱼与 CSRF** | 恶意网站诱导用户打开 `/oauth/authorize` 授权给恶意回调域 | 1. DCR 严格校验 `redirect_uri` Host 白名单；<br>2. 同意页醒目展示 Client 名称与回调域名；<br>3. 表单强制校验一次性 CSRF Token；<br>4. 设置 `X-Frame-Options: DENY` 与 `CSP: frame-ancestors 'none'` 防止点击劫持；<br>5. 口令采用 `argon2id` 校验，连续失败 5 次锁定 5 分钟。 |
| **令牌窃取与重放** | 日志泄露、网络抓包重放授权码或刷新令牌 | 1. 内存授权码仅存活 60s 且单次有效，重放即级联吊销全部关联令牌；<br>2. `access_token` 仅存活 1h；<br>3. `refresh_token` 每次轮换，超过 30s 宽限期重放立即吊销整个 Grant；<br>4. `bbolt` 仅存储 Token 的 SHA-256 哈希；<br>5. 全链路日志中间件自动脱敏敏感头与字段。 |
| **间接提示词注入 (IPI)** | 仓库 README 或代码注释中包含恶意指令，诱导 AI 读取密钥或外泄代码 | 1. **无 Shell、无网络工具**：AI 无法执行 `curl`/`bash` 主动外传；<br>2. **默认敏感名单**：`.env`、`.ssh`、`.git`、私钥在沙盒层彻底不可见；<br>3. **最小授权**：建议日常使用仅授予 `read` 权限，仅在需要修改代码时临时授权 `write`；<br>4. **安全告知**：文档明确提示若网页端同时开启网页浏览或其他连接器，存在组合外泄风险。 |
| **AI 误删改文件** | 模型幻觉导致大面积覆盖代码 | 1. `write_file` 覆盖已有文件强制校验 `expected_sha256`；<br>2. 所有写操作前自动备份快照至 `data_dir/snapshots/`；<br>3. `edit_file` 默认要求 `old_text` 唯一匹配；<br>4. `doctor` 检查工作区是否为 Git 仓库并给出建议。 |
| **高权限账号启动风险** | 用户误用 `sudo` 或 `Administrator/SYSTEM` 运行服务，扩大潜在风险 | 检测到 `uid == 0`（Unix）或 `SYSTEM` 账户（Windows）时**直接拒绝启动**，除非用户显式传入 `--i-know-what-i-am-doing`。 |

### 4.3 自检诊断（`wsbridge doctor`）

`wsbridge doctor` 通过读取本地配置并向 `public_url` 发起真实公网探测，验证端到端连通性与协议合规性：

**本地环境检查**

- 配置文件语法与工作区路径存在性；
- 口令哈希是否已初始化（`passwd`）；
- 各工作区是否包含 `.git`（未初始化 Git 时输出 `WARN` 建议）；
- 检查本机是否安装 `rg`（未安装时提示将使用纯 Go 搜索回退）。

**公网链路与零重定向检查**

使用配置了 `CheckRedirect: func(...) error { return http.ErrUseLastResponse }` 的 HTTP 客户端请求公网端点：

- `GET <public_url>/.well-known/oauth-protected-resource/mcp` → 必须返回 `200`，且 JSON 内 `resource == public_url + "/mcp"`；
- `GET <public_url>/.well-known/oauth-authorization-server` → 必须返回 `200`，且 `issuer == public_url`；
- `POST <public_url>/mcp`（无令牌）→ 必须返回 `401`（**严禁 301/302**），且 `WWW-Authenticate` 头包含正确的 `resource_metadata` URL；
- `POST <public_url>/mcp/`（无令牌）→ 必须同样返回 `401` 而非重定向；
- `POST <public_url>/oauth/register`（发送探测性 DCR 请求后立即清理或验证格式）→ 验证 DCR 端点公网可达。

### 4.4 审计日志规范（`audit.jsonl`）

所有安全敏感操作均以单行 JSON 追加写入 `<data_dir>/audit.jsonl`（权限 `0600`）：

```json
{
  "ts": "2026-11-13T10:15:30.123Z",
  "event": "tool_call",
  "grant_id": "wsb_grt_9f8a7b6c",
  "client_id": "wsb_cli_1a2b3c4d",
  "tool": "edit_file",
  "workspace": "myapp",
  "path": "internal/auth/handler.go",
  "status": "ok",
  "snapshot": "wsb_grt_9f8a7b6c/20261113-101530.120/myapp/internal/auth/handler.go",
  "duration_ms": 4
}
```

记录的事件类型（`event`）包括：`dcr_register`、`authorize_attempt`（含失败锁定记录，绝不含口令）、`token_issue`、`token_refresh`、`token_replay_revoked`、`grant_revoke`、`tool_call`、`sandbox_blocked`。