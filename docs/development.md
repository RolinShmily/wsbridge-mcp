# wsbridge 开发规范、仓库结构与里程碑

> 本文档面向实现 Agent 与贡献者：包含 Go 编码红线、仓库模块契约、测试策略与 M0–M7 里程碑拆解。**动手写代码前必须通读本节全部内容。**

## 目录导航

- [1. Go 开发规范与工程红线](#1-go-开发规范与工程红线)
  - [1.1 编译器与依赖白名单硬约束](#11-编译器与依赖白名单硬约束)
  - [1.2 HTTP 路由与中间件红线（防重定向丢头）](#12-http-路由与中间件红线防重定向丢头)
  - [1.3 错误处理与可操作提示规范](#13-错误处理与可操作提示规范)
  - [1.4 并发与跨平台兼容性规范](#14-并发与跨平台兼容性规范)
- [2. 仓库结构与模块接口契约](#2-仓库结构与模块接口契约)
  - [2.1 标准仓库目录结构](#21-标准仓库目录结构)
  - [2.2 核心包职责与 Go 接口契约](#22-核心包职责与-go-接口契约)
- [3. 测试策略、E2E 规范与 CI 配置](#3-测试策略e2e-规范与-ci-配置)
  - [3.1 测试金字塔与覆盖率目标](#31-测试金字塔与覆盖率目标)
  - [3.2 必须编写的单元测试清单](#32-必须编写的单元测试清单)
  - [3.3 无平台依赖 E2E 全链路测试](#33-无平台依赖-e2e-全链路测试e2efull_flow_testgo)
  - [3.4 调试抓包与 CI 流水线](#34-调试抓包与-ci-流水线)
- [4. 里程碑拆解与 Agent 独立任务书（M0–M7）](#4-里程碑拆解与-agent-独立任务书m0m7)

---

## 1. Go 开发规范与工程红线

### 1.1 编译器与依赖白名单硬约束

**Go 版本与构建参数**

- `go.mod` 必须声明 `go 1.25`（不可降级，因代码直接依赖 Go 1.25 新增的 `os.Root.ReadFile`、`os.Root.WriteFile` 与 `os.Root.Rename`）。Go 工具链会把 `go 1.25` 规范化为补丁版本（如 `go 1.25.0`），这是允许且预期的。
- 所有二进制构建默认使用：

  ```bash
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wsbridge ./cmd/wsbridge
  ```

**依赖白名单（严格执行）**

`go.mod` 的 `require` 列表中**仅允许出现以下 5 个直接依赖**：

1. `github.com/modelcontextprotocol/go-sdk` — MCP 服务端与 Streamable HTTP 传输
2. `go.etcd.io/bbolt` — 单文件嵌入式 KV 存储
3. `golang.org/x/crypto` — 仅允许导入 `golang.org/x/crypto/argon2`
4. `github.com/pelletier/go-toml/v2` — TOML 配置文件解析与序列化
5. `github.com/kardianos/service` — 仅允许在 `cmd/wsbridge` 的 `service` 子命令中导入

**明确禁止引入的库**：`cobra`、`viper`、`gin`、`chi`、`echo`、`fiber`、`zap`、`zerolog`、`testify`、`fosite`、`golang-jwt`。命令行参数解析一律使用标准库 `flag`；日志一律使用标准库 `log/slog`；测试断言一律使用标准库 `testing`。

### 1.2 HTTP 路由与中间件红线（防重定向丢头）

**`http.ServeMux` 路由注册铁律**

Go 标准库 `http.ServeMux` 的内置规则是：若注册了 `/mcp/`（带尾部斜杠），当客户端请求 `/mcp`（无尾部斜杠）时，`ServeMux` 会自动返回 `301 Moved Permanently` 重定向到 `/mcp/`。

- **后果**：Claude 云端托管运行时遇到重定向时会剥离 `Authorization` 请求头，导致 MCP 连接永久 `401` 失败。
- **强制规范**：
  1. 必须同时显式注册精确路径：

     ```go
     mux.Handle("POST /mcp", mcpProtectedHandler)
     mux.Handle("GET /mcp", mcpProtectedHandler)
     mux.Handle("DELETE /mcp", mcpProtectedHandler)
     mux.Handle("POST /mcp/", mcpProtectedHandler)
     mux.Handle("GET /mcp/", mcpProtectedHandler)
     mux.Handle("DELETE /mcp/", mcpProtectedHandler)
     ```

  2. 编写专门的单元测试，对 `/mcp` 与 `/mcp/` 发送请求并断言 `resp.StatusCode < 300 || resp.StatusCode >= 400`（绝不出现任何 `3xx`）。

**全链路日志脱敏规范**

`internal/httpx` 的访问日志中间件与 `--debug-oauth` 调试输出必须通过统一的 `Redact` 函数过滤所有敏感字段：

- **HTTP 请求头脱敏**：`Authorization`、`Cookie`、`Proxy-Authorization` 一律替换为 `[REDACTED]`（若为 `Bearer <token>` 可保留前缀 `Bearer [REDACTED]`）。
- **表单与 JSON 字段脱敏**：`password`、`passphrase`、`code`、`access_token`、`refresh_token`、`code_verifier`、`csrf_token` 一律替换为 `[REDACTED]`。
- **URL Query 脱敏**：记录重定向目标或请求 URL 时，若包含 `code=` 参数，必须将其值替换为 `code=[REDACTED]` 后再写入日志。

### 1.3 错误处理与可操作提示规范

**领域错误分层**

- **OAuth 错误**：严格按照 RFC 6749 / RFC 7591 / RFC 8707 返回标准 JSON 结构：

  ```json
  {"error": "invalid_grant", "error_description": "authorization code expired or already used"}
  ```

  HTTP `Content-Type` 必须为 `application/json; charset=utf-8`，并附带 `Cache-Control: no-store` 与 `Pragma: no-cache`。
- **MCP 工具错误**：业务逻辑错误（如文件不存在、匹配到多处、SHA-256 冲突、权限不足）**不要作为 JSON-RPC 协议层致命错误抛出**，而应返回 `CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "..."}}}`，并在文本中给出大模型可直接修正下一步调用的指令：
  - 示例 1（多处匹配）：

    ```text
    edit_file failed: old_text matched 3 occurrences in src/main.go (lines 12, 45, 89). Provide more surrounding context lines to uniquely identify the target block, or set replace_all=true.
    ```

  - 示例 2（哈希不匹配）：

    ```text
    write_file failed: expected_sha256 mismatch (expected a1b2..., actual f9e8...). Call read_file first to inspect the latest file content and sha256.
    ```

### 1.4 并发与跨平台兼容性规范

1. **内存状态并发安全**：授权码内存池（`codeStore`）、CSRF 会话池、口令失败计数器、令牌限流器均必须使用 `sync.Mutex` 或 `sync.RWMutex` 保护，所有包测试必须通过 `go test -race ./...`。
2. **`bbolt` 事务粒度**：所有涉及令牌轮换（`refresh_token` 校验 + 标记 `rotated_at` + 写入新令牌）与授权码消费的操作必须在同一个 `db.Update` 读写事务中原子完成，消除并发竞态。
3. **跨平台路径与行尾**：禁止在业务代码中硬编码 `/` 作为系统路径拼接符（仅在工作区相对路径规范化逻辑内部统一使用 `/`）；生成配置与默认数据目录时使用 `os.UserConfigDir()`。

---

## 2. 仓库结构与模块接口契约

### 2.1 标准仓库目录结构

```text
wsbridge/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Linux / macOS / Windows 三平台 go test -race 与交叉编译
├── cmd/
│   └── wsbridge/
│       └── main.go                # CLI 入口: serve | init | passwd | grants | doctor | service
├── internal/
│   ├── config/
│   │   ├── config.go              # TOML 结构定义、默认值、校验与 Save/Load
│   │   └── config_test.go
│   ├── httpx/
│   │   ├── server.go              # http.Server 封装、全链路超时、1MB Body 限制、优雅关闭
│   │   ├── middleware.go          # 脱敏日志、--debug-oauth 输出、令牌桶限流、可选 --dev-cors
│   │   └── redact.go              # 请求头/URL/JSON/Form 敏感信息脱敏工具
│   ├── oauth/
│   │   ├── server.go              # OAuth HTTP 路由挂载 (/oauth/* 与 /.well-known/*)
│   │   ├── metadata.go            # RFC 9728 (PRM) & RFC 8414 (AS Metadata) 响应生成
│   │   ├── register.go            # RFC 7591 DCR 注册与 redirect_uri 白名单校验
│   │   ├── authorize.go           # GET/POST /oauth/authorize、CSRF、口令锁定与授权码签发
│   │   ├── token.go               # POST /oauth/token (authorization_code & refresh_token 轮换) & /revoke
│   │   ├── pkce.go                # PKCE S256 校验与常量时间比较
│   │   ├── store.go               # bbolt 持久化存储、30s 宽限期幂等轮换、级联吊销与后台 GC
│   │   ├── consent.html           # //go:embed 内嵌授权同意页单文件 HTML/CSS
│   │   └── oauth_test.go
│   ├── mcpsrv/
│   │   ├── server.go              # 构建 *mcp.Server、注册工具、StreamableHTTPHandler 封装
│   │   ├── auth_middleware.go     # Bearer 校验、401 WWW-Authenticate 头、TokenInfo 注入
│   │   └── authz.go               # Grant 权限校验辅助函数 (EffectivePerm)
│   ├── tools/
│   │   ├── register.go            # 统一注册全部 MCP 工具与 annotations
│   │   ├── workspaces.go          # list_workspaces
│   │   ├── tree.go                # get_file_tree
│   │   ├── search.go              # search_code (rg 优先 + Go 二次沙盒过滤 + 纯 Go 回退)
│   │   ├── read.go                # read_file (多段 ranges、行号、64KB 限制、sha256)
│   │   ├── edit.go                # edit_file (原子批量编辑、唯一性校验、unified diff)
│   │   ├── write.go               # write_file (新建 / expected_sha256 覆盖)
│   │   ├── check.go               # run_check (配置白名单命令、环境变量隔离)
│   │   └── tools_test.go
│   ├── ws/
│   │   ├── manager.go             # 管理多个工作区的 *os.Root 实例池
│   │   ├── path.go                # 路径清洗、Windows 保留字/ADS 拦截、敏感名单匹配
│   │   ├── atomic.go              # 换行符/BOM 检测、混合换行拒绝、写前外部快照与同目录原子 Rename
│   │   └── ws_test.go
│   ├── audit/
│   │   └── logger.go              # 并发安全的 JSONL 审计日志写入器
│   └── tunnel/
│       └── doctor.go              # 公网 URL 自检诊断逻辑
├── tests/
│   └── e2e/
│       └── full_flow_test.go      # 无平台依赖的完整 OAuth + MCP 端到端测试客户端
├── docs/                          # 四份单文件规格：architecture.md / development.md / reference.md / design.md
├── AGENTS.md
├── go.mod
├── go.sum
├── .goreleaser.yaml
└── README.md
```

### 2.2 核心包职责与 Go 接口契约

**`internal/ws`（工作区沙盒契约）**

```go
package ws

type Permission int

const (
    PermNone  Permission = 0
    PermRead  Permission = 1
    PermWrite Permission = 2
    PermCheck Permission = 3
)

// Workspace 提供绑定到单一 *os.Root 的安全文件操作能力
type Workspace interface {
    Name() string
    MaxPerm() Permission
    AllowedChecks() []string
    ReadFile(relPath string) (content []byte, sha256Hex string, err error)
    WriteFileAtomic(grantID, relPath string, data []byte, expectSHA256 string, createOnly bool) (newSHA256Hex string, snapshotRelPath string, err error)
    WalkTree(relPath string, maxDepth int, cursor string, limit int) (TreeResult, error)
    Search(ctx context.Context, opts SearchOptions) ([]SearchMatch, bool, error)
    RunCheck(ctx context.Context, checkName string) (output string, exitCode int, err error)
    Close() error
}
```

**`internal/oauth`（授权验证与 Grant 查询契约）**

`internal/mcpsrv` 通过以下接口与 `internal/oauth` 解耦：

```go
package oauth

type GrantPrincipal struct {
    GrantID    string
    ClientID   string
    ClientName string
    Workspaces map[string]ws.Permission // workspace_name -> granted permission
    ExpiresAt  time.Time
}

// TokenVerifier 由 Bearer 中间件调用，校验访问令牌并返回关联的 Grant 信息
type TokenVerifier interface {
    VerifyAccessToken(rawToken string, expectedResource string) (*GrantPrincipal, error)
}
```

**`internal/tools`（多工作区参数解析契约）**

所有针对特定工作区的工具（除 `list_workspaces` 外）均接收可选字段 `Workspace string` (`json:"workspace,omitempty"`)，由统一辅助函数 `ResolveWorkspace(principal *oauth.GrantPrincipal, mgr *ws.Manager, requestedWS string, requiredPerm ws.Permission)` 解析：

1. 若 `requestedWS == ""`：
   - 若 `len(principal.Workspaces) == 1`，自动选中该唯一授权工作区；
   - 若 `len(principal.Workspaces) > 1`，返回可操作工具错误：

     ```text
     multiple workspaces are authorized in this session; specify the 'workspace' parameter (available: ...)
     ```

   - 若 `len(principal.Workspaces) == 0`，返回无可用工作区错误。
2. 若 `requestedWS != ""`：
   - 检查 `requestedWS` 是否存在于 `principal.Workspaces`（不存在则返回未授权该工作区）；
   - 计算 `effective := min(wsInstance.MaxPerm(), grantedPerm)`；
   - 若 `effective < requiredPerm`，返回权限不足错误并指明当前有效权限与所需权限。

---

## 3. 测试策略、E2E 规范与 CI 配置

### 3.1 测试金字塔与覆盖率目标

`wsbridge` 直接处理公网 OAuth 认证与本地文件修改，核心安全边界必须有 100% 的单元测试覆盖，并通过端到端测试验证协议合规性。

### 3.2 必须编写的单元测试清单

**`internal/ws` 沙盒与原子写测试（`ws_test.go`）**
- **路径逃逸拦截**：`../secret.txt`、`a/../../b`、`/etc/passwd`、`C:\Windows\System32`、`file.txt:ads`、`CON`、`NUL.txt`、`COM1` 均必须返回沙盒违规错误。
- **符号链接防御**：在临时工作区内创建一个指向工作区外部文件的符号链接 `escape_link`，验证 `ReadFile`、`WalkTree`、`Search` 均无法读取外部文件内容。
- **敏感文件屏蔽**：验证 `.git/config`、`.env`、`.env.local`、`id_ed25519`、`cert.pem`、`.ssh/authorized_keys` 在列目录时被隐藏，直接读取时被拒绝。
- **换行符与 BOM 保持**：
  - 带 UTF-8 BOM + CRLF 的文件经 `WriteFileAtomic` 修改后，BOM 与 CRLF 均完整保留；
  - 包含混合换行符（既有 `\r\n` 又有孤立 `\n`）的文件写入时必须直接拒绝并返回明确提示。
- **写前快照与原子性**：验证覆盖写入后，`<data_dir>/snapshots/<grant_id>/...` 下生成了原始内容备份，且超过保留上限时自动清理最旧快照。

**`internal/oauth` 协议与安全测试（`oauth_test.go`）**
- **PKCE S256**：验证正确的 `code_verifier` 通过，错误的 `code_verifier` 或空值返回 `400 invalid_grant`。
- **Redirect URI 精确匹配与白名单**：
  - DCR 提交未在白名单的域名（如 `https://evil.example.com/cb`）返回 `400`；
  - DCR 提交非 HTTPS 的公网域名（`http://chatgpt.com/cb`）返回 `400`；
  - DCR 提交 `http://127.0.0.1:8080/cb` 允许通过；
  - 授权请求时 `redirect_uri` 与注册值哪怕仅差一个查询参数或尾部斜杠，也必须拒绝。
- **授权码生命周期与重放撤销**：
  - 超过 60s TTL 的授权码换取令牌失败；
  - 已成功换取令牌的授权码再次提交（重放）时，不仅返回 `400 invalid_grant`，且先前已签发的 `access_token` 与 `refresh_token` 必须同时被吊销。
- **Refresh Token 轮换与 30s 宽限期**：
  - 首次刷新返回新 `access_token` 与新 `refresh_token`，旧 `access_token` 立即失效；
  - 轮换后 **30 秒内**使用旧 `refresh_token` 再次请求，幂等返回同一对新令牌；
  - 轮换后 **超过 30 秒**（测试中可通过注入时钟 `clock func() time.Time` 模拟时间推进）再次使用旧 `refresh_token`，触发重放告警并吊销整个 Grant。
- **口令暴力破解锁定**：连续 5 次提交错误口令后，第 6 次（即使口令正确）在 5 分钟内必须返回 `429 Too Many Requests`。
- **零重定向路由断言**：对 `/mcp` 与 `/mcp/` 发送无令牌 `POST`/`GET`，断言 HTTP 状态码为 `401` 而非 `301`/`302`/`307`/`308`。

### 3.3 无平台依赖 E2E 全链路测试（`tests/e2e/full_flow_test.go`）

在 `tests/e2e` 包中启动一个绑定到 `httptest.Server`（模拟公网 HTTPS 入口）的完整 `wsbridge` 实例，使用纯 Go 编写自动化测试客户端依次执行：

1. 无令牌请求 `POST <server>/mcp` → 断言 `401`，解析 `WWW-Authenticate` 头提取 `resource_metadata` URL；
2. 请求 PRM URL → 断言 `resource == <server>/mcp`，提取 `authorization_servers[0]`；
3. 请求 `<as>/.well-known/oauth-authorization-server` → 校验所有必填字段及 `S256`、`offline_access`；
4. 请求 `POST /oauth/register`（提交 `http://127.0.0.1:19999/callback`）→ 获取 `client_id`；
5. 生成随机 `code_verifier` 与 `code_challenge`，访问 `GET /oauth/authorize` 提取页面中的 `csrf_token`，随后 `POST /oauth/authorize` 提交工作区选择、权限与测试口令（禁用自动跟随重定向，拦截 `302 Location` 提取 `code`、`state`、`iss`）；
6. 请求 `POST /oauth/token`（`authorization_code`）→ 获取 `access_token` 与 `refresh_token`；
7. 使用 `go-sdk` 的 MCP Streamable HTTP Client（携带 `Authorization: Bearer <access_token>`）连接 `<server>/mcp`：
   - 调用 `Initialize`；
   - 调用 `ListTools` 确认工具列表完整；
   - 依次调用 `list_workspaces`、`get_file_tree`、`write_file`（新建文件）、`read_file`、`edit_file`、`search_code`、`run_check`（`git_status`）并断言结果；
8. 测试 `POST /oauth/token`（`refresh_token`）轮换，使用新令牌再次调用 `read_file` 成功，使用旧 `access_token` 调用返回 `401`；
9. 执行 Grant 撤销后，使用新令牌调用返回 `401`。

### 3.4 调试抓包与 CI 流水线

**`--debug-oauth` 调试模式**

启动 `wsbridge serve --debug-oauth` 时，将完整的 OAuth 发现、DCR、授权、令牌交互的**方法、路径、脱敏后的请求/响应头、脱敏后的参数与状态码**输出至 `stderr`，专门用于定位 Gemini Spark 等平台在真实网络下的握手异常。

**GitHub Actions CI（`.github/workflows/ci.yml`）**
- **测试矩阵**：`ubuntu-latest`、`macos-latest`、`windows-latest`，Go 版本 `1.25.x`。
- **执行命令**：

  ```bash
  go vet ./...
  go test -race -count=1 ./...
  CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
  ```

---

## 4. 里程碑拆解与 Agent 独立任务书（M0–M7）

> 每个里程碑均可作为独立 Prompt 派发给 Coding Agent。完成每个阶段后，必须运行全量测试并通过验收标准方可进入下一阶段。

```text
M0 脚手架与三平台 CI
 └─▶ M1 工作区沙盒 (os.Root) 与 MCP 工具集 (无鉴权 dev 模式)
      └─▶ M2 内置 OAuth 2.1 授权服务 + Bearer 保护 + 同意页 + e2e 全链路
           ├─▶ M3 ChatGPT 真实平台接入与 Token 自动刷新实测
           ├─▶ M4 Gemini (Spark) 真实平台接入与 OAuth 回调实测
           └─▶ M5 Claude (Web/Desktop/Mobile) 真实平台接入与无重定向验证
                └─▶ M6 doctor 诊断、用户级 service、审计快照与 goreleaser 分发
                     └─▶ M7 (v2/v3) CIMD、终端本地确认、托管隧道与 search/fetch 兼容
```

### M0：工程脚手架、配置加载与 HTTP 基础网关

- **前置条件**：无（仓库初始化）。
- **实现范围**：
  1. 初始化 `go.mod`（`go 1.25`），严格遵守依赖白名单；
  2. 实现 `internal/config`：支持加载与生成默认 `config.toml`，校验 `public_url`、`listen`、`[[workspace]]` 路径与权限枚举；
  3. 实现 `internal/httpx`：封装 `http.Server`（超时、1MB 请求体限制、优雅退出）、全链路脱敏中间件（`redact.go`）、`--dev-cors` 中间件；
  4. 实现 `cmd/wsbridge/main.go` 子命令分发骨架（基于标准库 `flag`：`serve`、`init`、`passwd`、`grants`、`doctor`、`service`）及启动账号权限检测（阻止 root/SYSTEM 直接启动）；
  5. 配置 `.github/workflows/ci.yml`。
- **验收标准**：
  - Linux / macOS / Windows 三平台 CI 全部绿灯；
  - `CGO_ENABLED=0 go build ./cmd/wsbridge` 零警告通过；
  - `wsbridge init` 可正常生成示例配置文件。

### M1：工作区沙盒（`os.Root`）与 MCP 工具集（无鉴权 Dev 模式）

- **前置条件**：M0 完成。
- **实现范围**：
  1. 实现 `internal/ws`：基于 `os.OpenRoot` 的路径清洗、Windows 设备名/ADS 拦截、敏感文件屏蔽、写前外部快照、换行/BOM 检测与原子重命名；
  2. 实现 `internal/tools`：`list_workspaces`、`get_file_tree`、`search_code`（`rg` 优先 + 二次过滤 + 纯 Go 回退）、`read_file`、`edit_file`、`write_file`、`run_check`；
  3. 实现 `internal/mcpsrv` 基础挂载，在 `serve --dev-no-auth`（强制仅允许绑定 `127.0.0.1`）下暴露 `/mcp` 与 `/mcp/`。
- **验收标准**：
  - `internal/ws` 与 `internal/tools` 单元测试全绿（含 Windows 特殊路径与符号链接逃逸用例）；
  - 使用官方 `@modelcontextprotocol/inspector` 连接本地 `/mcp`，能完整列出并成功调用全部 7 个工具。

### M2：内置 OAuth 2.1 授权服务、同意页与 E2E 闭环

- **前置条件**：M1 完成。
- **实现范围**：
  1. 实现 `internal/oauth` 全部模块（`metadata.go`、`register.go`、`authorize.go`、`token.go`、`pkce.go`、`store.go`、`consent.html`）；
  2. 实现 `wsbridge passwd`（argon2id 口令设置）与 `wsbridge grants list / revoke / prune`；
  3. 在 `internal/mcpsrv` 启用强制 Bearer 鉴权中间件与 Grant 细粒度权限拦截，移除 `--dev-no-auth` 或严格限制其仅限单测；
  4. 实现 `internal/audit` JSONL 审计日志记录；
  5. 编写并运行 `tests/e2e/full_flow_test.go`。
- **验收标准**：
  - `e2e` 测试客户端完整跑通"401 → PRM → AS → DCR → 授权提交 → 换 Token → MCP 调用 → Refresh 轮换 → 撤销失效"全链路；
  - 授权码重放、PKCE 错误、Redirect URI 不匹配、口令连续错误 5 次锁定、`/mcp` 零重定向等负面测试用例全部通过。

### M3：ChatGPT 平台真实接入验收（优先级 1）

- **前置条件**：M2 完成，且本地已配置稳定 HTTPS 隧道（如 Tailscale Funnel）。
- **实现范围**：
  1. 在 ChatGPT 开启 Developer Mode，通过 Settings → Apps & Connectors 添加自定义连接器；
  2. 完成浏览器 OAuth 同意页授权；
  3. 在对话中测试调用 `list_workspaces`、`get_file_tree`、`read_file`、`edit_file`；
  4. 观察 `access_token` 过期（1 小时后）ChatGPT 是否自动使用 `refresh_token` 刷新成功；
  5. 执行 `wsbridge grants revoke` 后验证调用被拒绝。
- **验收标准 & 文档回写**：
  - 上述功能全部验证通过；
  - 将 ChatGPT 实际发送的 `client_id` 形态（CIMD URL 还是 DCR）、`redirect_uri`、`resource`、`scope` 及工具确认弹窗表现回写至 `docs/reference.md` 第 4 节。

### M4：Gemini（Spark 自定义应用）真实平台接入验收（优先级 2）

- **前置条件**：M2 完成；准备个人 Google 账号、界面语言设为英文、开启 Keep Activity。
- **实现范围**：
  1. 在 `gemini.google.com` → Settings → Connected Apps → Add a custom app 添加 `public_url + "/mcp"`；
  2. 开启 `wsbridge serve --debug-oauth` 观察完整 OAuth 握手过程并完成授权与只读工具调用；
  3. 若遇授权最后一步失败（"授权码已返回但 Google 未调用 token 端点"或 `Cannot Complete Request`），结合 `--debug-oauth` 日志与参考实现 `ghchinoy/spark-agent-tools` 逐项排查（issuer 一致性、元数据路径、302 响应参数 `iss`、`Content-Type` 等）并修复兼容问题。
- **验收标准 & 文档回写**：
  - 完成授权并成功调用只读工具，或准确定位平台侧限制；
  - 将实测抓包结论与解决方案回写至 `docs/reference.md` 第 4 节。

### M5：Claude（Web / Desktop / Mobile）真实平台接入验收（优先级 3）

- **前置条件**：M2 完成。
- **实现范围**：
  1. 在 Claude Settings → Connectors → Add custom connector 添加连接器并完成授权；
  2. 验证工具调用成功，确认 `/mcp` 全程无 301/302 重定向导致丢 `Authorization` 头；
  3. 验证重复重新连接时未激活 DCR client 自动清理机制生效；
  4. 在 Claude 移动端验证同一已连接连接器的工具调用可用性。
- **验收标准 & 文档回写**：
  - Web 与移动端均调用成功，结论回写至 `docs/reference.md` 第 4 节。

### M6：运维加固（`doctor` / `service`）与跨平台发布（`goreleaser`）

- **前置条件**：M3–M5 完成。
- **实现范围**：
  1. 完善 `internal/tunnel/doctor.go`（公网元数据探测、DCR 探测、`/mcp` 与 `/mcp/` 401 无重定向探测、Git 仓库检查）；
  2. 实现 `wsbridge service install / uninstall / start / stop / status`（基于 `kardianos/service`，严格用户级）；
  3. 编写 `.goreleaser.yaml` 支持交叉编译 `windows/amd64`、`darwin/arm64`、`darwin/amd64`、`linux/amd64`、`linux/arm64`；
  4. 完善面向最终用户的 `README.md`（含快速上手、隧道配置示例与提示词注入风险提示）。
- **验收标准**：
  - 三平台发布包构建成功；`doctor` 能准确识别并报告 URL 不一致、隧道返回 301 重定向、隧道未启动等常见故障。

### M7：可选增强特性（v2 / v3 规划）

按需拆分独立任务：

1. **CIMD 支持（v2）**：实现 Client ID Metadata Document 获取与缓存校验，并在 `/.well-known/oauth-authorization-server` 中将 `client_id_metadata_document_supported` 置为 `true`。
2. **本机终端确认模式（v2）**：支持在同意页点击后于运行 `wsbridge` 的终端交互确认（替代或叠加网页口令）。
3. **工具历史撤销 `undo_last_edit`（v2）**：暴露第 8 个工具，允许 AI 从最近一次外部快照恢复误改文件。
4. **ChatGPT 深度研究兼容工具 `search` / `fetch`（v2）**：为非 Developer Mode 场景提供兼容别名。
5. **托管隧道适配器（v2）与内嵌隧道（v3）**：托管 `cloudflared` / `tailscale` 子进程，或通过 Build Tag 内嵌 `tsnet` / `ngrok-go`。