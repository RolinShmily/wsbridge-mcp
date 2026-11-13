# 01. Go 开发规范与工程红线

## 1. 编译器与依赖白名单硬约束

### 1.1 Go 版本与构建参数
- `go.mod` 必须声明 `go 1.25`（不可降级，因代码直接依赖 Go 1.25 新增的 `os.Root.ReadFile`、`os.Root.WriteFile` 与 `os.Root.Rename`）。
- 所有二进制构建默认使用：
  ```bash
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wsbridge ./cmd/wsbridge
  ```

### 1.2 依赖白名单（严格执行）
`go.mod` 的 `require` 列表中**仅允许出现以下 5 个直接依赖**：

1. `github.com/modelcontextprotocol/go-sdk` — MCP 服务端与 Streamable HTTP 传输
2. `go.etcd.io/bbolt` — 单文件嵌入式 KV 存储
3. `golang.org/x/crypto` — 仅允许导入 `golang.org/x/crypto/argon2`
4. `github.com/pelletier/go-toml/v2` — TOML 配置文件解析与序列化
5. `github.com/kardianos/service` — 仅允许在 `cmd/wsbridge` 的 `service` 子命令中导入

**明确禁止引入的库**：`cobra`、`viper`、`gin`、`chi`、`echo`、`fiber`、`zap`、`zerolog`、`testify`、`fosite`、`golang-jwt`。命令行参数解析一律使用标准库 `flag`；日志一律使用标准库 `log/slog`；测试断言一律使用标准库 `testing`。

---

## 2. HTTP 路由与中间件红线（防重定向丢头）

### 2.1 `http.ServeMux` 路由注册铁律
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

### 2.2 全链路日志脱敏规范
`internal/httpx` 的访问日志中间件与 `--debug-oauth` 调试输出必须通过统一的 `Redact` 函数过滤所有敏感字段：
- **HTTP 请求头脱敏**：`Authorization`、`Cookie`、`Proxy-Authorization` 一律替换为 `[REDACTED]`（若为 `Bearer <token>` 可保留前缀 `Bearer [REDACTED]`）。
- **表单与 JSON 字段脱敏**：`password`、`passphrase`、`code`、`access_token`、`refresh_token`、`code_verifier`、`csrf_token` 一律替换为 `[REDACTED]`。
- **URL Query 脱敏**：记录重定向目标或请求 URL 时，若包含 `code=` 参数，必须将其值替换为 `code=[REDACTED]` 后再写入日志。

---

## 3. 错误处理与可操作提示规范

### 3.1 领域错误分层
- **OAuth 错误**：严格按照 RFC 6749 / RFC 7591 / RFC 8707 返回标准 JSON 结构：
  ```json
  {"error": "invalid_grant", "error_description": "authorization code expired or already used"}
  ```
  HTTP `Content-Type` 必须为 `application/json; charset=utf-8`，并附带 `Cache-Control: no-store` 与 `Pragma: no-cache`。
- **MCP 工具错误**：业务逻辑错误（如文件不存在、匹配到多处、SHA-256 冲突、权限不足）**不要作为 JSON-RPC 协议层致命错误抛出**，而应返回 `CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "..."}}}`，并在文本中给出大模型可直接修正下一步调用的指令：
  - 示例 1（多处匹配）：`edit_file failed: old_text matched 3 occurrences in src/main.go (lines 12, 45, 89). Provide more surrounding context lines to uniquely identify the target block, or set replace_all=true.`
  - 示例 2（哈希不匹配）：`write_file failed: expected_sha256 mismatch (expected a1b2..., actual f9e8...). Call read_file first to inspect the latest file content and sha256.`

---

## 4. 并发与跨平台兼容性规范

1. **内存状态并发安全**：授权码内存池（`codeStore`）、CSRF 会话池、口令失败计数器、令牌限流器均必须使用 `sync.Mutex` 或 `sync.RWMutex` 保护，所有包测试必须通过 `go test -race ./...`。
2. **`bbolt` 事务粒度**：所有涉及令牌轮换（`refresh_token` 校验 + 标记 `rotated_at` + 写入新令牌）与授权码消费的操作必须在同一个 `db.Update` 读写事务中原子完成，消除并发竞态。
3. **跨平台路径与行尾**：禁止在业务代码中硬编码 `/` 作为系统路径拼接符（仅在工作区相对路径规范化逻辑内部统一使用 `/`）；生成配置与默认数据目录时使用 `os.UserConfigDir()`。
