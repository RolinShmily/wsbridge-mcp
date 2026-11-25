# AGENTS.md — wsbridge 实现执行总则

> 本文档为 Coding Agent（Claude Code / Codex / OpenCode / pi-coding-agent）的入口指引。所有实现必须严格遵循 `docs/` 目录下的规格说明。

## 1. 项目定位
`wsbridge` 是一个面向单用户的本地工作区安全桥接服务，以**单个静态 Go（≥1.25）二进制文件（`CGO_ENABLED=0`）**运行在 Windows / macOS / Linux 上。它通过内置的 OAuth 2.1 授权服务与 Streamable HTTP MCP 端点，使 **ChatGPT → Gemini → Claude** 网页端与客户端在最小权限（Grant）约束下安全读写与检查本机指定工作区。

## 2. 文档导航（必读顺序）
在编写任何业务代码前，请按以下顺序通读 `docs/` 下的 4 份单文件规格（`docs/README.md` 索引已废除，`docs/` 不再有子目录）：

1. **总览与系统架构**：`docs/architecture.md`
2. **开发红线与仓库/模块契约**：`docs/development.md`
3. **协议、工具、CLI 与配置接口契约**：`docs/reference.md`
4. **授权同意页前端规范**：`docs/design.md`

## 3. 不可逾越的工程红线
1. **Go 版本与静态编译**：`go.mod` 必须要求 Go ≥ 1.25（依赖 `os.Root.ReadFile` / `WriteFile` / `Rename`）。Go 工具链会把 `go 1.25` 规范化为补丁版本（如 `go 1.25.0`），这是允许且预期的；更高版本的 1.25.x 补丁同样可用。所有构建均需在 `CGO_ENABLED=0` 下通过。
2. **依赖白名单冻结**：仅允许引入以下 5 个外部依赖，其余一律使用 Go 标准库（严禁引入 `cobra`、`gin`、`chi`、`fosite` 等）：
   - `github.com/modelcontextprotocol/go-sdk`
   - `go.etcd.io/bbolt`
   - `golang.org/x/crypto`（仅用于 `argon2`）
   - `github.com/pelletier/go-toml/v2`
   - `github.com/kardianos/service`（仅用于 `service` 子命令）
3. **零重定向路由原则**：全站除 `/oauth/authorize` 授权回调 `302` 跳转至客户端 `redirect_uri` 外，**严禁产生任何 HTTP 301/302/307/308 重定向**。`/mcp` 与 `/mcp/` 必须分别显式注册，防止 Go `ServeMux` 自动 301 导致 Claude 云端运行时丢弃 `Authorization` 请求头。
4. **日志绝对脱敏**：用户口令、授权码（`code`）、访问令牌（`access_token`）、刷新令牌（`refresh_token`）、`Authorization` 请求头及 `code_verifier` 严禁出现在任何日志（含 `--debug-oauth`）与错误响应中。
5. **先测试后实现（TDD）**：每个里程碑（M0–M7）必须先编写单元测试或 `e2e` 集成测试，再编写实现代码；不确定的 `go-sdk` API 必须查阅当前锁定版本的源码与 `pkg.go.dev`，不得凭记忆编写。
