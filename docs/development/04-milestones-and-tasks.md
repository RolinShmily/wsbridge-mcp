# 04. 里程碑拆解与 Agent 独立任务书（M0–M7）

> 每个里程碑均可作为独立 Prompt 派发给 Coding Agent。完成每个阶段后，必须运行全量测试并通过验收标准方可进入下一阶段。

---

## M0：工程脚手架、配置加载与 HTTP 基础网关

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

---

## M1：工作区沙盒（`os.Root`）与 MCP 工具集（无鉴权 Dev 模式）

- **前置条件**：M0 完成。
- **实现范围**：
  1. 实现 `internal/ws`：基于 `os.OpenRoot` 的路径清洗、Windows 设备名/ADS 拦截、敏感文件屏蔽、写前外部快照、换行/BOM 检测与原子重命名；
  2. 实现 `internal/tools`：`list_workspaces`、`get_file_tree`、`search_code`（`rg` 优先 + 二次过滤 + 纯 Go 回退）、`read_file`、`edit_file`、`write_file`、`run_check`；
  3. 实现 `internal/mcpsrv` 基础挂载，在 `serve --dev-no-auth`（强制仅允许绑定 `127.0.0.1`）下暴露 `/mcp` 与 `/mcp/`。
- **验收标准**：
  - `internal/ws` 与 `internal/tools` 单元测试全绿（含 Windows 特殊路径与符号链接逃逸用例）；
  - 使用官方 `@modelcontextprotocol/inspector` 连接本地 `/mcp`，能完整列出并成功调用全部 7 个工具。

---

## M2：内置 OAuth 2.1 授权服务、同意页与 E2E 闭环

- **前置条件**：M1 完成。
- **实现范围**：
  1. 实现 `internal/oauth` 全部模块（`metadata.go`、`register.go`、`authorize.go`、`token.go`、`pkce.go`、`store.go`、`consent.html`）；
  2. 实现 `wsbridge passwd`（argon2id 口令设置）与 `wsbridge grants list / revoke / prune`；
  3. 在 `internal/mcpsrv` 启用强制 Bearer 鉴权中间件与 Grant 细粒度权限拦截，移除 `--dev-no-auth` 或严格限制其仅限单测；
  4. 实现 `internal/audit` JSONL 审计日志记录；
  5. 编写并运行 `e2e/full_flow_test.go`。
- **验收标准**：
  - `e2e` 测试客户端完整跑通“401 → PRM → AS → DCR → 授权提交 → 换 Token → MCP 调用 → Refresh 轮换 → 撤销失效”全链路；
  - 授权码重放、PKCE 错误、Redirect URI 不匹配、口令连续错误 5 次锁定、`/mcp` 零重定向等负面测试用例全部通过。

---

## M3：ChatGPT 平台真实接入验收（优先级 1）

- **前置条件**：M2 完成，且本地已配置稳定 HTTPS 隧道（如 Tailscale Funnel）。
- **实现范围**：
  1. 在 ChatGPT 开启 Developer Mode，通过 Settings → Apps & Connectors 添加自定义连接器；
  2. 完成浏览器 OAuth 同意页授权；
  3. 在对话中测试调用 `list_workspaces`、`get_file_tree`、`read_file`、`edit_file`；
  4. 观察 `access_token` 过期（1 小时后）ChatGPT 是否自动使用 `refresh_token` 刷新成功；
  5. 执行 `wsbridge grants revoke` 后验证调用被拒绝。
- **验收标准 & 文档回写**：
  - 上述功能全部验证通过；
  - 将 ChatGPT 实际发送的 `client_id` 形态（CIMD URL 还是 DCR）、`redirect_uri`、`resource`、`scope` 及工具确认弹窗表现回写至 `docs/reference/04-platform-quirks-matrix.md`。

---

## M4：Gemini（Spark 自定义应用）真实平台接入验收（优先级 2）

- **前置条件**：M2 完成；准备个人 Google 账号、界面语言设为英文、开启 Keep Activity。
- **实现范围**：
  1. 在 `gemini.google.com` → Settings → Connected Apps → Add a custom app 添加 `public_url + "/mcp"`；
  2. 开启 `wsbridge serve --debug-oauth` 观察完整 OAuth 握手过程并完成授权与只读工具调用；
  3. 若遇授权最后一步失败（“授权码已返回但 Google 未调用 token 端点”或 `Cannot Complete Request`），结合 `--debug-oauth` 日志与参考实现 `ghchinoy/spark-agent-tools` 逐项排查（issuer 一致性、元数据路径、302 响应参数 `iss`、`Content-Type` 等）并修复兼容问题。
- **验收标准 & 文档回写**：
  - 完成授权并成功调用只读工具，或准确定位平台侧限制；
  - 将实测抓包结论与解决方案回写至 `docs/reference/04-platform-quirks-matrix.md`。

---

## M5：Claude（Web / Desktop / Mobile）真实平台接入验收（优先级 3）

- **前置条件**：M2 完成。
- **实现范围**：
  1. 在 Claude Settings → Connectors → Add custom connector 添加连接器并完成授权；
  2. 验证工具调用成功，确认 `/mcp` 全程无 301/302 重定向导致丢 `Authorization` 头；
  3. 验证重复重新连接时未激活 DCR client 自动清理机制生效；
  4. 在 Claude 移动端验证同一已连接连接器的工具调用可用性。
- **验收标准 & 文档回写**：
  - Web 与移动端均调用成功，结论回写至 `docs/reference/04-platform-quirks-matrix.md`。

---

## M6：运维加固（`doctor` / `service`）与跨平台发布（`goreleaser`）

- **前置条件**：M3–M5 完成。
- **实现范围**：
  1. 完善 `internal/tunnel/doctor.go`（公网元数据探测、DCR 探测、`/mcp` 与 `/mcp/` 401 无重定向探测、Git 仓库检查）；
  2. 实现 `wsbridge service install / uninstall / start / stop / status`（基于 `kardianos/service`，严格用户级）；
  3. 编写 `.goreleaser.yaml` 支持交叉编译 `windows/amd64`、`darwin/arm64`、`darwin/amd64`、`linux/amd64`、`linux/arm64`；
  4. 完善面向最终用户的 `README.md`（含快速上手、隧道配置示例与提示词注入风险提示）。
- **验收标准**：
  - 三平台发布包构建成功；`doctor` 能准确识别并报告 URL 不一致、隧道返回 301 重定向、隧道未启动等常见故障。

---

## M7：可选增强特性（v2 / v3 规划）

按需拆分独立任务：
1. **CIMD 支持（v2）**：实现 Client ID Metadata Document 获取与缓存校验，并在 `/.well-known/oauth-authorization-server` 中将 `client_id_metadata_document_supported` 置为 `true`。
2. **本机终端确认模式（v2）**：支持在同意页点击后于运行 `wsbridge` 的终端交互确认（替代或叠加网页口令）。
3. **工具历史撤销 `undo_last_edit`（v2）**：暴露第 8 个工具，允许 AI 从最近一次外部快照恢复误改文件。
4. **ChatGPT 深度研究兼容工具 `search` / `fetch`（v2）**：为非 Developer Mode 场景提供兼容别名。
5. **托管隧道适配器（v2）与内嵌隧道（v3）**：托管 `cloudflared` / `tailscale` 子进程，或通过 Build Tag 内嵌 `tsnet` / `ngrok-go`。
