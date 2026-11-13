# 03. 测试策略、E2E 规范与 CI 配置

## 1. 测试金字塔与覆盖率目标

`wsbridge` 直接处理公网 OAuth 认证与本地文件修改，核心安全边界必须有 100% 的单元测试覆盖，并通过端到端测试验证协议合规性。

---

## 2. 必须编写的单元测试清单

### 2.1 `internal/ws` 沙盒与原子写测试（`ws_test.go`）
- **路径逃逸拦截**：`../secret.txt`、`a/../../b`、`/etc/passwd`、`C:\Windows\System32`、`file.txt:ads`、`CON`、`NUL.txt`、`COM1` 均必须返回沙盒违规错误。
- **符号链接防御**：在临时工作区内创建一个指向工作区外部文件的符号链接 `escape_link`，验证 `ReadFile`、`WalkTree`、`Search` 均无法读取外部文件内容。
- **敏感文件屏蔽**：验证 `.git/config`、`.env`、`.env.local`、`id_ed25519`、`cert.pem`、`.ssh/authorized_keys` 在列目录时被隐藏，直接读取时被拒绝。
- **换行符与 BOM 保持**：
  - 带 UTF-8 BOM + CRLF 的文件经 `WriteFileAtomic` 修改后，BOM 与 CRLF 均完整保留；
  - 包含混合换行符（既有 `\r\n` 又有孤立 `\n`）的文件写入时必须直接拒绝并返回明确提示。
- **写前快照与原子性**：验证覆盖写入后，`<data_dir>/snapshots/<grant_id>/...` 下生成了原始内容备份，且超过保留上限时自动清理最旧快照。

### 2.2 `internal/oauth` 协议与安全测试（`oauth_test.go`）
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

---

## 3. 无平台依赖 E2E 全链路测试（`e2e/full_flow_test.go`）

在 `e2e/` 包中启动一个绑定到 `httptest.Server`（模拟公网 HTTPS 入口）的完整 `wsbridge` 实例，使用纯 Go 编写自动化测试客户端依次执行：

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

---

## 4. 调试抓包与 CI 流水线

### 4.1 `--debug-oauth` 调试模式
启动 `wsbridge serve --debug-oauth` 时，将完整的 OAuth 发现、DCR、授权、令牌交互的**方法、路径、脱敏后的请求/响应头、脱敏后的参数与状态码**输出至 `stderr`，专门用于定位 Gemini Spark 等平台在真实网络下的握手异常。

### 4.2 GitHub Actions CI（`.github/workflows/ci.yml`）
- **测试矩阵**：`ubuntu-latest`、`macos-latest`、`windows-latest`，Go 版本 `1.25.x`。
- **执行命令**：
  ```bash
  go vet ./...
  go test -race -count=1 ./...
  CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
  ```
