# wsbridge 协议、工具与配置接口参考规范

> 本文档是全部外部契约的权威参考：OAuth 2.1 HTTP 端点报文、MCP 工具 JSON Schema、CLI/`config.toml` 规范，以及三个 AI 平台的接入细节与实测记录。

设定配置项 `public_url = "https://my-box.tail1234.ts.net"`，则 `issuer = "https://my-box.tail1234.ts.net"`，`mcp_url = "https://my-box.tail1234.ts.net/mcp"`。

## 目录导航

- [1. OAuth 2.1 端点与报文参考规范](#1-oauth-21-端点与报文参考规范)
  - [1.1 受保护资源元数据（RFC 9728）](#11-受保护资源元数据rfc-9728)
  - [1.2 授权服务器元数据（RFC 8414）](#12-授权服务器元数据rfc-8414)
  - [1.3 动态客户端注册（RFC 7591 DCR）](#13-动态客户端注册rfc-7591-dcr)
  - [1.4 授权端点（GET & POST /oauth/authorize）](#14-授权端点get--post-oauthauthorize)
  - [1.5 令牌端点（POST /oauth/token）](#15-令牌端点post-oauthtoken)
  - [1.6 令牌撤销端点（RFC 7009 POST /oauth/revoke）](#16-令牌撤销端点rfc-7009-post-oauthevoke)
- [2. MCP 工具契约与 JSON Schema 规范](#2-mcp-工具契约与-json-schema-规范)
  - [2.1 通用协议约束](#21-通用协议约束)
  - [2.2 工具清单与权限/标注矩阵](#22-工具清单与标注矩阵)
  - [2.3 各工具详细输入 Schema 与行为规格](#23-各工具详细输入-schema-与行为规格)
- [3. CLI 子命令与 TOML 配置文件参考规范](#3-cli-子命令与-toml-配置文件参考规范)
  - [3.1 配置文件规范（config.toml）](#31-配置文件规范configtoml)
  - [3.2 CLI 子命令规格](#32-cli-子命令规格标准库-flag-实现)
- [4. 三平台接入细节、已知坑点与实测记录矩阵](#4-三平台接入细节已知坑点与实测记录矩阵)
  - [4.1 ChatGPT（OpenAI）](#41-chatgptopenai)
  - [4.2 Gemini（Google Spark 自定义应用）](#42-geminigoogle-spark-自定义应用)
  - [4.3 Claude（Anthropic Web / Desktop / Mobile / Cowork）](#43-claudeanthropic-web--desktop--mobile--cowork)
  - [4.4 平台实测验收记录表](#44-平台实测验收记录表agent-完成-m3m4m5-后回写)

---

## 1. OAuth 2.1 端点与报文参考规范

### 1.1 受保护资源元数据（RFC 9728）

**请求**

```text
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-protected-resource/mcp
```

**响应（`200 OK`, `Content-Type: application/json; charset=utf-8`）**

```json
{
  "resource": "https://my-box.tail1234.ts.net/mcp",
  "authorization_servers": [
    "https://my-box.tail1234.ts.net"
  ],
  "scopes_supported": [
    "mcp:tools",
    "offline_access"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```

**未授权 `/mcp` 响应（`401 Unauthorized`）**

任意未携带有效 `Bearer` 令牌的 `/mcp` 或 `/mcp/` 请求必须返回：

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://my-box.tail1234.ts.net/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json; charset=utf-8
Cache-Control: no-store

{"error":"invalid_token","error_description":"missing or invalid bearer token"}
```

### 1.2 授权服务器元数据（RFC 8414）

**请求**

```text
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration（同内容别名，兼容部分 OIDC 发现客户端）
```

**响应（`200 OK`, `Content-Type: application/json; charset=utf-8`）**

```json
{
  "issuer": "https://my-box.tail1234.ts.net",
  "authorization_endpoint": "https://my-box.tail1234.ts.net/oauth/authorize",
  "token_endpoint": "https://my-box.tail1234.ts.net/oauth/token",
  "registration_endpoint": "https://my-box.tail1234.ts.net/oauth/register",
  "revocation_endpoint": "https://my-box.tail1234.ts.net/oauth/revoke",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "revocation_endpoint_auth_methods_supported": ["none"],
  "scopes_supported": ["mcp:tools", "offline_access"],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": false
}
```

### 1.3 动态客户端注册（RFC 7591 DCR）

**请求：`POST /oauth/register`**

```json
{
  "client_name": "Claude",
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "web"
}
```

**校验规则与错误码**

1. `redirect_uris` 为空或超过 **10** 条 → `400 invalid_redirect_uri`。
2. 任一 `redirect_uri` 非法、含片段 `#`、非 `https`（回环地址 `127.0.0.1` / `localhost` / `[::1]` 除外）或 Host 未命中白名单 → `400 invalid_redirect_uri`（服务端日志记录完整被拒 URI）。
3. `token_endpoint_auth_method` 若传入且不等于 `"none"` → `400 invalid_client_metadata`。
4. 已注册 Client 总数达 `200` 且清理过期未激活 Client 后仍满 → `429` 或 `400 invalid_client_metadata`。

**默认 Redirect Host 白名单**

- `chatgpt.com`
- `platform.openai.com`
- `claude.ai`
- `claude.com`
- `oauth-redirect.googleusercontent.com`
- `oauth-redirect-sandbox.googleusercontent.com`
- `oauth-redirect-test.googleusercontent.com`
- `localhost`、`127.0.0.1`、`[::1]`（任意端口）
- 外加配置文件 `allow_redirect_hosts` 中的精确域名。

**成功响应（`201 Created`）**

```json
{
  "client_id": "wsb_cli_7f9a2b4c8d1e",
  "client_id_issued_at": 1794560000,
  "client_name": "Claude",
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "web"
}
```

### 1.4 授权端点（GET & POST /oauth/authorize）

**`GET /oauth/authorize` 查询参数**

| 参数 | 必填 | 校验规则 |
| :--- | :--- | :--- |
| `response_type` | 是 | 必须为 `"code"` |
| `client_id` | 是 | 必须存在于 `bbolt` `clients` 表 |
| `redirect_uri` | 是 | 必须与该 `client_id` 注册的某条 `redirect_uri` **字节级完全相等** |
| `code_challenge` | 是 | 43–128 字符合法 Base64URL 字符串 |
| `code_challenge_method` | 是 | 必须为 `"S256"`（拒绝 `plain` 或空值） |
| `state` | 推荐 | 若提供，原样透传并在回调中回传 |
| `scope` | 否 | 空格分隔字符串，展示于同意页 |
| `resource` | 否 | 若提供，必须严格等于 `public_url + "/mcp"`，否则报 `invalid_target` |

**`POST /oauth/authorize` 表单提交与成功回调**

用户提交同意表单且校验通过后，服务端返回 `302 Found`：

```http
HTTP/1.1 302 Found
Location: https://claude.ai/api/mcp/auth_callback?code=<32B_RANDOM_B64URL>&state=<ORIGINAL_STATE>&iss=https%3A%2F%2Fmy-box.tail1234.ts.net
Cache-Control: no-store
```

### 1.5 令牌端点（POST /oauth/token）

请求体支持 `application/x-www-form-urlencoded`（标准强制要求）。

**授权码换令牌（`grant_type=authorization_code`）**

请求参数：`grant_type`、`code`、`redirect_uri`、`client_id`、`code_verifier`、可选 `resource`。

成功响应（`200 OK`）：

```json
{
  "access_token": "wsb_at_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "wsb_rt_...",
  "scope": "mcp:tools offline_access"
}
```

**刷新令牌轮换（`grant_type=refresh_token`）**

请求参数：`grant_type`、`refresh_token`、可选 `client_id`、可选 `resource`。

行为约束：

- 首次轮换：生成新 `access_token`（3600s）与新 `refresh_token`（30d），旧 `refresh_token` 进入 30 秒宽限期；
- 30s 宽限期内重复提交同一旧 `refresh_token`：幂等返回相同的 `200 OK` JSON；
- 超过 30s 再次提交旧 `refresh_token`：触发重放撤销整个 Grant，返回 `400 {"error":"invalid_grant","error_description":"refresh token replay detected"}`。

### 1.6 令牌撤销端点（RFC 7009 POST /oauth/revoke）

- **请求参数**：`token`（必填）、`token_type_hint`（可选 `access_token` 或 `refresh_token`）。
- **行为**：若 `token` 命中库中有效记录，则将对应 `Grant` 及其名下全部 `access_token` / `refresh_token` 标记为 `revoked = true`；无论令牌是否存在或已过期，按 RFC 7009 规范统一返回 `200 OK`（空响应体）。

---

## 2. MCP 工具契约与 JSON Schema 规范

### 2.1 通用协议约束

1. **工具总数上限**：v1 严格控制在 **7 个核心工具**（v2 最多增至 8 个），防止网页端模型工具选择准确率下降。
2. **输出格式**：所有工具一律返回 `[]mcp.Content{&mcp.TextContent{Text: ...}}`，不依赖 `structuredContent`。
3. **响应体硬上限**：单次工具输出文本上限为 **64KB（65,536 字节）**。超出上限时必须安全截断（不破坏 UTF-8 多字节字符边界），并在末尾附加如何缩小范围或分页继续读取的明确提示。
4. **多工作区路由规则**：除 `list_workspaces` 外，所有工具均定义可选字段 `workspace`（`string`）。当当前 Grant 仅授权 1 个工作区时可省略并自动命中该工作区；当授权 ≥ 2 个工作区时必须显式传入 `workspace`。

### 2.2 工具清单与标注矩阵

| 工具名称 | 所需最低权限 | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `list_workspaces` | `read` | `true` | `false` | `true` | `false` |
| `get_file_tree` | `read` | `true` | `false` | `true` | `false` |
| `search_code` | `read` | `true` | `false` | `true` | `false` |
| `read_file` | `read` | `true` | `false` | `true` | `false` |
| `edit_file` | `write` | `false` | `true` | `false` | `false` |
| `write_file` | `write` | `false` | `true` | `false` | `false` |
| `run_check` | `check` | `false` | `true` | `false` | `false` |

> **安全边界**：所有工具的 `openWorldHint` 必须显式设为 `false`，向宿主平台声明本工具集仅作用于受控本地工作区，不访问开放互联网。

### 2.3 各工具详细输入 Schema 与行为规格

#### `list_workspaces`

- **描述**：列出当前授权会话可访问的所有本地工作区名称、有效权限级别及允许执行的检查项。
- **输入 Schema**：`{"type": "object", "properties": {}, "additionalProperties": false}`
- **输出样例**：

  ```text
  Authorized workspaces (1):
  - name: myapp | effective_perm: check | allowed_checks: [git_status, git_diff]
  ```

#### `get_file_tree`

- **描述**：查看指定工作区下的目录树结构（自动跳过 `.git`、`node_modules` 等重目录及敏感文件）。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
      "path": { "type": "string", "default": "", "description": "Relative directory path inside the workspace." },
      "depth": { "type": "integer", "default": 3, "minimum": 1, "maximum": 10, "description": "Max traversal depth." },
      "cursor": { "type": "string", "default": "", "description": "Pagination cursor returned by a previous truncated response." }
    },
    "additionalProperties": false
  }
  ```

- **约束**：单次返回最多 **2,000** 个条目；超出时返回下一页 `cursor` 与提示。

#### `search_code`

- **描述**：在工作区文本文件中搜索正则或字面量模式，返回 `path:line:text` 格式匹配结果。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "query": { "type": "string", "minLength": 1, "description": "Search pattern (regex or plain text)." },
      "path": { "type": "string", "default": "", "description": "Optional subdirectory or file filter." },
      "regex": { "type": "boolean", "default": false, "description": "Interpret query as regular expression when true." },
      "ignore_case": { "type": "boolean", "default": true },
      "max_results": { "type": "integer", "default": 100, "minimum": 1, "maximum": 500 }
    },
    "required": ["query"],
    "additionalProperties": false
  }
  ```

- **约束**：执行超时 `20s`；命中结果均经过沙盒敏感文件二次过滤。

#### `read_file`

- **描述**：读取工作区文本文件内容，支持单次读取多个行号区间，返回带行号文本与文件当前 `sha256`。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "ranges": {
        "type": "array",
        "description": "Optional list of 1-based inclusive line ranges. Reads from line 1 up to limits if omitted.",
        "items": {
          "type": "object",
          "properties": {
            "start_line": { "type": "integer", "minimum": 1 },
            "end_line": { "type": "integer", "minimum": 1 }
          },
          "required": ["start_line", "end_line"],
          "additionalProperties": false
        }
      }
    },
    "required": ["path"],
    "additionalProperties": false
  }
  ```

- **约束**：单文件大小上限 `2MB`；检测到二进制内容直接返回 `IsError: true`；单次返回总行数 ≤ 2000 行且总字节 ≤ 64KB；输出头部固定包含 `File: <path> | SHA256: <hex>`。

#### `edit_file`

- **描述**：对已有文本文件执行一处或多处原子精确替换，自动保留原文件换行符与 BOM，写入前生成外部快照。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "expected_sha256": { "type": "string", "description": "Optional optimistic concurrency check against last read sha256." },
      "edits": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": "object",
          "properties": {
            "old_text": { "type": "string", "minLength": 1 },
            "new_text": { "type": "string" },
            "replace_all": { "type": "boolean", "default": false }
          },
          "required": ["old_text", "new_text"],
          "additionalProperties": false
        }
      }
    },
    "required": ["path", "edits"],
    "additionalProperties": false
  }
  ```

- **行为与返回**：所有 `edits` 在内存中按顺序校验并应用（任何一条失败则整批回滚，不修改磁盘）；`replace_all=false` 时若匹配数 ≠ 1 报错并列出匹配行号；成功写入后返回统一 Diff 片段及**更新后的新 `SHA256`**（便于链式连续编辑）。

#### `write_file`

- **描述**：创建新文件，或在提供 `expected_sha256` 的前提下完整覆盖已有文件。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "content": { "type": "string" },
      "expected_sha256": { "type": "string", "description": "Required when overwriting an existing file; must be omitted or empty when creating a new file." }
    },
    "required": ["path", "content"],
    "additionalProperties": false
  }
  ```

- **行为与返回**：
  - 目标文件不存在且未传 `expected_sha256` → 创建父目录（均经 `os.Root` 校验）并写入新文件；
  - 目标文件不存在但传了非空 `expected_sha256` → 报错（文件不存在，无法匹配预期哈希）；
  - 目标文件已存在但未传 `expected_sha256` → 报错拒绝覆盖，提示先调用 `read_file`；
  - 成功后返回字节数与**最新 `SHA256`**。

#### `run_check`

- **描述**：执行工作区内建的项目检查/测试命令（默认全部开放；如配置了工作区 `checks` 子集则按子集限制）。
- **输入 Schema**：

  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "name": { "type": "string", "minLength": 1, "description": "Built-in check identifier (e.g., git_status, git_diff, go_test, npm_test, pytest, uv_pytest, uv_ruff, uv_pip_list, pip_list, cargo_test). Call list_workspaces for the full list." }
    },
    "required": ["name"],
    "additionalProperties": false
  }
  ```

- **内置命令映射表**（默认全部开放，绝不读取工作区内 `Makefile`/`package.json` 动态拼接 shell 命令）：

  | 类别 | 检查项（命令） |
  | :--- | :--- |
  | **Git** | `git_status`（`git status --short --branch`）｜ `git_diff`（`git diff`）｜ `git_log`（`git log -n 20 --oneline`） |
  | **Go** | `go_vet`（`go vet ./...`）｜ `go_test`（`go test ./...`）｜ `go_build`（`go build ./...`） |
  | **Node** | `npm_lint`（`npm run lint`）｜ `npm_test`（`npm test`）｜ `npm_build`（`npm run build`） |
  | **Python** | `pytest`（`pytest`）｜ `ruff_check`（`ruff check .`）｜ `mypy`（`mypy .`）｜ `uv_pytest`（`uv run pytest`）｜ `uv_ruff`（`uv run ruff check .`）｜ `uv_mypy`（`uv run mypy .`）｜ `uv_lock_check`（`uv lock --check`）｜ `uv_pip_list`（`uv pip list`）｜ `uv_pip_check`（`uv pip check`）｜ `pip_list`（`pip list`）｜ `pip_check`（`pip check`） |
  | **Rust** | `cargo_check`（`cargo check`）｜ `cargo_test`（`cargo test`） |

- **环境隔离**：子进程仅继承非敏感白名单环境变量（`PATH`、`HOME`/`USERPROFILE`、`TMPDIR`/`TEMP`/`TMP`、`GOPATH`、`GOROOT`、`GOMODCACHE`、`APPDATA`、`LOCALAPPDATA`、`SYSTEMROOT`/`WINDIR`/`COMSPEC`/`PATHEXT`、`VIRTUAL_ENV`、`UV_CACHE_DIR`、`UV_PYTHON_INSTALL_DIR`、`PIP_CACHE_DIR`、`PYTHONUTF8`、`CARGO_HOME`、`RUSTUP_HOME`、`XDG_CACHE_HOME`、`XDG_DATA_HOME`、`LANG`、`LC_ALL`、`NODE_ENV`）；执行超时 `60s`；输出上限 `64KB`。

---

## 3. CLI 子命令与 TOML 配置文件参考规范

### 3.1 配置文件规范（`config.toml`）

默认路径：`<os.UserConfigDir()>/wsbridge/config.toml`（可通过 `--config` 覆盖）。

```toml
# 必填：公网可访问的 HTTPS 基础 URL（不含尾部斜杠，不含 /mcp）
public_url = "https://my-box.tail1234.ts.net"

# 本地监听地址，默认仅绑定回环网卡
listen = "127.0.0.1:8787"

# 数据目录（存放 wsbridge.db、audit.jsonl、snapshots/、active-workspace.json）
# 留空时默认与 config.toml 同目录（os.UserConfigDir()/wsbridge）
data_dir = ""

# 可选：本地权限上限（"read" | "write" | "check"）。留空默认全开（"check"），由浏览器 OAuth 同意页管理每条连接的权限。
# max_perm = "check"

# 额外允许的 OAuth redirect_uri 域名列表（精确匹配 Host）
allow_redirect_hosts = []

# 全局额外敏感文件/目录匹配模式（追加到内置 denylist，不可移除 .git 与 .ssh）
deny_patterns = []

# 每个 Grant 保留的写前快照最大份数
max_snapshots_per_grant = 20

# 工作区配置为可选项：留空时 "wsbridge serve" 默认使用当前工作目录，并可通过 "wsbridge use <dir>" 在运行中热切换。
# 如需固定静态工作区，可取消注释：
# [[workspace]]
# name = "myapp"
# path = "/home/me/code/myapp"
```

**字段校验规则**

- `public_url`：必须以 `https://` 开头（仅当 `listen` 为回环且传 `--allow-http-public-url` 测试参数时才允许 `http://`），不得包含路径、查询参数或尾部斜杠。
- `max_perm`（可选）：留空默认 `check`；若显式配置则必须为 `read` / `write` / `check`，作为本地权限天花板与 OAuth Grant 权限取最小值。
- `[[workspace]]`（可选）：`name` 必须全局唯一且仅含 `[a-zA-Z0-9._-]`；`path` 必须是存在的本地目录绝对路径；`max_perm` 省略时继承全局 `max_perm`；`checks` 省略或为空时开放全部内置检查项。
- 管理员口令的 `argon2id` 哈希存储在 `<data_dir>/wsbridge.db` 中，**严禁出现在 `config.toml` 中**。

### 3.2 CLI 子命令规格（标准库 `flag` 实现）

全局可用参数：`--config <path>`（指定配置文件路径）。

**`wsbridge init`**

- 交互式仅配置隧道方案（`cloudflared` / `tailscale funnel` / 自定义）、`public_url`、`listen` 与管理员口令（不再绑定工作区与全局权限）。
- 可选参数：`--force`（覆盖已有配置文件）、`--non-interactive`（写入精简示例配置）。

**`wsbridge passwd`**

- 交互式读取新管理员口令（关闭终端回显，确认输入两次，最小长度 10 位），生成 `argon2id` 哈希写入 `wsbridge.db`。
- 安全约束：不支持通过命令行位置参数传递明文口令（防止泄露至 Shell 历史记录与 `ps` 进程表）。

**`wsbridge serve [dir]`**

- 启动 HTTP 服务及本机独立回环控制通道（`<data_dir>/control.json`，仅本机随机端口 + 32B 随机 Bearer 令牌，与公网隧道隔离），阻塞监听信号（`SIGINT` / `SIGTERM` 优雅关闭）。
- **工作区解析优先级**：
  1. 显式传入位置参数 `[dir]` → 挂载该目录并持久化至 `active-workspace.json`；
  2. `config.toml` 配置了静态 `[[workspace]]` → 加载配置的静态工作区；
  3. 动态模式（默认）：前台终端启动时自动挂载当前工作目录（`cwd`）；后台系统服务模式（`wsbridge service`）自动恢复 `active-workspace.json` 中上次选定的目录（若尚未选择则空载等待 `wsbridge use <dir>`）。
- **参数**：
  - `--max-perm <read|write|check>`：可选临时收紧本地权限上限；
  - `--debug-oauth`：输出脱敏后的完整 OAuth 握手调试日志；
  - `--dev-cors`：允许本地 `http://localhost:*` 与 `http://127.0.0.1:*` 跨域访问，仅供本地 MCP Inspector 浏览器调试；
  - `--i-know-what-i-am-doing`：允许在 `root` 或 `SYSTEM` 高权限账号下启动服务。
- **启动前强校验**：若尚未设置管理员口令（`admin_pass_hash` 为空），拒绝启动并提示先执行 `wsbridge passwd`。

**`wsbridge use [dir]`**

- 热切换当前活跃工作区（默认 `[dir]` 为当前目录 `.`），更新 `active-workspace.json`；若 `wsbridge serve` / `wsbridge service` 正在运行，立即通过本机控制通道原子切换 `*os.Root`，远端 AI 连接与 OAuth Token 全程不中断、无需重连。
- **参数**：
  - `--name <name>`：可选自定义工作区名（默认由目录名自动规范化生成）；
  - `--show`：仅查看当前活跃或已保存的工作区状态，不执行切换。

**`wsbridge grants`**

管理已签发的 OAuth 授权会话：

- `wsbridge grants list`：表格打印所有 Grant（`Grant ID`、`Client Name`、`Workspaces & Perms`、`Created`、`Expires`、`Status`）；
- `wsbridge grants revoke <grant_id>`：立即吊销指定 Grant 及其名下所有 Access/Refresh Token；
- `wsbridge grants revoke --all`：一键紧急吊销全部活跃 Grant；
- `wsbridge grants prune`：物理清理已过期或已吊销的历史 Grant 与孤立快照。

**`wsbridge doctor`**

- 执行本地配置完整性与公网 `public_url` 连通性/零重定向自检（完整检查项见 `docs/architecture.md` 第 4.3 节）。
- 退出码：全部检查通过返回 `0`；存在关键错误返回 `1`（仅存在 `WARN` 如未初始化 Git 时返回 `0` 并高亮提示）。

**`wsbridge service`**

基于 `github.com/kardianos/service` 管理**当前用户级**后台守护进程（macOS `~/Library/LaunchAgents`、Linux `systemd --user`、Windows 当前用户计划任务）：

```text
wsbridge service install
wsbridge service uninstall
wsbridge service start
wsbridge service stop
wsbridge service status
```

---

## 4. 三平台接入细节、已知坑点与实测记录矩阵

> **优先级顺序**：1. ChatGPT → 2. Gemini → 3. Claude。凡标注 `【待实测】` 的条目必须在对应里程碑（M3/M4/M5）中用真实账号验证，并将结果回写至本节末尾的实测记录表。

### 4.1 ChatGPT（OpenAI）

- **接入路径**：网页端开启 `Settings → Security / Connectors → Developer mode` → `Apps & Connectors` → `Create custom connector`，填写 MCP URL（`<public_url>/mcp`）。
- **认证行为**：
  - 优先检查 `/.well-known/oauth-authorization-server` 中的 `client_id_metadata_document_supported`；若为 `false`，回退使用 `registration_endpoint`（RFC 7591 DCR）注册临时客户端；
  - 若支持 CIMD，`client_id` 为托管在 `chatgpt.com` 上的 HTTPS JSON URL（v2 适配）；
  - 授权请求与 Token 请求均携带 `resource=<public_url>/mcp`（RFC 8707）；
  - **关键坑点**：部分场景下 ChatGPT 发起授权请求时未显式申请 `offline_access` scope，若服务端不返回 `refresh_token`，1 小时后 `access_token` 过期会导致连接器直接失效且不会自动重连。因此 `wsbridge` **始终签发 `refresh_token`**。
- **工具确认机制 `【待实测】`**：Developer Mode 下默认依据工具 `annotations`（如 `destructiveHint: true`）决定是否在对话中弹出确认按钮。

### 4.2 Gemini（Google Spark 自定义应用）

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

### 4.3 Claude（Anthropic Web / Desktop / Mobile / Cowork）

- **接入路径**：`claude.ai`（或 Claude 桌面端）→ `Settings` → `Connectors` → `Add custom connector`，输入 `<public_url>/mcp`。
- **认证行为**：
  - 统一由 Anthropic 云端托管运行时发起所有 MCP 请求（即使在桌面端或移动端操作，流量也来自 Anthropic 云端 IP）；
  - 回调地址主要为 `https://claude.ai/api/mcp/auth_callback`（部分工作区为 `claude.com`）；
  - 支持 DCR、CIMD 与预注册客户端，强制 PKCE S256 与 `resource` 参数。
- **已知关键坑点**：
  1. **跨主机或路径重定向丢失 `Authorization` 头**：Claude 托管运行时在遇到 `301`/`302` 重定向时会剥离 `Authorization` 头，导致后续请求全部 `401`。`wsbridge` 通过显式双注册 `/mcp` 与 `/mcp/` 彻底规避；
  2. **重复重连产生僵尸 Client**：用户每次在 Claude 界面点击断开并重新连接时，Claude 都会再次调用 `/oauth/register` 创建新的 `client_id`。`wsbridge` 的 24 小时未激活自动清理与 `200` 上限淘汰机制专门解决此问题。

### 4.4 平台实测验收记录表（Agent 完成 M3/M4/M5 后回写）

| 里程碑 | 实测日期 | 平台与版本/入口 | 实测抓包特征（`client_id` / `redirect_uri` / `scope`） | 遇到的问题与最终解法 |
| :--- | :--- | :--- | :--- | :--- |
| **M3 ChatGPT** | 2026-11-14 | ChatGPT Web (`Settings → Connectors → Developer mode → Create custom connector`)；UA: `openai-connectors-oauth/1.0`, `openai-mcp/1.0.0` | `client_id=wsb_cli_207865b21092` (`ChatGPT`)；`redirect_uri=https://chatgpt.com/connector_platform_oauth_redirect`；`scope=offline_access mcp:tools`；`Mcp-Protocol-Version: 2026-07-28`（`server/discover` → `tools/list` → `tools/call`）；重连时会先调用 `/oauth/revoke` | 1. 同意页原 CSP `form-action 'self'` 在 Chromium 下拦截表单 POST 后的跨域 `302` 回调，移除 `form-action 'self'` 后恢复跳转；2. 有状态 MCP 传输不支持 `2026-07-28` 协议版本导致 `action discovery failed`，在 `StreamableHTTPOptions` 启用 `Stateless: true` 后完整通过 `list_workspaces` 与 `read_file` |
| **M4 Gemini** | 2026-11-14 | Gemini Web (`Settings → Connected Apps → Add a custom app`)；UA: `Google` | `client_id=wsb_cli_f149850be151` (`Google`)；DCR 一次提交 6 个 `oauth-redirect*.googleusercontent.com/{r,a}/...` 回调；`Mcp-Protocol-Version: 2025-11-25` | 一次通过 DCR、授权、换取 token 与 `get_file_tree` / `list_workspaces` / `read_file`；未出现 `/oauth/token` 未调用问题 |
| **M5 Claude** | 2026-11-14 | Claude Web (`Settings → Connectors → Add custom connector`)；UA: `Claude-User`, `X-Anthropic-Client: ClaudeAI` | `client_id=wsb_cli_7ffe3fba437a` (`Claude`)；`redirect_uri=https://claude.ai/api/mcp/auth_callback`；`scope=mcp:tools offline_access`；`Mcp-Protocol-Version: 2026-07-28`（`server/discover` → `tools/list` → `tools/call`） | 一次通过 DCR、授权、换取 token 与 `list_workspaces` / `get_file_tree` / `read_file`；`Stateless: true` 与 `/mcp`、`/mcp/` 无重定向双注册协同生效 |