# wsbridge

`wsbridge` 是一个面向单用户的本地工作区安全桥接服务。它以**单个静态 Go 二进制**运行在 Windows / macOS / Linux 上，通过内置的 OAuth 2.1 授权服务与 Streamable HTTP MCP 端点，让 **ChatGPT、Gemini、Claude** 的网页端与客户端在最小权限约束下安全地读取、修改与检查本机指定工作区。

```
ChatGPT / Gemini / Claude (云端)
        │  HTTPS (稳定隧道)
        ▼
   Tailscale Funnel / Cloudflare Named Tunnel / ngrok
        │  http://127.0.0.1:8787
        ▼
   wsbridge  ──  OAuth 2.1 + MCP
        │
        ▼
   [[workspace]] 沙盒（只读 / 写入 / 检查）
```

## 特性

- **单静态二进制**：`CGO_ENABLED=0` 构建，无运行时依赖；数据库使用内嵌 bbolt。
- **完整 OAuth 2.1 授权服务**：RFC 9728 PRM、RFC 8414 AS 元数据、RFC 7591 DCR、PKCE S256、RFC 8707 `resource`、RFC 9207 `iss`、RFC 7009 撤销。
- **最小权限 Grant**：每次授权明确选择工作区、权限（`read` / `write` / `check`）与有效期；可随时列出、吊销、清理。
- **零重定向路由**：`/mcp` 与 `/mcp/` 分别显式注册，避免隧道或 `ServeMux` 的 301 导致云端客户端丢弃 `Authorization` 头。
- **沙盒与敏感文件防护**：路径逃逸、符号链接逃逸、Windows 保留名与 ADS 均被拦截；`.git`、`.ssh`、`.env`、私钥等默认不可见。
- **写前快照**：所有写操作前自动备份至 `<data_dir>/snapshots/`，便于回滚。
- **默认脱敏审计**：`audit.jsonl` 记录注册、授权、令牌、工具调用与沙盒拦截，绝不记录口令与令牌原文。

## 环境要求

| 项目 | 要求 |
| :--- | :--- |
| 运行时 | Windows 10+ / macOS 13+ / 主流 Linux，amd64 或 arm64 |
| 构建 | Go ≥ 1.25，`CGO_ENABLED=0` |
| 网络 | 一个**固定域名**的 HTTPS 隧道（端口转发到 `127.0.0.1:8787`） |

## 构建与安装

```bash
git clone <repo-url> mcp-bridge
cd mcp-bridge
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o wsbridge ./cmd/wsbridge
```

也可从 Releases 下载对应平台压缩包。发布包目标：`windows/amd64`、`darwin/amd64`、`darwin/arm64`、`linux/amd64`、`linux/arm64`。

## 快速开始

### 1. 初始化配置

```bash
./wsbridge init
```

默认配置路径为 `<用户配置目录>/wsbridge/config.toml`：

- Linux：`~/.config/wsbridge/config.toml`
- macOS：`~/Library/Application Support/wsbridge/config.toml`
- Windows：`%AppData%\wsbridge\config.toml`

使用 `--config <path>` 可指定其他位置。随后编辑配置，至少设置 `public_url` 与一个 `[[workspace]]`：

```toml
# 固定 HTTPS 域名，不带尾部斜杠与路径
public_url = "https://my-box.tail1234.ts.net"

listen = "127.0.0.1:8787"

[[workspace]]
name = "myapp"
path = "/home/me/code/myapp"
max_perm = "check"                       # read | write | check
checks = ["git_status", "git_diff"]      # run_check 白名单
```

### 2. 设置管理员口令

```bash
./wsbridge passwd
```

口令不会回显，也不会出现在命令行参数、Shell 历史或进程表中；仅以 `argon2id` 哈希写入 `<data_dir>/wsbridge.db`。未设置口令时 `serve` 拒绝启动。

### 3. 启动 HTTPS 隧道

推荐使用**固定域名**的隧道方案：

| 方案 | 示例 |
| :--- | :--- |
| Tailscale Funnel（首选） | `tailscale funnel --bg 8787` → `https://<node>.<tailnet>.ts.net` |
| Cloudflare Named Tunnel | `cloudflared tunnel run`（指向 `http://127.0.0.1:8787`） |
| ngrok 静态域名 | `ngrok http --domain=<static-domain> 8787` |

若使用 Cloudflare Named Tunnel 且不希望单独维护系统服务，可在 `config.toml` 中启用托管模式，由 `wsbridge serve` 自动拉起、监控并在退出时一并关闭 `cloudflared`：

```toml
[tunnel]
provider = "cloudflared"
token_file = "/path/to/cloudflared-token" # 权限建议 0600，或改用 token_env = "CLOUDFLARE_TUNNEL_TOKEN"
```

> **不要使用随机临时域名**（如 `*.trycloudflare.com`）。`issuer`、`client_id`、Grant 与令牌均与 `public_url` 强绑定，域名变化会使所有已连接的 AI 平台连接器失效。
>
> 隧道层**不得**对 `/.well-known/*` 或 `/mcp` 返回 301/302（例如强制 HTTP→HTTPS 跳转或补全尾部斜杠），否则 Claude 云端运行时会丢弃 `Authorization` 头。

### 4. 启动服务

```bash
./wsbridge serve
```

参数：

| 参数 | 说明 |
| :--- | :--- |
| `--debug-oauth` | 输出脱敏后的 OAuth 握手细节，用于排查平台兼容问题 |
| `--dev-cors` | 允许本地 `localhost` 跨域访问，仅供 MCP Inspector 调试 |
| `--i-know-what-i-am-doing` | 允许在 `root` / `SYSTEM` 账号下启动（不建议） |
| `--allow-http-public-url` | 允许回环地址使用 `http://`，仅供本地测试 |

### 5. 自检

```bash
./wsbridge doctor
```

`doctor` 会检查数据目录与口令、工作区与 Git 状态、`rg` 可用性，并向 `public_url` 发起真实公网探测：PRM / AS 元数据字段、`/mcp` 与 `/mcp/` 的无令牌 `401`（含 `WWW-Authenticate`）、DCR 可达性。任何 3xx 重定向都会报告为关键错误。存在 `FAIL` 时退出码为 `1`，仅有 `WARN` 时为 `0`。

### 6. 在 AI 平台添加连接器

MCP URL 统一为 `<public_url>/mcp`，首次连接会跳转到 wsbridge 的同意页，选择工作区、权限与有效期后输入管理员口令。

| 平台 | 入口 |
| :--- | :--- |
| ChatGPT | `Settings → Connectors → Developer mode` → `Create custom connector` |
| Gemini | `gemini.google.com → Settings → Connected Apps → Add a custom app` |
| Claude | `claude.ai / Claude 桌面端 / 移动端 → Settings → Connectors → Add custom connector` |

Gemini 需要**个人 Google 账号**、界面语言设为 **English**，并开启 **Gemini Apps Activity**。

## 命令参考

```text
wsbridge [--config <path>] <command> [options]

  init      创建初始 config.toml 与 data_dir
  passwd    交互式设置管理员口令
  serve     启动 HTTP 桥接服务
  grants    列出、吊销或清理 OAuth Grant
  doctor    本地配置与公网连通性自检
  service   管理当前用户级后台服务
  help      显示帮助
```

### `wsbridge grants`

```bash
./wsbridge grants list                    # 表格列出全部 Grant
./wsbridge grants revoke <grant_id>       # 立即吊销该 Grant 及其全部令牌
./wsbridge grants revoke --all            # 紧急吊销全部活跃 Grant
./wsbridge grants prune                   # 清理过期/已吊销 Grant 与孤立快照
```

### `wsbridge service`

管理**当前用户级**后台守护进程（macOS `~/Library/LaunchAgents`、Linux `systemd --user`、Windows 当前用户计划任务），安装后的服务以 `wsbridge --config <绝对路径> serve` 运行：

```bash
./wsbridge service install
./wsbridge service start
./wsbridge service status
./wsbridge service stop
./wsbridge service uninstall
```

安装前会校验配置文件；配置无效时拒绝安装。Linux 若需在未登录时保持运行，可执行 `loginctl enable-linger "$USER"`。

## 提供哪些工具

| 工具 | 作用 | 最低权限 |
| :--- | :--- | :--- |
| `list_workspaces` | 列出 Grant 可访问的工作区与权限 | `read` |
| `get_file_tree` | 树形浏览目录（敏感文件已隐藏） | `read` |
| `read_file` | 读取文本文件 | `read` |
| `search_code` | 优先 `rg`，缺失时回退纯 Go 搜索 | `read` |
| `edit_file` | 唯一匹配替换，可要求 `expected_sha256` | `write` |
| `write_file` | 原子写入；覆盖已有文件需 `expected_sha256` | `write` |
| `run_check` | 仅执行配置白名单中的 `git_status` / `git_diff` 等检查 | `check` |

## 安全模型与风险提示

- **默认最小权限**：日常建议仅授予 `read`；仅在需要修改代码时临时授予 `write`。Grant 到期或吊销后令牌立即失效。
- **无 Shell、无外联工具**：AI 无法通过 wsbridge 执行任意命令或发起网络请求，降低「读取机密后主动外传」的可能性。
- **敏感文件默认不可见**：`.git`、`.ssh`、`.env`、`*.pem`、`id_*` 私钥等由沙盒层拦截；可用 `deny_patterns` 追加规则。
- **间接提示词注入（IPI）**：仓库 README、代码注释或 Issue 中可能藏有恶意指令，诱导 AI 读取并泄露内容。请仅连接可信工作区，并在网页端同时开启浏览或其他连接器时格外谨慎——那会形成组合外泄通道。
- **写前快照**：所有写入前都会备份原文件至 `snapshots/`；仍建议工作区使用 Git 以便审查与回滚。
- **高权限启动被拒绝**：以 `root` / `SYSTEM` 运行时默认拒绝启动，防止权限放大。
- **日志脱敏**：口令、授权码、访问/刷新令牌、`Authorization` 头与 `code_verifier` 不会出现在任何日志或错误响应中。

## 数据目录

默认与 `config.toml` 同目录（可用 `data_dir` 覆盖），目录权限建议 `0700`：

```text
<data_dir>/
├── wsbridge.db     # OAuth 客户端、Grant、令牌哈希与口令哈希（0600）
├── audit.jsonl     # 追加写入的 JSONL 审计日志（0600）
└── snapshots/
    └── <grant_id>/<timestamp>/<workspace>/<path>   # 写前快照
```

审计事件包括 `dcr_register`、`authorize_attempt`、`token_issue`、`token_refresh`、`token_replay_revoked`、`grant_revoke`、`tool_call`、`sandbox_blocked`。

## 故障排查

| 现象 | 处理 |
| :--- | :--- |
| 连接器授权后立即失效 | 确认 `public_url` 与隧道域名逐字符一致（无尾部斜杠）；域名变更会吊销全部 Grant，重新连接即可 |
| 平台报错且令牌请求未到达 | 用 `--debug-oauth` 观察握手；确认隧道未对 `/mcp` 返回 3xx |
| `doctor` 报 `unexpected 3xx redirect` | 关闭隧道或反向代理的重定向规则（HTTP→HTTPS、尾斜杠补全、登录页） |
| `serve` 提示口令未设置 | 先执行 `wsbridge passwd` |
| `doctor` 提示数据库被锁定 | 属预期：`serve` 正持有写锁，口令与签发者检查跳过；如需完整检查可先停止服务 |
| Linux 服务注销后停止 | `loginctl enable-linger "$USER"` |
| 写入被拒绝 | 检查该 Grant 的权限是否为 `write`，目标是否命中敏感名单，或 `expected_sha256` 是否过期 |

## 开发

```bash
gofmt -l cmd internal e2e
go vet ./...
go test -race -count=1 ./...

# 跨平台静态构建
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -o /tmp/wsbridge-$os-$arch ./cmd/wsbridge
  done
done
```

发布流程由 `.goreleaser.yaml` 与 `.github/workflows/release.yml` 驱动：推送 `v*` 标签后自动构建五平台产物并生成校验和。

详细设计文档见 `docs/`，实现红线见 `AGENTS.md`。
