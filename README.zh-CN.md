# wsbridge

[English](README.md) | **简体中文**

`wsbridge` 是一个面向单用户的本地工作区安全桥接服务。它以**单个静态 Go 二进制**运行在 Windows / macOS / Linux 上，通过内置 OAuth 2.1 授权服务与 Streamable HTTP MCP 端点，让 **ChatGPT、Gemini、Claude** 在最小权限 Grant 约束下安全读取、修改与检查本机指定工作区。

## 核心特性

- **单二进制零运行时依赖**：Go ≥ 1.25，`CGO_ENABLED=0` 静态编译，内置 `bbolt`、Argon2id、OAuth 2.1 同意页与 MCP Server。
- **内置 OAuth 2.1 + Grant 模型**：支持 PRM、AS 元数据、DCR、PKCE S256、Refresh Token 轮换（30s 宽限期）与重放吊销；授权精确绑定工作区、权限（`read` / `write` / `check`）与有效期。
- **`os.Root` 内核级沙盒**：基于 Go `os.OpenRoot` 阻断路径穿越与符号链接逃逸，拦截 Windows 保留设备名与 ADS，默认屏蔽 `.git`、`.ssh`、`.env` 与私钥文件。
- **写前快照与固定检查白名单**：修改前自动保存外部快照，覆盖文件校验 `expected_sha256`；`run_check` 仅支持预编译固定检查枚举（`git_status`、`git_diff`、`go_vet`、`go_test`、`npm_lint`、`npm_test`）。
- **托管内网穿透**：首选内置托管 `cloudflared`（`[tunnel]`，`wsbridge` 退出时一并回收），次选 `tailscale funnel`。

## 快速上手

### 1. 构建（或从 Releases 下载）

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. 交互式初始化

在终端直接执行 `init`，按提示输入工作区路径、权限、穿透方案（首选 `cloudflared`、次选 `tailscale funnel`）、`public_url` 与管理员口令：

```bash
./wsbridge init
```

如需脚本化生成示例配置后再手动编辑：

```bash
./wsbridge init --non-interactive
./wsbridge passwd
```

### 3. 启动与自检

```bash
./wsbridge serve
# 另开终端检查本地配置、托管隧道与公网连通性
./wsbridge doctor --timeout 10s
```

如需以用户级后台服务常驻运行（systemd / launchd / Windows Service）：

```bash
./wsbridge service install
./wsbridge service start
```

### 4. 接入 AI 平台

所有平台均填写同一个 MCP 端点 URL：`<public_url>/mcp`（例如 `https://bridge.example.com/mcp`）。

| 平台 | 接入入口 | 备注 |
| :--- | :--- | :--- |
| **ChatGPT** | `Settings → Connectors → Developer mode → Create custom connector` | 自动 DCR + PKCE，重连自动 `/oauth/revoke` |
| **Gemini** | `gemini.google.com → Settings → Connected Apps → Add a custom app` | 需个人 Google 账号、界面语言 `English`、开启 Keep Activity |
| **Claude** | `Settings → Connectors → Add custom connector` | `/mcp` 与 `/mcp/` 无 301 重定向 |

## 常用命令

```bash
wsbridge grants list                  # 查看当前 Grant
wsbridge grants revoke <grant_id>     # 立即吊销指定 Grant
wsbridge grants revoke --all          # 吊销全部 Grant
wsbridge grants prune                 # 清理过期 Grant 与陈旧客户端
wsbridge serve --debug-oauth          # 脱敏输出 OAuth/MCP 调试日志
```

## 文档与 Skill

- 工程规格索引：[docs/README.md](docs/README.md)
- 平台实测记录：[docs/reference/04-platform-quirks-matrix.md](docs/reference/04-platform-quirks-matrix.md)
- Agent / AI 接入 SOP Skill：[skills/wsbridge-setup/SKILL.md](skills/wsbridge-setup/SKILL.md)

## 开源协议与作者

- 协议：[MIT](LICENSE)
- 作者：RoL1n_SrP (`contact@srprolin.com`)
*** Delete File: README.md
