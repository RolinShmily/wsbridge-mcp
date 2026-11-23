# wsbridge

[English](README.md) | **简体中文**

`wsbridge` 是一个面向单用户的本地工作区安全桥接服务。它以**单个静态 Go 二进制**运行在 Windows / macOS / Linux 上，通过内置 OAuth 2.1 授权服务与 Streamable HTTP MCP 端点，让 **ChatGPT、Gemini、Claude** 在最小权限 Grant 约束下安全读取、修改与检查本机指定工作区。

## 核心特性

- **单二进制零运行时依赖**：Go ≥ 1.25，`CGO_ENABLED=0` 静态编译，内置 `bbolt`、Argon2id、极简 OAuth 2.1 同意页与 MCP Server。
- **动态工作区与热切换**：`wsbridge serve` 默认服务当前工作目录；任意项目目录下运行 `wsbridge use` 可实时热切换运行中的活跃工作区，隧道不断线、远端无需重新 OAuth 授权。
- **内置 OAuth 2.1 + 连接级权限管理**：支持 PRM、AS 元数据、DCR、PKCE S256、Refresh Token 轮换（30s 宽限期）与重放吊销；权限（默认全开 `check`，可选 `write`/`read`）完全在浏览器同意页控制，变更权限只需断开重连。
- **`os.Root` 内核级沙盒**：基于 Go `os.OpenRoot` 阻断路径穿越与符号链接逃逸，拦截 Windows 保留设备名与 ADS，默认屏蔽 `.git`、`.ssh`、`.env` 与私钥文件。
- **写前快照与内置项目检查**：修改前自动保存外部快照，覆盖文件校验 `expected_sha256`；`run_check` 默认开放全套预编译项目检查（Git / Go / Node / Python `pytest`、`ruff`、`mypy`、`uv`、`pip` / Rust）。
- **托管内网穿透**：首选内置托管 `cloudflared`（`[tunnel]`，`wsbridge` 退出时一并回收），次选 `tailscale funnel`。

## 快速上手

### 1. 构建（或从 Releases 下载）

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. 交互式初始化

只需初始化一次，配置穿透方案（首选 `cloudflared`、次选 `tailscale funnel`）、`public_url` 与管理员口令（无需写死工作区和权限）：

```bash
wsbridge init
```

如需脚本化生成示例配置后再手动编辑：

```bash
wsbridge init --non-interactive
wsbridge passwd
```

### 3. 启动、热切换项目与自检

```bash
# 在任意项目目录直接启动：
cd /path/to/project-a
wsbridge serve

# 另开终端切到其他项目目录，热切换活跃工作区（远端免重连）：
cd /path/to/project-b
wsbridge use

# 查看当前活跃工作区：
wsbridge use --show

# 检查本地配置、托管隧道与公网连通性：
wsbridge doctor --timeout 10s
```

如需以用户级后台服务常驻运行（systemd / launchd / Windows Service）：

```bash
wsbridge service install
wsbridge service start
# 常驻后在任意项目目录执行 wsbridge use 即可秒切工作区
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
