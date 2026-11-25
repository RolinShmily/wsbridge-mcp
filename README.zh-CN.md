# wsbridge

[English](README.md) | **简体中文**

## 这是什么？

`wsbridge` 是一座面向单用户的本地工作区安全桥接服务，供 **ChatGPT、Gemini、Claude** 使用。它以**单个静态 Go 二进制**（`CGO_ENABLED=0`）运行在 Windows / macOS / Linux 上，内置：

- **OAuth 2.1 授权服务** —— 让 AI 平台通过各自标准的自定义连接器流程（发现 → DCR → PKCE S256 → 同意页）完成对你的本机鉴权，无需任何外部 IdP；
- **Streamable HTTP MCP 端点**（`<public_url>/mcp`）—— 暴露一组刻意收窄的工具（读 / 搜索 / 编辑 / 写入 / 运行内置项目检查），AI 模型只能安全地操作你当前的工作区；
- **`os.Root` 内核级沙盒** —— 阻断路径穿越与符号链接逃逸，默认屏蔽 `.git`、`.ssh`、`.env`、私钥等敏感文件。

控制权始终在你手上：工作区跟随你执行 `wsbridge serve` 的目录（并可随时用 `wsbridge use` 热切换），每条连接的最大权限在浏览器同意页选择，断开重连即可随时调整。**不暴露任何 Shell 执行与网络请求工具。**

## 你需要准备什么？

- **Go ≥ 1.25** 用于源码构建（或从 Releases 直接下载发布包）。
- 一个**稳定的公网 HTTPS 地址** —— 平台云端必须能访问到你。推荐方案：
  - **Tailscale Funnel**（首选）：`tailscale funnel --bg 8787`
  - **Cloudflare Named Tunnel**：固定 `cloudflared` 二级域名
  - **ngrok 静态域名**：`ngrok http --domain=<static-domain> 8787`

  > 切勿使用随机临时域名（如 `*.trycloudflare.com`）：URL 变更会导致所有已连接的连接器全部失效。

## 怎么用

### 1. 构建

```bash
CGO_ENABLED=0 go build -o wsbridge ./cmd/wsbridge
```

### 2. 初始化一次

`wsbridge init` 负责配置穿透方案（首选 `cloudflared`、次选 `tailscale funnel`）、`public_url` 与管理员口令：

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

### 常用命令

```bash
wsbridge grants list                  # 查看当前 Grant 列表
wsbridge grants revoke <grant_id>     # 立即吊销指定 Grant
wsbridge grants revoke --all          # 吊销全部 Grant
wsbridge grants prune                 # 清理过期 Grant 与陈旧客户端
wsbridge serve --debug-oauth          # 脱敏输出 OAuth/MCP 调试日志
```

## 文档

`docs/` 目录共四份自包含规格：

| 文件 | 内容 |
| :--- | :--- |
| **[architecture.md](docs/architecture.md)** | 系统总体架构、OAuth 2.1 与 Grant 模型、MCP/沙盒设计、部署与威胁模型 |
| **[reference.md](docs/reference.md)** | OAuth 端点报文、MCP 工具 Schema、CLI 与 `config.toml`、各平台接入细节与实测记录 |
| **[development.md](docs/development.md)** | 编码规范、仓库/模块契约、测试与 CI、M0–M7 里程碑 |
| **[design.md](docs/design.md)** | OAuth 同意页 UI 与表单契约 |

另见：[CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md)

## 开源协议与作者

- 协议：[MIT](LICENSE)
- 作者：RoL1n_SrP (`contact@srprolin.com`)