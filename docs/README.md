# wsbridge 工程规格文档体系（docs/）

> **调研基准时间**：2026-11 ｜ **目标语言**：Go ≥ 1.25（`CGO_ENABLED=0`） ｜ **平台优先级**：ChatGPT → Gemini → Claude

本目录是 `wsbridge` 项目的唯一权威设计与开发规格书（Single Source of Truth）。文档按 **Architecture（架构）**、**Development（开发）**、**Reference（参考契约）**、**Design（前端设计）** 四个维度组织，可直接交由实现 Agent 按里程碑分阶段开发与验收。

---

## 目录结构索引

### 1. 架构设计（`docs/architecture/`）
| 文档 | 核心内容 |
| :--- | :--- |
| [01-system-overview.md](architecture/01-system-overview.md) | 总体拓扑、三平台协议交集（Streamable HTTP + OAuth 2.1 + DCR + PKCE S256）、信任边界与目标/非目标 |
| [02-oauth-and-grant-model.md](architecture/02-oauth-and-grant-model.md) | 内置 OAuth 2.1 授权服务状态机、`bbolt` 数据模型、“授权即 Grant”最小权限绑定、Token 轮换 30s 宽限期与重放撤销 |
| [03-mcp-and-workspace-sandbox.md](architecture/03-mcp-and-workspace-sandbox.md) | `go-sdk` Streamable HTTP 集成、`os.OpenRoot` 沙盒边界、Windows 保留字/ADS 防御、敏感文件拦截、原子写入与外部快照 |
| [04-deployment-and-security.md](architecture/04-deployment-and-security.md) | 威胁模型与纵深防御、公网隧道稳定性要求（Tailscale Funnel / Cloudflare Tunnel / ngrok）、用户级服务化与 `doctor` 诊断 |

### 2. 开发规范（`docs/development/`）
| 文档 | 核心内容 |
| :--- | :--- |
| [01-coding-standards.md](development/01-coding-standards.md) | Go 1.25 编码规范、依赖白名单硬约束、零框架 `net/http` 路由防坑、日志脱敏中间件与并发安全规范 |
| [02-repository-and-modules.md](development/02-repository-and-modules.md) | 标准仓库目录树、各 `internal/*` 包职责边界与核心 Go 接口/结构体契约 |
| [03-testing-and-ci.md](development/03-testing-and-ci.md) | 安全与边界单元测试矩阵、无平台依赖的 `e2e/` 全链路测试客户端、`--debug-oauth` 抓包排查与三平台 CI |
| [04-milestones-and-tasks.md](development/04-milestones-and-tasks.md) | M0–M7 可独立拆分的 Agent 任务书、前置条件、具体代码交付物与可量化验收标准 |

### 3. 参考规范（`docs/reference/`）
| 文档 | 核心内容 |
| :--- | :--- |
| [01-oauth-endpoints-spec.md](reference/01-oauth-endpoints-spec.md) | RFC 9728 / 8414 / 7591 / 7009 / 9207 / 8707 全部 HTTP 端点请求/响应 JSON 样例、HTTP 状态码与错误码表 |
| [02-mcp-tools-schema.md](reference/02-mcp-tools-schema.md) | 全部 MCP 工具的输入 JSON Schema、`annotations`、多工作区参数解析、64KB 截断规则与可操作错误文案模板 |
| [03-cli-and-config-spec.md](reference/03-cli-and-config-spec.md) | `config.toml` 完整字段说明、CLI 子命令（`serve` / `init` / `passwd` / `grants` / `doctor` / `service`）参数与退出码 |
| [04-platform-quirks-matrix.md](reference/04-platform-quirks-matrix.md) | ChatGPT、Gemini（Spark）、Claude 接入路径、认证差异、已知平台坑点（`【待实测】` 项）与验收回写模板 |

### 4. 前端设计规范（`docs/design/`）
| 文档 | 核心内容 |
| :--- | :--- |
| [01-oauth-consent-ui.md](design/01-oauth-consent-ui.md) | `internal/oauth/consent.html` 授权同意页布局、防钓鱼视觉锚点、严苛 CSP 策略、表单字段契约与状态反馈设计 |

---

## 里程碑执行路线图

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
