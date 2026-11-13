# 01. OAuth 授权同意页前端设计规范（`consent.html`）

## 1. 设计目标与安全约束

`internal/oauth/consent.html` 是整个系统唯一面向人类用户的图形界面，通过 Go `//go:embed` 直接内嵌进二进制文件，无需任何外部静态资源目录。

### 1.1 零外链与严苛 CSP 策略
为防止恶意工作区或网络中间人注入脚本窃取口令或 CSRF Token，响应 `GET /oauth/authorize` 时必须下发以下 HTTP 安全响应头：

```http
Content-Type: text/html; charset=utf-8
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
```

- **禁止任何外链**：不加载 Google Fonts、不加载外部 CSS/JS CDN、不加载外部图片（图标统一使用内联 SVG）。
- **纯原生表单提交**：页面不依赖 JavaScript 即可完成全部选择与提交（纯 HTML `<form method="POST" action="/oauth/authorize">`），确保在任何内置浏览器 WebView（ChatGPT/Claude 移动端或桌面端内嵌浏览器）中 100% 稳定工作。

---

## 2. 信息架构与防钓鱼视觉设计

页面采用居中单卡片布局（最大宽度 `480px`，适配桌面端与手机竖屏 WebView），按**自上而下的信任确认流**排列：

```text
┌──────────────────────────────────────────────────────────┐
│  [盾牌 SVG] wsbridge 本地工作区安全授权                    │
├──────────────────────────────────────────────────────────┤
│  应用来源核验（防钓鱼核心区块 — 高对比度边框提示）           │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 请求应用:  Claude                                   │  │
│  │ 回调域名:  claude.ai  (完整地址悬停/折叠可见)         │  │
│  │ 请求权限:  mcp:tools  offline_access                │  │
│  └────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────┤
│  1. 选择允许访问的工作区（至少勾选 1 项）                  │
│     [✓] myapp      (配置上限: write)                     │
│     [ ] notes      (配置上限: read)                      │
├──────────────────────────────────────────────────────────┤
│  2. 授予本次会话的最高权限级别                             │
│     (•) 只读 (read)   — 仅浏览目录、搜索与读取文件 [推荐]   │
│     ( ) 读写 (write)  — 允许编辑与新建文件（自动写前快照）  │
│     ( ) 读写+检查 (check) — 额外允许运行白名单检查命令      │
├──────────────────────────────────────────────────────────┤
│  3. 授权有效期                                            │
│     [ 7 天 (默认) ▼ ]  (可选: 1 小时 / 24 小时 / 7 天 / 30 天) │
├──────────────────────────────────────────────────────────┤
│  4. 输入本机 wsbridge 管理员口令                          │
│     [ •••••••••••••••••••• ]                             │
│     (错误提示/锁定倒计时横幅位置)                          │
├──────────────────────────────────────────────────────────┤
│  [ 拒绝并关闭 ]                    [ 确认授权并连接 ]      │
└──────────────────────────────────────────────────────────┘
```

### 视觉与交互细节规范
1. **主题自适应**：使用 CSS `@media (prefers-color-scheme: dark)` 自动适配浅色与深色模式，确保与 Claude / ChatGPT 桌面暗色主题视觉协调。
2. **风险分级色彩语义**：
   - `read` 徽章使用中性蓝/绿色调并标注“推荐”；
   - `write` 徽章使用琥珀色警告色调，提示将允许修改文件；
   - `check` 徽章使用橙红色高危提示色调，明确告知可触发配置白名单内的本地命令执行。
3. **有效权限计算兜底提示**：当用户勾选了 `max_perm = "read"` 的工作区但全局权限选择了 `write` 时，界面文案明确说明“每个工作区的实际生效权限不会超过服务端配置文件中的 `max_perm` 上限”。

---

## 3. 前后端表单字段契约（`html/template`）

### 3.1 服务端渲染模板数据结构
```go
type ConsentPageData struct {
    ClientName      string
    RedirectHost    string
    RedirectURI     string
    RequestedScopes []string
    AuthRequestID   string // 关联内存中的授权请求上下文（含 client_id, redirect_uri, code_challenge, state, resource）
    CSRFToken       string
    Workspaces      []ConsentWorkspaceItem
    ErrorMessage    string // 口令错误、未选工作区或锁定提示
    LockedSeconds   int    // >0 时禁用提交按钮并显示剩余锁定秒数
}

type ConsentWorkspaceItem struct {
    Name    string
    Path    string
    MaxPerm string // "read" | "write" | "check"
    Checked bool
}
```

### 3.2 `POST /oauth/authorize` 表单提交字段
| 表单 `name` | 类型 | 说明 |
| :--- | :--- | :--- |
| `auth_req_id` | `hidden` | 绑定当前一次授权请求的临时服务端上下文 ID（有效期 10 分钟，单次消费） |
| `csrf_token` | `hidden` | 与服务端会话绑定的随机 CSRF 令牌 |
| `action` | `submit` | `"approve"`（确认授权）或 `"deny"`（拒绝授权，服务端重定向回 `redirect_uri?error=access_denied&state=...&iss=...`） |
| `workspaces` | `checkbox[]` | 用户勾选的一个或多个工作区 `name` |
| `permission` | `radio` | `"read"` / `"write"` / `"check"` |
| `ttl_hours` | `select` | `"1"` / `"24"` / `"168"`（7 天）/ `"720"`（30 天） |
| `passphrase` | `password` | 用户输入的管理员明文口令（服务端立即执行 argon2id 校验，绝不落盘或打印日志） |
