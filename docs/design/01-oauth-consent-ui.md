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
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'
```

- **禁止任何外链**：不加载 Google Fonts、不加载外部 CSS/JS CDN、不加载外部图片（图标统一使用内联 SVG）。
- **纯原生表单提交**：页面不依赖 JavaScript 即可完成全部选择与提交（纯 HTML `<form method="POST" action="/oauth/authorize">`），确保在任何内置浏览器 WebView（ChatGPT/Claude 移动端或桌面端内嵌浏览器）中 100% 稳定工作。

---

## 2. 信息架构与防钓鱼视觉设计

页面采用居中单卡片布局（最大宽度 `480px`，适配桌面端与手机竖屏 WebView），按**自上而下的信任确认流**排列：

```text
┌──────────────────────────────────────────────────────────┐
│  [盾牌 SVG] Authorize wsbridge                           │
├──────────────────────────────────────────────────────────┤
│  Requesting Application（防钓鱼核心区块）                  │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Client:           Claude                           │  │
│  │ Callback host:    claude.ai (完整地址折叠可见)        │  │
│  │ Active workspace: myapp (随本地切换动态跟随)         │  │
│  │ Scopes:           mcp:tools  offline_access        │  │
│  └────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────┤
│  1. Connection Permission（决定本连接最大权限）            │
│     (•) Full access (check) — 读写 + 内置检查 [Default]   │
│     ( ) Read + write (write) — 编辑与新建文件（写前快照）  │
│     ( ) Read only (read) — 仅浏览、搜索与读取             │
├──────────────────────────────────────────────────────────┤
│  2. Lifetime                                             │
│     [ 30 days (Default) ▼ ] (1h / 24h / 7d / 30d)        │
├──────────────────────────────────────────────────────────┤
│  3. Administrator Passphrase                             │
│     [ •••••••••••••••••••• ]                             │
│     (错误提示/锁定倒计时横幅位置)                          │
├──────────────────────────────────────────────────────────┤
│  [ Approve and connect ]                                 │
│  [ Deny and close ]                                      │
└──────────────────────────────────────────────────────────┘
```

### 视觉与交互细节规范
1. **极简授权流**：默认选中 `Full access (check)` 与 `30 days`，自动签发动态通配工作区授权（`*`），用户输入管理员口令点击确认即可完成连接；需要调整权限时在 AI 平台断开并重新授权。
2. **主题自适应**：使用 CSS `@media (prefers-color-scheme: dark)` 自动适配浅色与深色模式。
3. **本地上限提示**：当本地服务端配置了低于 `check` 的 `max_perm` 时，页面提示当前本地上限，运行时自动按 `min(local_cap, grant_perm)` 收敛。

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
