# 04. 部署架构、隧道选型与安全模型

## 1. 公网隧道拓扑与稳定性要求

由于 ChatGPT、Gemini、Claude 的工具调用均由**云端服务器**发起（而非用户本地浏览器直接请求 `127.0.0.1`），`wsbridge` 必须通过 HTTPS 反向隧道暴露至公网。

### 1.1 公网 URL 稳定性铁律
- `issuer`、DCR 注册的 `client_id`、用户签发的 `Grant` 以及 Token 均与 `public_url` 强绑定。
- **严禁在日常使用中使用随机临时域名**（如 Cloudflare Quick Tunnel `*.trycloudflare.com`），因为每次重启隧道域名都会改变，导致所有已绑定的 AI 平台连接器全部失效。

### 1.2 推荐隧道方案对比

| 方案 | 域名特征 | 配置要点 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **Tailscale Funnel**（首选） | 固定 `https://<node>.<tailnet>.ts.net` | `tailscale funnel --bg 8787`；零公网 IP 要求，自动签发 Let's Encrypt 证书 | 个人开发机、家庭服务器（Linux/macOS/Windows） |
| **Cloudflare Named Tunnel** | 自有二级域名 `https://ws.example.com` | `cloudflared tunnel run` 指向 `http://127.0.0.1:8787`；关闭任何强制重定向页面规则 | 已有 Cloudflare 托管域名的用户 |
| **ngrok 静态域名** | 免费/付费固定 `*.ngrok-free.app` | `ngrok http --domain=<static-domain> 8787` | 快速跨网络验证 |

> **关键配置提醒**：无论使用何种隧道，务必确保隧道层**不会对 `/.well-known/*` 或 `/mcp` 返回 301/302 重定向（如 HTTP→HTTPS 跳转或末尾斜杠补全）**，否则 Claude 云端运行时会丢弃 `Authorization` 头。

---

## 2. 威胁模型与纵深防御矩阵

| 威胁类别 | 攻击向量 | 防御机制 |
| :--- | :--- | :--- |
| **公网扫描与 DoS** | 恶意爬虫枚举端点或发送超大请求体耗尽内存 | 1. 进程默认仅监听 `127.0.0.1:8787`；<br>2. 除元数据与 `/oauth/*` 外所有路径强制 Bearer 校验；<br>3. 全局请求体硬限制 `1MB`（`http.MaxBytesReader`）；<br>4. 读写与空闲超时（`ReadHeaderTimeout: 10s`, `IdleTimeout: 120s`）；<br>5. 每令牌限流 `120 req/min`。 |
| **授权页钓鱼与 CSRF** | 恶意网站诱导用户打开 `/oauth/authorize` 授权给恶意回调域 | 1. DCR 严格校验 `redirect_uri` Host 白名单；<br>2. 同意页醒目展示 Client 名称与回调域名；<br>3. 表单强制校验一次性 CSRF Token；<br>4. 设置 `X-Frame-Options: DENY` 与 `CSP: frame-ancestors 'none'` 防止点击劫持；<br>5. 口令采用 `argon2id` 校验，连续失败 5 次锁定 5 分钟。 |
| **令牌窃取与重放** | 日志泄露、网络抓包重放授权码或刷新令牌 | 1. 内存授权码仅存活 60s 且单次有效，重放即级联吊销全部关联令牌；<br>2. `access_token` 仅存活 1h；<br>3. `refresh_token` 每次轮换，超过 30s 宽限期重放立即吊销整个 Grant；<br>4. `bbolt` 仅存储 Token 的 SHA-256 哈希；<br>5. 全链路日志中间件自动脱敏敏感头与字段。 |
| **间接提示词注入 (IPI)** | 仓库 README 或代码注释中包含恶意指令，诱导 AI 读取密钥或外泄代码 | 1. **无 Shell、无网络工具**：AI 无法执行 `curl`/`bash` 主动外传；<br>2. **默认敏感名单**：`.env`、`.ssh`、`.git`、私钥在沙盒层彻底不可见；<br>3. **最小授权**：建议日常使用仅授予 `read` 权限，仅在需要修改代码时临时授权 `write`；<br>4. **安全告知**：文档明确提示若网页端同时开启网页浏览或其他连接器，存在组合外泄风险。 |
| **AI 误删改文件** | 模型幻觉导致大面积覆盖代码 | 1. `write_file` 覆盖已有文件强制校验 `expected_sha256`；<br>2. 所有写操作前自动备份快照至 `data_dir/snapshots/`；<br>3. `edit_file` 默认要求 `old_text` 唯一匹配；<br>4. `doctor` 检查工作区是否为 Git 仓库并给出建议。 |
| **高权限账号启动风险** | 用户误用 `sudo` 或 `Administrator/SYSTEM` 运行服务，扩大潜在风险 | 检测到 `uid == 0`（Unix）或 `SYSTEM` 账户（Windows）时**直接拒绝启动**，除非用户显式传入 `--i-know-what-i-am-doing`。 |

---

## 3. 自检诊断（`wsbridge doctor`）

`wsbridge doctor` 通过读取本地配置并向 `public_url` 发起真实公网探测，验证端到端连通性与协议合规性：

1. **本地环境检查**：
   - 配置文件语法与工作区路径存在性；
   - 口令哈希是否已初始化（`passwd`）；
   - 各工作区是否包含 `.git`（未初始化 Git 时输出 `WARN` 建议）；
   - 检查本机是否安装 `rg`（未安装时提示将使用纯 Go 搜索回退）。
2. **公网链路与零重定向检查**：
   - 使用配置了 `CheckRedirect: func(...) error { return http.ErrUseLastResponse }` 的 HTTP 客户端请求公网端点；
   - `GET <public_url>/.well-known/oauth-protected-resource/mcp` → 必须返回 `200`，且 JSON 内 `resource == public_url + "/mcp"`；
   - `GET <public_url>/.well-known/oauth-authorization-server` → 必须返回 `200`，且 `issuer == public_url`；
   - `POST <public_url>/mcp`（无令牌）→ 必须返回 `401`（**严禁 301/302**），且 `WWW-Authenticate` 头包含正确的 `resource_metadata` URL；
   - `POST <public_url>/mcp/`（无令牌）→ 必须同样返回 `401` 而非重定向；
   - `POST <public_url>/oauth/register`（发送探测性 DCR 请求后立即清理或验证格式）→ 验证 DCR 端点公网可达。

---

## 4. 审计日志规范（`audit.jsonl`）

所有安全敏感操作均以单行 JSON 追加写入 `<data_dir>/audit.jsonl`（权限 `0600`）：

```json
{
  "ts": "2026-11-13T10:15:30.123Z",
  "event": "tool_call",
  "grant_id": "wsb_grt_9f8a7b6c",
  "client_id": "wsb_cli_1a2b3c4d",
  "tool": "edit_file",
  "workspace": "myapp",
  "path": "internal/auth/handler.go",
  "status": "ok",
  "snapshot": "wsb_grt_9f8a7b6c/20261113-101530.120/myapp/internal/auth/handler.go",
  "duration_ms": 4
}
```

记录的事件类型（`event`）包括：`dcr_register`、`authorize_attempt`（含失败锁定记录，绝不含口令）、`token_issue`、`token_refresh`、`token_replay_revoked`、`grant_revoke`、`tool_call`、`sandbox_blocked`。
