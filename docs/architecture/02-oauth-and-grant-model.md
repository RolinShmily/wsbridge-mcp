# 02. 内置 OAuth 2.1 与 Grant 权限模型

## 1. 核心概念模型

`wsbridge` 将标准 OAuth 2.1 授权流程与本地工作区访问控制深度融合，核心实体关系如下：

```text
[OAuth Client (DCR 注册)] 1 ──── * [Grant (用户授权实例)] 1 ──── * [Token (Access / Refresh)]
                                        │
                                        ├── 绑定 issuer (public_url)
                                        ├── 绑定 allowed_workspaces: map[name]Permission
                                        ├── 绑定 expires_at (授权总有效期)
                                        └── 绑定 revoked (是否已吊销)
```

### 1.1 Issuer 强绑定原则
- `issuer` 严格等于配置文件中的 `public_url`（去除末尾斜杠，例如 `https://my-box.tail1234.ts.net`）。
- 所有元数据端点、授权端点、令牌端点及 `resource`（`issuer + "/mcp"`）均由该 `issuer` 派生。
- **变更失效机制**：启动时校验 `bbolt` 中记录的 `system_meta.issuer` 是否与当前配置的 `public_url` 一致。若发生变更：
  1. 自动将旧 `issuer` 下所有历史 `Grant` 与 `Token` 标记为失效（或清空旧授权表）；
  2. 更新 `system_meta.issuer` 为新值；
  3. 在启动日志输出醒目 `WARN` 提示，告知用户需在 AI 平台重新连接。

---

## 2. 完整授权生命周期状态机

### 阶段一：资源发现与动态客户端注册（DCR）
1. AI 平台首次访问 `POST /mcp`（无令牌）→ 收到 `401 Unauthorized` 及响应头：
   `WWW-Authenticate: Bearer resource_metadata="https://<public_url>/.well-known/oauth-protected-resource/mcp"`
2. 平台请求 `GET /.well-known/oauth-protected-resource/mcp`（RFC 9728），获取 `authorization_servers: ["https://<public_url>"]`。
3. 平台请求 `GET /.well-known/oauth-authorization-server`（RFC 8414），获取 `registration_endpoint`、`authorization_endpoint`、`token_endpoint` 等元数据。
4. 平台调用 `POST /oauth/register`（RFC 7591）：
   - 校验 `token_endpoint_auth_method` 必须为 `"none"`（若省略则默认为 `"none"`）；
   - 校验 `redirect_uris` 非空且数量 $\le 10$；
   - 逐条校验 `redirect_uri`：协议必须为 `https`（回环地址 `localhost` / `127.0.0.1` / `[::1]` 允许 `http`），且 Host 必须命中白名单；
   - 若总数已达 `200` 上限，先清理超过 24 小时未产生任何有效 Grant 的僵尸 Client；若仍满则返回 `429` 或 `400`；
   - 生成随机 `client_id`（前缀 `wsb_cli_`）写入 `bbolt` 的 `clients` bucket，返回 `201 Created`。

### 阶段二：用户同意页与授权码签发
1. 平台引导用户浏览器跳转至 `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...&resource=...&scope=...`。
2. 服务端执行前置参数校验（**任何一项失败均直接渲染错误页，绝不重定向至未验证的 `redirect_uri`**）：
   - `client_id` 必须存在于 `bbolt`；
   - `redirect_uri` 必须与该 Client 注册列表中的某一项**字节级完全一致**；
   - `response_type` 必须为 `"code"`；
   - `code_challenge_method` 必须为 `"S256"`，且 `code_challenge` 长度合法（43–128 字符 Base64URL）；
   - 若携带 `resource` 参数，其值必须严格等于 `public_url + "/mcp"`（否则返回 `invalid_target`）。
3. 服务端生成一次性 CSRF Token（写入内存或签名 Cookie，绑定当前表单会话），渲染 `consent.html`。
4. 用户在浏览器确认连接权限级别（默认全开 `check`）、授权有效期（默认 30 天）并提交本机管理员口令（`POST /oauth/authorize`）：
   - 校验防暴力破解锁定状态：连续口令错误达 **5 次**，全局锁定授权提交 **5 分钟**（返回 HTTP 429 与剩余秒数）；
   - 校验 CSRF Token；
   - 使用 `argon2.IDKey` 对比口令哈希；
   - 默认签发动态通配工作区授权（`workspaces: {"*": perm}`），使连接自动跟随本机当前活跃工作区（兼容历史显式指定工作区名的 Grant）；
   - 创建 `Grant` 持久化至 `bbolt`；将对应 `client_id` 标记为“已激活”（免受 24h 僵尸清理）；
   - 生成 **32 字节密码学随机授权码**（Base64URL 编码），存入**纯内存映射表**（不落盘），TTL = **60 秒**；
   - 返回 `302 Found` 重定向至 `redirect_uri?code=<CODE>&state=<STATE>&iss=<URL_ENCODED_ISSUER>`（遵循 RFC 9207）。

### 阶段三：令牌换取与刷新轮换（含 30s 宽限期）
1. 平台后端调用 `POST /oauth/token`（`grant_type=authorization_code`）：
   - 原子取出并删除内存中的授权码记录；
   - **重放检测**：若该 `code` 已被标记为 `used`（在保留的 5 分钟已用黑名单窗口内再次出现），立即判定为重放攻击，**级联吊销该 `code` 此前签发的所有 Token 与对应 Grant**，返回 `400 invalid_grant`；
   - 校验 `client_id`、`redirect_uri` 与授权时完全一致；
   - 校验 `resource`（若提供）等于 `public_url + "/mcp"`；
   - 计算 `BASE64URL(SHA256(code_verifier)) == code_challenge`（常量时间比较 `subtle.ConstantTimeCompare`）；
   - 签发 `access_token`（TTL = **1 小时**）与 `refresh_token`（TTL = **30 天**），均生成 32 字节随机串，仅将 `SHA-256` 哈希存入 `bbolt` 的 `tokens` bucket；
   - **无论请求是否包含 `offline_access`，响应中始终返回 `refresh_token`**。
2. 平台后续调用 `POST /oauth/token`（`grant_type=refresh_token`）：
   - 计算传入 `refresh_token` 的 SHA-256 哈希并在 `bbolt` 中检索；
   - 检查关联 `Grant` 是否未过期且未被吊销；
   - **正常首次轮换**（`rotated_at` 为零值）：
     - 生成新一对 `(new_access_token, new_refresh_token)` 写入 `bbolt`；
     - 将旧 `refresh_token` 记录标记为 `rotated_at = now`，并记录 `replaced_by_access_hash` 与 `replaced_by_refresh_hash`（或短期内存缓存明文对 30 秒，仅用于应对网络抖动导致的并发重试）；
     - 立即使旧 `access_token` 失效，返回新令牌对。
   - **宽限期内并发重复刷新**（`now - rotated_at <= 30s`）：
     - 视为同一客户端并发请求竞态，不报错、不吊销，幂等返回该次轮换生成的同一对新令牌。
   - **宽限期外重放刷新**（`now - rotated_at > 30s`）：
     - 判定为令牌泄露重放，**立即吊销整个 `Grant` 及其名下所有令牌**，返回 `400 invalid_grant`。

---

## 3. `bbolt` 存储结构设计（`wsbridge.db`）

数据库文件位于 `<data_dir>/wsbridge.db`（文件权限 `0600`），按以下 Bucket 划分：

| Bucket 名称 | Key | Value (JSON 编码) | 说明 |
| :--- | :--- | :--- | :--- |
| `meta` | `"schema_version"`, `"issuer"`, `"admin_pass_hash"` | 字符串 / 字节 | 存储 Schema 版本、当前 `public_url`、argon2id 口令哈希 |
| `clients` | `client_id` (`wsb_cli_...`) | `ClientRecord` | `client_name`, `redirect_uris`, `application_type`, `created_at`, `activated` |
| `grants` | `grant_id` (`wsb_grt_...`) | `GrantRecord` | `client_id`, `client_name`, `scopes`, `workspaces` (权限映射), `created_at`, `expires_at`, `revoked` |
| `tokens` | `token_sha256_hex` | `TokenRecord` | `token_type` (`access`/`refresh`), `grant_id`, `client_id`, `resource`, `expires_at`, `rotated_at`, `revoked` |
| `audit_index` | 保留 | — | 审计日志主存为 JSONL 文件，不膨胀 `bbolt` |

### 后台定期清理任务（GC Goroutine）
服务启动后每 **10 分钟**运行一次后台清理事务：
1. 删除 `clients` 中 `activated == false` 且 `now - created_at > 24h` 的未完成注册客户端；
2. 删除 `tokens` 中 `expires_at < now` 且非宽限期内的过期令牌记录；
3. 标记 `grants` 中 `expires_at < now` 的授权为已过期（保留记录供 `grants list` 审计查看，支持 `grants prune` 物理清理）。

---

## 4. Grant 权限计算规则

权限严格遵循**全序集**：

`none (0) < read (1) < write (2) < check (3)`

- 高级别权限自动包含低级别权限（例如 `check` 包含 `write` 与 `read`；`write` 包含 `read`）。
- 单次工具调用时的**有效权限（Effective Permission）**计算公式为：
  - 本地全局配置默认不设限制（等同 `check`）；如显式配置了更低的全局 `max_perm`、工作区 `max_perm` 或启动参数 `--max-perm`，则按两者最小值收敛：
  `EffectivePerm(w) = min(LocalMaxPerm(w), GrantPerm)`
- 当 Grant 包含通配键 `"*"` 时，自动作用于服务端当前活跃的所有工作区（随 `wsbridge serve [dir]` 或 `wsbridge use [dir]` 实时变化，无需重连 OAuth）；如需更改连接权限，断开连接重新授权即可。
- 若当前无活跃工作区或 `EffectivePerm(w) < Tool.RequiredPerm`，则立即拒绝工具调用并返回清晰的权限或工作区提示。
