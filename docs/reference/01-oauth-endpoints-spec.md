# 01. OAuth 2.1 端点与报文参考规范

> 设配置项 `public_url = "https://my-box.tail1234.ts.net"`，则 `issuer = "https://my-box.tail1234.ts.net"`，`mcp_url = "https://my-box.tail1234.ts.net/mcp"`。

---

## 1. 受保护资源元数据（RFC 9728）

### 请求
- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-protected-resource/mcp`

### 响应（`200 OK`, `Content-Type: application/json; charset=utf-8`）
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

### 未授权 `/mcp` 响应（`401 Unauthorized`）
任意未携带有效 `Bearer` 令牌的 `/mcp` 或 `/mcp/` 请求必须返回：
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://my-box.tail1234.ts.net/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json; charset=utf-8
Cache-Control: no-store

{"error":"invalid_token","error_description":"missing or invalid bearer token"}
```

---

## 2. 授权服务器元数据（RFC 8414）

### 请求
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`（同内容别名，兼容部分 OIDC 发现客户端）

### 响应（`200 OK`, `Content-Type: application/json; charset=utf-8`）
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

---

## 3. 动态客户端注册（RFC 7591 DCR）

### 请求：`POST /oauth/register`
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

### 校验规则与错误码
1. `redirect_uris` 为空或超过 **10** 条 → `400 invalid_redirect_uri`。
2. 任一 `redirect_uri` 非法、含片段 `#`、非 `https`（回环地址 `127.0.0.1` / `localhost` / `[::1]` 除外）或 Host 未命中白名单 → `400 invalid_redirect_uri`（服务端日志记录完整被拒 URI）。
3. `token_endpoint_auth_method` 若传入且不等于 `"none"` → `400 invalid_client_metadata`。
4. 已注册 Client 总数达 `200` 且清理过期未激活 Client 后仍满 → `429` 或 `400 invalid_client_metadata`。

### 默认 Redirect Host 白名单
- `chatgpt.com`
- `platform.openai.com`
- `claude.ai`
- `claude.com`
- `oauth-redirect.googleusercontent.com`
- `oauth-redirect-sandbox.googleusercontent.com`
- `oauth-redirect-test.googleusercontent.com`
- `localhost`、`127.0.0.1`、`[::1]`（任意端口）
- 外加配置文件 `allow_redirect_hosts` 中的精确域名。

### 成功响应（`201 Created`）
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

---

## 4. 授权端点（`GET` & `POST /oauth/authorize`）

### 4.1 `GET /oauth/authorize` 查询参数
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

### 4.2 `POST /oauth/authorize` 表单提交与成功回调
用户提交同意表单且校验通过后，服务端返回 `302 Found`：
```http
HTTP/1.1 302 Found
Location: https://claude.ai/api/mcp/auth_callback?code=<32B_RANDOM_B64URL>&state=<ORIGINAL_STATE>&iss=https%3A%2F%2Fmy-box.tail1234.ts.net
Cache-Control: no-store
```

---

## 5. 令牌端点（`POST /oauth/token`）

请求体支持 `application/x-www-form-urlencoded`（标准强制要求）。

### 5.1 授权码换令牌（`grant_type=authorization_code`）
**请求参数**：`grant_type`、`code`、`redirect_uri`、`client_id`、`code_verifier`、可选 `resource`。

**成功响应（`200 OK`）**：
```json
{
  "access_token": "wsb_at_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "wsb_rt_...",
  "scope": "mcp:tools offline_access"
}
```

### 5.2 刷新令牌轮换（`grant_type=refresh_token`）
**请求参数**：`grant_type`、`refresh_token`、可选 `client_id`、可选 `resource`。

**行为约束**：
- 首次轮换：生成新 `access_token`（3600s）与新 `refresh_token`（30d），旧 `refresh_token` 进入 30 秒宽限期；
- 30s 宽限期内重复提交同一旧 `refresh_token`：幂等返回相同的 `200 OK` JSON；
- 超过 30s 再次提交旧 `refresh_token`：触发重放撤销整个 Grant，返回 `400 {"error":"invalid_grant","error_description":"refresh token replay detected"}`。

---

## 6. 令牌撤销端点（RFC 7009 `POST /oauth/revoke`）

- **请求参数**：`token`（必填）、`token_type_hint`（可选 `access_token` 或 `refresh_token`）。
- **行为**：若 `token` 命中库中有效记录，则将对应 `Grant` 及其名下全部 `access_token` / `refresh_token` 标记为 `revoked = true`；无论令牌是否存在或已过期，按 RFC 7009 规范统一返回 `200 OK`（空响应体）。
