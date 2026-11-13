# 03. MCP 协议集成与工作区沙盒（Sandbox）

## 1. Streamable HTTP 与鉴权上下文传递

### 1.1 SDK 配置要求
使用 `github.com/modelcontextprotocol/go-sdk` 暴露 MCP 端点时，必须遵守以下配置：
- **关闭 Host 头校验**：设置 `DisableLocalhostProtection: true`。原因：云端平台经由 Tailscale Funnel / Cloudflare Tunnel / ngrok 访问本地时，HTTP 请求的 `Host` 头为公网域名（如 `my-box.tail1234.ts.net`），若开启 SDK 默认的 localhost 保护会直接返回 `403 Forbidden`。
- **传输端点双注册**：`/mcp` 与 `/mcp/` 必须分别显式注册到同一个 `mcp.StreamableHTTPHandler` 实例，彻底消除 `ServeMux` 的 301 重定向。
- **Bearer 鉴权包装器**：在进入 `StreamableHTTPHandler` 之前，由 `internal/mcpsrv` 的鉴权中间件执行：
  1. 提取 `Authorization: Bearer <token>`（缺失或格式错误返回 `401` + `WWW-Authenticate` 头）；
  2. 计算 `SHA-256(token)` 并查询 `bbolt`：验证令牌存在、类型为 `access`、未过期、未吊销；
  3. 校验令牌绑定的 `resource == public_url + "/mcp"`；
  4. 校验关联的 `Grant` 未过期且未吊销；
  5. 检查令牌级限流器（每令牌每分钟最多 120 次请求，超限返回 `429 Too Many Requests` + `Retry-After`）；
  6. 使用 SDK 的 `auth` 包将包含 `GrantID` 与 `ClientID` 的 `*auth.TokenInfo` 注入 `r.Context()`，供工具 Handler 通过请求的 `Extra.TokenInfo` 提取。

> **实现注意**：编码前务必检查 `go.mod` 锁定的 `go-sdk` 版本的 `mcp` 与 `auth` 包源码，确认 `StreamableHTTPHandler` 与 `TokenInfo` 的精确签名，严禁凭旧版本记忆编写。

---

## 2. 工作区沙盒（`internal/ws`）

### 2.1 Go 1.25 `os.Root` 句柄管理
- 服务启动时为配置文件中的每个 `[[workspace]]` 打开一个 `*os.Root`（`os.OpenRoot(ws.Path)`），并在服务关闭时统一 `Close()`。
- 所有目录遍历、文件读取、文件写入、重命名与状态检查**必须且只能**通过对应工作区的 `*os.Root` 方法执行（`Root.Open`、`Root.ReadFile`、`Root.WriteFile`、`Root.Stat`、`Root.Remove`、`Root.Rename`），严禁拼接宿主机绝对路径后调用全局 `os.Open` / `os.ReadFile`。

### 2.2 路径规范化与跨平台逃逸防御
所有外部传入的 `path` 参数（默认为空字符串 `""` 或 `"."` 表示工作区根目录）在进入 `os.Root` 前必须经过 `ws.SanitizeRelPath(raw string)` 严格清洗：
1. **统一分隔符**：将 `\` 替换为 `/`；拒绝包含空字节 `\x00` 的路径。
2. **禁止绝对路径与盘符**：拒绝以 `/` 开头的路径；在所有平台（不仅限 Windows，防止跨平台配置混淆）拒绝包含冒号 `:` 的路径（同时阻断 Windows 盘符 `C:` 与 **NTFS 备用数据流 ADS** 如 `file.txt:Zone.Identifier`）。
3. **禁止父级穿越**：按 `/` 分割路径段，若任一段为 `".."`，直接拒绝。
4. **Windows 保留设备名拦截**：提取每个路径段去除扩展名后的基名并转大写，若命中 `CON`、`PRN`、`AUX`、`NUL`、`COM1`–`COM9`、`LPT1`–`LPT9`，直接拒绝。
5. **符号链接防御**：依赖 `os.Root` 底层阻断跳出根目录的符号链接；工具自身不提供创建符号链接的能力；遍历目录时跳过符号链接条目（`d.Type()&fs.ModeSymlink != 0`）。

### 2.3 敏感文件默认屏蔽名单（Denylist）
路径的任意层级目录名或文件名命中以下规则时，视为不可见且不可读写（列目录跳过，直接访问返回权限/不存在错误）：
- **默认内置规则**：
  - 目录/前缀：`.git`、`.ssh`、`.aws`
  - 环境与凭证文件：`.env`、`.env.*`、`.npmrc`、`.netrc`
  - 密钥与证书：`*.pem`、`*.key`、`*.p12`、`*.pfx`、`id_rsa`、`id_rsa.*`、`id_ed25519`、`id_ed25519.*`、`*.kdbx`
- **配置追加规则**：支持通过工作区或全局配置 `deny_patterns` 追加自定义 glob 规则。
- **不可覆盖红线**：`.git` 与 `.ssh` 为硬编码永久屏蔽项，任何配置均不可放行。

---

## 3. 搜索隔离（`search_code` 双重校验）

`search_code` 采用 **`rg`（ripgrep）优先、纯 Go 并发遍历回退**策略：
1. **使用 `rg` 时**：
   - 工作目录固定为工作区路径，不跟随符号链接（默认不传 `-L`）；
   - 通过 `--glob` 参数排除默认重目录（`!node_modules/**`、`!dist/**`、`!build/**`、`!target/**`、`!__pycache__/**`、`!.venv/**`）及所有敏感名单 glob；
   - 设置 `--max-filesize 2M` 与 `20s` 上下文超时。
2. **Go 侧二次沙盒过滤（强制）**：
   - 由于外部 `rg` 进程不受 `os.Root` 文件描述符保护，Go 侧解析 `rg` 输出的每一条 `path:line:text` 后，**必须**再次调用 `ws.SanitizeRelPath` 与 `ws.IsDeniedPath` 进行校验，并确认路径未逃逸工作区，不合格条目直接丢弃。
3. **纯 Go 回退实现**：
   - 当宿主机未安装 `rg` 时，基于 `os.Root` 递归遍历文件，跳过二进制文件（前 512 字节含 `\x00` 或非有效 UTF-8 比例过高）与超 2MB 文件，逐行匹配正则表达式或字面量。

---

## 4. 原子写入、换行符保护与写前快照

所有修改磁盘的工具（`edit_file`、`write_file`）均通过 `ws.AtomicWrite` 执行：

1. **文件大小上限**：单文件读取与写入上限均为 **2MB**（2,097,152 字节）。
2. **换行符与 BOM 检测**：
   - 读取原文件时检测是否存在 UTF-8 BOM（`\xEF\xBB\xBF`），写入时原样保留；
   - 扫描文件换行风格：若同时包含 `\r\n`（CRLF）与独立 `\n`（LF），判定为**混合换行符**，直接拒绝修改并返回提示（要求用户先统一文件换行格式，避免整文件 diff 污染）；
   - 若原文件为 CRLF，自动将编辑内容中的换行规范化为 CRLF 后再落盘。
3. **写前外部快照（Snapshot）**：
   - 若目标文件已存在，写入前先将其完整内容与权限复制至工作区外部目录：
     `<data_dir>/snapshots/<grant_id>/<YYYYMMDD-HHMMSS.mmm>/<workspace>/<rel_path>`
   - 自动修剪该 `grant_id` 下的历史快照，仅保留最近 **20 份**（可通过配置 `max_snapshots_per_grant` 调整）。
4. **同目录原子重命名**：
   - 在目标文件所在的同一子目录内通过 `Root` 创建临时文件（命名如 `.wsbridge-tmp-<random>`），写入全部字节并 `Sync()`、`Close()`，继承原文件权限（新建文件默认 `0644`），最后调用 `Root.Rename` 原子替换目标文件；异常时清理临时文件。
