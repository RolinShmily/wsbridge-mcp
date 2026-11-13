# 03. CLI 子命令与 TOML 配置文件参考规范

## 1. 配置文件规范（`config.toml`）

默认路径：`<os.UserConfigDir()>/wsbridge/config.toml`（可通过 `--config` 覆盖）。

```toml
# 必填：公网可访问的 HTTPS 基础 URL（不含尾部斜杠，不含 /mcp）
public_url = "https://my-box.tail1234.ts.net"

# 本地监听地址，默认仅绑定回环网卡
listen = "127.0.0.1:8787"

# 数据目录（存放 wsbridge.db、audit.jsonl、snapshots/）
# 留空时默认与 config.toml 同目录（os.UserConfigDir()/wsbridge）
data_dir = ""

# 额外允许的 OAuth redirect_uri 域名列表（精确匹配 Host）
allow_redirect_hosts = []

# 全局额外敏感文件/目录匹配模式（追加到内置 denylist，不可移除 .git 与 .ssh）
deny_patterns = []

# 每个 Grant 保留的写前快照最大份数
max_snapshots_per_grant = 20

# 允许本地用户通过 wsbridge workspace add/list/remove 管理工作区，或直接编辑下表：
[[workspace]]
name = "myapp"
path = "/home/me/code/myapp"
max_perm = "write"                      # 可选值: "read" | "write" | "check"
checks = ["git_status", "git_diff"]     # 允许 run_check 调用的白名单项

[[workspace]]
name = "notes"
path = "/home/me/notes"
max_perm = "read"
checks = []
```

### 字段校验规则
- `public_url`：必须以 `https://` 开头（仅当 `listen` 为回环且传 `--allow-http-public-url` 测试参数时才允许 `http://`），不得包含路径、查询参数或尾部斜杠。
- `[[workspace]]`：`name` 必须全局唯一且仅含 `[a-zA-Z0-9._-]`；`path` 必须是存在的本地目录绝对路径。
- 管理员口令的 `argon2id` 哈希存储在 `<data_dir>/wsbridge.db` 中，**严禁出现在 `config.toml` 中**。

---

## 2. CLI 子命令规格（标准库 `flag` 实现）

全局可用参数：`--config <path>`（指定配置文件路径）。

### 2.1 `wsbridge init`
- **作用**：若配置文件不存在，交互式或使用默认值创建初始 `config.toml` 与 `data_dir`（目录权限 `0700`），并提示下一步运行 `wsbridge passwd`。
- **可选参数**：`--force`（覆盖已有配置文件）。

### 2.2 `wsbridge passwd`
- **作用**：交互式读取新管理员口令（使用 `golang.org/x/term` 关闭终端回显，确认输入两次，最小长度 10 位），生成 `argon2id` 哈希写入 `wsbridge.db`。
- **安全约束**：不支持通过命令行位置参数传递明文口令（防止泄露至 Shell 历史记录与 `ps` 进程表）。

### 2.3 `wsbridge serve`
- **作用**：启动 HTTP 服务并阻塞监听信号（`SIGINT` / `SIGTERM` 优雅关闭）。
- **参数**：
  - `--debug-oauth`：输出脱敏后的完整 OAuth 握手调试日志；
  - `--dev-cors`：允许本地 `http://localhost:*` 与 `http://127.0.0.1:*` 跨域访问，仅供本地 MCP Inspector 浏览器调试；
  - `--i-know-what-i-am-doing`：允许在 `root` 或 `SYSTEM` 高权限账号下启动服务。
- **启动前强校验**：若尚未设置管理员口令（`admin_pass_hash` 为空），拒绝启动并提示先执行 `wsbridge passwd`。

### 2.4 `wsbridge grants`
管理已签发的 OAuth 授权会话：
- `wsbridge grants list`：表格打印所有 Grant（`Grant ID`、`Client Name`、`Workspaces & Perms`、`Created`、`Expires`、`Status`）；
- `wsbridge grants revoke <grant_id>`：立即吊销指定 Grant 及其名下所有 Access/Refresh Token；
- `wsbridge grants revoke --all`：一键紧急吊销全部活跃 Grant；
- `wsbridge grants prune`：物理清理已过期或已吊销的历史 Grant 与孤立快照。

### 2.5 `wsbridge doctor`
- **作用**：执行本地配置完整性与公网 `public_url` 连通性/零重定向自检（详见 `docs/architecture/04-deployment-and-security.md` 第 3 节）。
- **退出码**：全部检查通过返回 `0`；存在关键错误返回 `1`（仅存在 `WARN` 如未初始化 Git 时返回 `0` 并高亮提示）。

### 2.6 `wsbridge service`
基于 `github.com/kardianos/service` 管理**当前用户级**后台守护进程（macOS `~/Library/LaunchAgents`、Linux `systemd --user`、Windows 当前用户计划任务）：
- `wsbridge service install`
- `wsbridge service uninstall`
- `wsbridge service start`
- `wsbridge service stop`
- `wsbridge service status`
