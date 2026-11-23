# 03. CLI 子命令与 TOML 配置文件参考规范

## 1. 配置文件规范（`config.toml`）

默认路径：`<os.UserConfigDir()>/wsbridge/config.toml`（可通过 `--config` 覆盖）。

```toml
# 必填：公网可访问的 HTTPS 基础 URL（不含尾部斜杠，不含 /mcp）
public_url = "https://my-box.tail1234.ts.net"

# 本地监听地址，默认仅绑定回环网卡
listen = "127.0.0.1:8787"

# 数据目录（存放 wsbridge.db、audit.jsonl、snapshots/、active-workspace.json）
# 留空时默认与 config.toml 同目录（os.UserConfigDir()/wsbridge）
data_dir = ""

# 可选：本地权限上限（"read" | "write" | "check"）。留空默认全开（"check"），由浏览器 OAuth 同意页管理每条连接的权限。
# max_perm = "check"

# 额外允许的 OAuth redirect_uri 域名列表（精确匹配 Host）
allow_redirect_hosts = []

# 全局额外敏感文件/目录匹配模式（追加到内置 denylist，不可移除 .git 与 .ssh）
deny_patterns = []

# 每个 Grant 保留的写前快照最大份数
max_snapshots_per_grant = 20

# 工作区配置为可选项：留空时 "wsbridge serve" 默认使用当前工作目录，并可通过 "wsbridge use <dir>" 在运行中热切换。
# 如需固定静态工作区，可取消注释：
# [[workspace]]
# name = "myapp"
# path = "/home/me/code/myapp"
```

### 字段校验规则
- `public_url`：必须以 `https://` 开头（仅当 `listen` 为回环且传 `--allow-http-public-url` 测试参数时才允许 `http://`），不得包含路径、查询参数或尾部斜杠。
- `max_perm`（可选）：留空默认 `check`；若显式配置则必须为 `read` / `write` / `check`，作为本地权限天花板与 OAuth Grant 权限取最小值。
- `[[workspace]]`（可选）：`name` 必须全局唯一且仅含 `[a-zA-Z0-9._-]`；`path` 必须是存在的本地目录绝对路径；`max_perm` 省略时继承全局 `max_perm`；`checks` 省略或为空时开放全部内置检查项。
- 管理员口令的 `argon2id` 哈希存储在 `<data_dir>/wsbridge.db` 中，**严禁出现在 `config.toml` 中**。

---

## 2. CLI 子命令规格（标准库 `flag` 实现）

全局可用参数：`--config <path>`（指定配置文件路径）。

### 2.1 `wsbridge init`
- **作用**：交互式仅配置隧道方案（`cloudflared` / `tailscale funnel` / 自定义）、`public_url`、`listen` 与管理员口令（不再绑定工作区与全局权限）；`--non-interactive` 写入精简示例配置。
- **可选参数**：`--force`（覆盖已有配置文件）、`--non-interactive`。

### 2.2 `wsbridge passwd`
- **作用**：交互式读取新管理员口令（关闭终端回显，确认输入两次，最小长度 10 位），生成 `argon2id` 哈希写入 `wsbridge.db`。
- **安全约束**：不支持通过命令行位置参数传递明文口令（防止泄露至 Shell 历史记录与 `ps` 进程表）。

### 2.3 `wsbridge serve [dir]`
- **作用**：启动 HTTP 服务及本机独立回环控制通道（`<data_dir>/control.json`，仅本机随机端口 + 32B 随机 Bearer 令牌，与公网隧道隔离），阻塞监听信号（`SIGINT` / `SIGTERM` 优雅关闭）。
- **工作区解析优先级**：
  1. 显式传入位置参数 `[dir]` → 挂载该目录并持久化至 `active-workspace.json`；
  2. `config.toml` 配置了静态 `[[workspace]]` → 加载配置的静态工作区；
  3. 动态模式（默认）：前台终端启动时自动挂载当前工作目录（`cwd`）；后台系统服务模式（`wsbridge service`）自动恢复 `active-workspace.json` 中上次选定的目录（若尚未选择则空载等待 `wsbridge use <dir>`）。
- **参数**：
  - `--max-perm <read|write|check>`：可选临时收紧本地权限上限；
  - `--debug-oauth`：输出脱敏后的完整 OAuth 握手调试日志；
  - `--dev-cors`：允许本地 `http://localhost:*` 与 `http://127.0.0.1:*` 跨域访问，仅供本地 MCP Inspector 浏览器调试；
  - `--i-know-what-i-am-doing`：允许在 `root` 或 `SYSTEM` 高权限账号下启动服务。
- **启动前强校验**：若尚未设置管理员口令（`admin_pass_hash` 为空），拒绝启动并提示先执行 `wsbridge passwd`。

### 2.4 `wsbridge use [dir]`
- **作用**：热切换当前活跃工作区（默认 `[dir]` 为当前目录 `.`），更新 `active-workspace.json`；若 `wsbridge serve` / `wsbridge service` 正在运行，立即通过本机控制通道原子切换 `*os.Root`，远端 AI 连接与 OAuth Token 全程不中断、无需重连。
- **参数**：
  - `--name <name>`：可选自定义工作区名（默认由目录名自动规范化生成）；
  - `--show`：仅查看当前活跃或已保存的工作区状态，不执行切换。

### 2.5 `wsbridge grants`
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
