# 02. MCP 工具契约与 JSON Schema 规范

## 1. 通用协议约束

1. **工具总数上限**：v1 严格控制在 **7 个核心工具**（v2 最多增至 8 个），防止网页端模型工具选择准确率下降。
2. **输出格式**：所有工具一律返回 `[]mcp.Content{&mcp.TextContent{Text: ...}}`，不依赖 `structuredContent`。
3. **响应体硬上限**：单次工具输出文本上限为 **64KB（65,536 字节）**。超出上限时必须安全截断（不破坏 UTF-8 多字节字符边界），并在末尾附加如何缩小范围或分页继续读取的明确提示。
4. **多工作区路由规则**：除 `list_workspaces` 外，所有工具均定义可选字段 `workspace`（`string`）。当当前 Grant 仅授权 1 个工作区时可省略并自动命中该工作区；当授权 $\ge 2$ 个工作区时必须显式传入 `workspace`。

---

## 2. 工具清单与权限/标注矩阵

| 工具名称 | 所需最低权限 | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `list_workspaces` | `read` | `true` | `false` | `true` | `false` |
| `get_file_tree` | `read` | `true` | `false` | `true` | `false` |
| `search_code` | `read` | `true` | `false` | `true` | `false` |
| `read_file` | `read` | `true` | `false` | `true` | `false` |
| `edit_file` | `write` | `false` | `true` | `false` | `false` |
| `write_file` | `write` | `false` | `true` | `false` | `false` |
| `run_check` | `check` | `false` | `false` | `true` | `false` |

> **安全边界**：所有工具的 `openWorldHint` 必须显式设为 `false`，向宿主平台声明本工具集仅作用于受控本地工作区，不访问开放互联网。

---

## 3. 各工具详细输入 Schema 与行为规格

### 3.1 `list_workspaces`
- **描述**：列出当前授权会话可访问的所有本地工作区名称、有效权限级别及允许执行的检查项。
- **输入 Schema**：`{"type": "object", "properties": {}, "additionalProperties": false}`
- **输出样例**：
  ```text
  Authorized workspaces (1):
  - name: myapp | effective_perm: check | allowed_checks: [git_status, git_diff]
  ```

### 3.2 `get_file_tree`
- **描述**：查看指定工作区下的目录树结构（自动跳过 `.git`、`node_modules` 等重目录及敏感文件）。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
      "path": { "type": "string", "default": "", "description": "Relative directory path inside the workspace." },
      "depth": { "type": "integer", "default": 3, "minimum": 1, "maximum": 10, "description": "Max traversal depth." },
      "cursor": { "type": "string", "default": "", "description": "Pagination cursor returned by a previous truncated response." }
    },
    "additionalProperties": false
  }
  ```
- **约束**：单次返回最多 **2,000** 个条目；超出时返回下一页 `cursor` 与提示。

### 3.3 `search_code`
- **描述**：在工作区文本文件中搜索正则或字面量模式，返回 `path:line:text` 格式匹配结果。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "query": { "type": "string", "minLength": 1, "description": "Search pattern (regex or plain text)." },
      "path": { "type": "string", "default": "", "description": "Optional subdirectory or file filter." },
      "regex": { "type": "boolean", "default": false, "description": "Interpret query as regular expression when true." },
      "ignore_case": { "type": "boolean", "default": true },
      "max_results": { "type": "integer", "default": 100, "minimum": 1, "maximum": 500 }
    },
    "required": ["query"],
    "additionalProperties": false
  }
  ```
- **约束**：执行超时 `20s`；命中结果均经过沙盒敏感文件二次过滤。

### 3.4 `read_file`
- **描述**：读取工作区文本文件内容，支持单次读取多个行号区间，返回带行号文本与文件当前 `sha256`。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "ranges": {
        "type": "array",
        "description": "Optional list of 1-based inclusive line ranges. Reads from line 1 up to limits if omitted.",
        "items": {
          "type": "object",
          "properties": {
            "start_line": { "type": "integer", "minimum": 1 },
            "end_line": { "type": "integer", "minimum": 1 }
          },
          "required": ["start_line", "end_line"],
          "additionalProperties": false
        }
      }
    },
    "required": ["path"],
    "additionalProperties": false
  }
  ```
- **约束**：单文件大小上限 `2MB`；检测到二进制内容直接返回 `IsError: true`；单次返回总行数 $\le 2000$ 行且总字节 $\le 64	ext{KB}$；输出头部固定包含 `File: <path> | SHA256: <hex>`。

### 3.5 `edit_file`
- **描述**：对已有文本文件执行一处或多处原子精确替换，自动保留原文件换行符与 BOM，写入前生成外部快照。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "expected_sha256": { "type": "string", "description": "Optional optimistic concurrency check against last read sha256." },
      "edits": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": "object",
          "properties": {
            "old_text": { "type": "string", "minLength": 1 },
            "new_text": { "type": "string" },
            "replace_all": { "type": "boolean", "default": false }
          },
          "required": ["old_text", "new_text"],
          "additionalProperties": false
        }
      }
    },
    "required": ["path", "edits"],
    "additionalProperties": false
  }
  ```
- **行为与返回**：所有 `edits` 在内存中按顺序校验并应用（任何一条失败则整批回滚，不修改磁盘）；`replace_all=false` 时若匹配数 $
eq 1$ 报错并列出匹配行号；成功写入后返回统一 Diff 片段及**更新后的新 `SHA256`**（便于链式连续编辑）。

### 3.6 `write_file`
- **描述**：创建新文件，或在提供 `expected_sha256` 的前提下完整覆盖已有文件。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "path": { "type": "string", "minLength": 1 },
      "content": { "type": "string" },
      "expected_sha256": { "type": "string", "description": "Required when overwriting an existing file; must be omitted or empty when creating a new file." }
    },
    "required": ["path", "content"],
    "additionalProperties": false
  }
  ```
- **行为与返回**：
  - 目标文件不存在且未传 `expected_sha256` → 创建父目录（均经 `os.Root` 校验）并写入新文件；
  - 目标文件不存在但传了非空 `expected_sha256` → 报错（文件不存在，无法匹配预期哈希）；
  - 目标文件已存在但未传 `expected_sha256` → 报错拒绝覆盖，提示先调用 `read_file`；
  - 成功后返回字节数与**最新 `SHA256`**。

### 3.7 `run_check`
- **描述**：执行当前工作区配置白名单中允许的只读/测试检查命令。
- **输入 Schema**：
  ```json
  {
    "type": "object",
    "properties": {
      "workspace": { "type": "string" },
      "name": { "type": "string", "minLength": 1, "description": "Check identifier configured on the server (e.g., git_status, git_diff, go_vet)." }
    },
    "required": ["name"],
    "additionalProperties": false
  }
  ```
- **内置命令映射表**（绝不读取工作区内 `Makefile`/`package.json` 动态拼接命令）：
  - `git_status` → `git status --short --branch`（默认可启用）
  - `git_diff` → `git diff`（默认可启用）
  - `go_vet` → `go vet ./...`（默认可启用）
  - `go_test` → `go test ./...`（**默认禁用**，需在工作区 `checks` 显式配置）
  - `npm_lint` → `npm run lint`（**默认禁用**，需显式配置）
  - `npm_test` → `npm test`（**默认禁用**，需显式配置）
- **环境隔离**：子进程仅继承白名单环境变量（`PATH`、`HOME`/`USERPROFILE`、`TMPDIR`/`TEMP`、`GOPATH`、`GOROOT`、`GOMODCACHE`、`APPDATA`、`LOCALAPPDATA`），剥离所有其他宿主环境变量；执行超时 `60s`；输出上限 `64KB`。
