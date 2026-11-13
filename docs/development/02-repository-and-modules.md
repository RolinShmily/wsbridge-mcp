# 02. 仓库结构与模块接口契约

## 1. 标准仓库目录结构

```text
wsbridge/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Linux / macOS / Windows 三平台 go test -race 与交叉编译
├── cmd/
│   └── wsbridge/
│       └── main.go                # CLI 入口: serve | init | passwd | grants | doctor | service
├── internal/
│   ├── config/
│   │   ├── config.go              # TOML 结构定义、默认值、校验与 Save/Load
│   │   └── config_test.go
│   ├── httpx/
│   │   ├── server.go              # http.Server 封装、全链路超时、1MB Body 限制、优雅关闭
│   │   ├── middleware.go          # 脱敏日志、--debug-oauth 输出、令牌桶限流、可选 --dev-cors
│   │   └── redact.go              # 请求头/URL/JSON/Form 敏感信息脱敏工具
│   ├── oauth/
│   │   ├── server.go              # OAuth HTTP 路由挂载 (/oauth/* 与 /.well-known/*)
│   │   ├── metadata.go            # RFC 9728 (PRM) & RFC 8414 (AS Metadata) 响应生成
│   │   ├── register.go            # RFC 7591 DCR 注册与 redirect_uri 白名单校验
│   │   ├── authorize.go           # GET/POST /oauth/authorize、CSRF、口令锁定与授权码签发
│   │   ├── token.go               # POST /oauth/token (authorization_code & refresh_token 轮换) & /revoke
│   │   ├── pkce.go                # PKCE S256 校验与常量时间比较
│   │   ├── store.go               # bbolt 持久化存储、30s 宽限期幂等轮换、级联吊销与后台 GC
│   │   ├── consent.html           # //go:embed 内嵌授权同意页单文件 HTML/CSS
│   │   └── oauth_test.go
│   ├── mcpsrv/
│   │   ├── server.go              # 构建 *mcp.Server、注册工具、StreamableHTTPHandler 封装
│   │   ├── auth_middleware.go     # Bearer 校验、401 WWW-Authenticate 头、TokenInfo 注入
│   │   └── authz.go               # Grant 权限校验辅助函数 (EffectivePerm)
│   ├── tools/
│   │   ├── register.go            # 统一注册全部 MCP 工具与 annotations
│   │   ├── workspaces.go          # list_workspaces
│   │   ├── tree.go                # get_file_tree
│   │   ├── search.go              # search_code (rg 优先 + Go 二次沙盒过滤 + 纯 Go 回退)
│   │   ├── read.go                # read_file (多段 ranges、行号、64KB 限制、sha256)
│   │   ├── edit.go                # edit_file (原子批量编辑、唯一性校验、unified diff)
│   │   ├── write.go               # write_file (新建 / expected_sha256 覆盖)
│   │   ├── check.go               # run_check (配置白名单命令、环境变量隔离)
│   │   └── tools_test.go
│   ├── ws/
│   │   ├── manager.go             # 管理多个工作区的 *os.Root 实例池
│   │   ├── path.go                # 路径清洗、Windows 保留字/ADS 拦截、敏感名单匹配
│   │   ├── atomic.go              # 换行符/BOM 检测、混合换行拒绝、写前外部快照与同目录原子 Rename
│   │   └── ws_test.go
│   ├── audit/
│   │   └── logger.go              # 并发安全的 JSONL 审计日志写入器
│   └── tunnel/
│       └── doctor.go              # 公网 URL 自检诊断逻辑
├── e2e/
│   └── full_flow_test.go          # 无平台依赖的完整 OAuth + MCP 端到端测试客户端
├── docs/                          # 本规格文档体系
├── AGENTS.md
├── go.mod
├── go.sum
├── .goreleaser.yaml
└── README.md
```

---

## 2. 核心包职责与 Go 接口契约

### 2.1 `internal/ws`（工作区沙盒契约）
```go
package ws

type Permission int

const (
    PermNone  Permission = 0
    PermRead  Permission = 1
    PermWrite Permission = 2
    PermCheck Permission = 3
)

// Workspace 提供绑定到单一 *os.Root 的安全文件操作能力
type Workspace interface {
    Name() string
    MaxPerm() Permission
    AllowedChecks() []string
    ReadFile(relPath string) (content []byte, sha256Hex string, err error)
    WriteFileAtomic(grantID, relPath string, data []byte, expectSHA256 string, createOnly bool) (newSHA256Hex string, snapshotRelPath string, err error)
    WalkTree(relPath string, maxDepth int, cursor string, limit int) (TreeResult, error)
    Search(ctx context.Context, opts SearchOptions) ([]SearchMatch, bool, error)
    RunCheck(ctx context.Context, checkName string) (output string, exitCode int, err error)
    Close() error
}
```

### 2.2 `internal/oauth`（授权验证与 Grant 查询契约）
`internal/mcpsrv` 通过以下接口与 `internal/oauth` 解耦：
```go
package oauth

type GrantPrincipal struct {
    GrantID    string
    ClientID   string
    ClientName string
    Workspaces map[string]ws.Permission // workspace_name -> granted permission
    ExpiresAt  time.Time
}

// TokenVerifier 由 Bearer 中间件调用，校验访问令牌并返回关联的 Grant 信息
type TokenVerifier interface {
    VerifyAccessToken(rawToken string, expectedResource string) (*GrantPrincipal, error)
}
```

### 2.3 `internal/tools`（多工作区参数解析契约）
所有针对特定工作区的工具（除 `list_workspaces` 外）均接收可选字段 `Workspace string` (`json:"workspace,omitempty"`)，由统一辅助函数 `ResolveWorkspace(principal *oauth.GrantPrincipal, mgr *ws.Manager, requestedWS string, requiredPerm ws.Permission)` 解析：
1. 若 `requestedWS == ""`：
   - 若 `len(principal.Workspaces) == 1`，自动选中该唯一授权工作区；
   - 若 `len(principal.Workspaces) > 1`，返回可操作工具错误：`multiple workspaces are authorized in this session; specify the 'workspace' parameter (available: ...)`；
   - 若 `len(principal.Workspaces) == 0`，返回无可用工作区错误。
2. 若 `requestedWS != ""`：
   - 检查 `requestedWS` 是否存在于 `principal.Workspaces`（不存在则返回未授权该工作区）；
   - 计算 `effective := min(wsInstance.MaxPerm(), grantedPerm)`；
   - 若 `effective < requiredPerm`，返回权限不足错误并指明当前有效权限与所需权限。
