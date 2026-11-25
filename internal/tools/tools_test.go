package tools_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RolinShmily/wsbridge-mcp/internal/tools"
	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func channel(t *testing.T, configs []ws.WorkspaceConfig) (*ws.Manager, *mcp.ClientSession) {
	t.Helper()
	mgr, err := ws.NewManager(configs, ws.ManagerOptions{DataDir: t.TempDir(), RipgrepPath: "none"})
	if err != nil {
		t.Fatalf("ws.NewManager: %v", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "wsbridge-test", Version: "test"}, nil)
	tools.Register(server, func(context.Context) (*tools.Scope, error) {
		scope := &tools.Scope{GrantID: "test-grant"}
		for _, name := range mgr.Names() {
			w, _ := mgr.Get(name)
			scope.Allowed = append(scope.Allowed, tools.Access{Workspace: w, Permission: w.MaxPerm()})
		}
		return scope, nil
	})
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = serverSession.Wait()
		_ = mgr.Close()
	})
	return mgr, cs
}

func singleWorkspace(t *testing.T, maxPerm ws.Permission, checks ...string) (string, *ws.Manager, *mcp.ClientSession) {
	t.Helper()
	dir := t.TempDir()
	mgr, cs := channel(t, []ws.WorkspaceConfig{{
		Name: "app", Path: dir, MaxPerm: maxPerm, Checks: checks,
	}})
	return dir, mgr, cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("tool returned no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func wantError(t *testing.T, res *mcp.CallToolResult, substrings ...string) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("result is not an error: %q", textOf(t, res))
	}
	text := textOf(t, res)
	for _, want := range substrings {
		if !strings.Contains(text, want) {
			t.Errorf("error %q does not contain %q", text, want)
		}
	}
	return text
}

func TestListToolsSchemasAndAnnotations(t *testing.T) {
	_, cs := channel(t, []ws.WorkspaceConfig{{Name: "app", Path: t.TempDir(), MaxPerm: ws.PermCheck}})
	ctx := context.Background()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]*mcp.Tool{}
	for _, tool := range list.Tools {
		names[tool.Name] = tool
	}
	wantNames := []string{"list_workspaces", "get_file_tree", "search_code", "read_file", "edit_file", "write_file", "run_check"}
	if len(names) != len(wantNames) {
		t.Errorf("got %d tools, want %d", len(names), len(wantNames))
	}
	for _, name := range wantNames {
		if names[name] == nil {
			t.Errorf("tool %q missing", name)
		}
	}
	readOnly := map[string]bool{
		"list_workspaces": true, "get_file_tree": true, "search_code": true, "read_file": true,
	}
	destructive := map[string]bool{"edit_file": true, "write_file": true, "run_check": true}
	for name, tool := range names {
		if tool.Annotations == nil {
			t.Errorf("%s: annotations missing", name)
			continue
		}
		if tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Errorf("%s: openWorldHint must be explicit false", name)
		}
		if tool.Annotations.ReadOnlyHint != readOnly[name] {
			t.Errorf("%s: readOnlyHint = %v", name, tool.Annotations.ReadOnlyHint)
		}
		if tool.Annotations.DestructiveHint != nil && *tool.Annotations.DestructiveHint != destructive[name] {
			t.Errorf("%s: destructiveHint = %v", name, *tool.Annotations.DestructiveHint)
		}
	}

	treeSchema := schemaMap(t, names["get_file_tree"])
	if treeSchema["additionalProperties"] != false {
		t.Errorf("get_file_tree additionalProperties = %v", treeSchema["additionalProperties"])
	}
	props := treeSchema["properties"].(map[string]any)
	depth := props["depth"].(map[string]any)
	if depth["default"] != float64(3) || depth["minimum"] != float64(1) || depth["maximum"] != float64(10) {
		t.Errorf("depth schema = %v", depth)
	}
	searchSchema := schemaMap(t, names["search_code"])
	searchProps := searchSchema["properties"].(map[string]any)
	ignoreCase := searchProps["ignore_case"].(map[string]any)
	if ignoreCase["default"] != true {
		t.Errorf("ignore_case default = %v, want true", ignoreCase["default"])
	}
	maxResults := searchProps["max_results"].(map[string]any)
	if maxResults["default"] != float64(100) || maxResults["maximum"] != float64(500) {
		t.Errorf("max_results schema = %v", maxResults)
	}
	readSchema := schemaMap(t, names["read_file"])
	required := readSchema["required"].([]any)
	if len(required) != 1 || required[0] != "path" {
		t.Errorf("read_file required = %v", required)
	}
}

func schemaMap(t *testing.T, tool *mcp.Tool) map[string]any {
	t.Helper()
	data, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return m
}

func TestListWorkspaces(t *testing.T) {
	_, _, cs := singleWorkspace(t, ws.PermCheck, "git_status", "git_diff")
	res := call(t, cs, "list_workspaces", map[string]any{})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	want := "Authorized workspaces (1):\n- name: app | effective_perm: check | allowed_checks: [git_status, git_diff]"
	if got := textOf(t, res); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestReadFileRangesAndHash(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	content := []byte("line one\nline two\nline three\nline four\n")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	wantHash := hex.EncodeToString(sum[:])

	res := call(t, cs, "read_file", map[string]any{
		"path":   "a.txt",
		"ranges": []map[string]any{{"start_line": 2, "end_line": 3}},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", textOf(t, res))
	}
	text := textOf(t, res)
	if !strings.HasPrefix(text, "File: a.txt | SHA256: "+wantHash+"\n") {
		t.Errorf("bad header: %q", text)
	}
	if !strings.Contains(text, "line two") || !strings.Contains(text, "line three") {
		t.Errorf("requested lines missing: %q", text)
	}
	if strings.Contains(text, "line one") || strings.Contains(text, "line four") {
		t.Errorf("unrequested lines present: %q", text)
	}
}

func TestReadFileLineCapAndUTF8(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	var b strings.Builder
	for i := 1; i <= 2100; i++ {
		b.WriteString("x\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "many.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	text := textOf(t, call(t, cs, "read_file", map[string]any{"path": "many.txt"}))
	if !strings.Contains(text, "\n2000 | x") {
		t.Errorf("line 2000 missing from output")
	}
	if strings.Contains(text, "\n2001 | x") {
		t.Errorf("output exceeds 2000 lines")
	}
	if !strings.Contains(text, "truncated") {
		t.Errorf("truncation hint missing")
	}
	if len(text) > 65536 {
		t.Errorf("output size = %d, want <= 65536", len(text))
	}

	long := strings.Repeat("汉", 30000) // 90KB on one line, splits mid-rune at 64KB
	if err := os.WriteFile(filepath.Join(dir, "utf8.txt"), []byte(long), 0o644); err != nil {
		t.Fatal(err)
	}
	text = textOf(t, call(t, cs, "read_file", map[string]any{"path": "utf8.txt"}))
	if len(text) > 65536 {
		t.Errorf("output size = %d, want <= 65536", len(text))
	}
	if !utf8.ValidString(text) {
		t.Error("truncated output is not valid UTF-8")
	}
	if !strings.Contains(text, "truncated") {
		t.Error("truncation hint missing")
	}
}

func TestReadFileErrors(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	if err := os.WriteFile(filepath.Join(dir, "bin.dat"), []byte("abc\x00def"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantError(t, call(t, cs, "read_file", map[string]any{"path": "bin.dat"}), "binary")
	wantError(t, call(t, cs, "read_file", map[string]any{"path": ".env"}), "sensitive")
	wantError(t, call(t, cs, "read_file", map[string]any{"path": "missing.txt"}))
	wantError(t, call(t, cs, "read_file", map[string]any{
		"path": "bin.dat", "ranges": []map[string]any{{"start_line": 3, "end_line": 2}},
	}), "range")
}

func TestSearchDefaultsAndFilters(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	files := map[string]string{
		"a.txt":     "Hello world\n",
		"b.txt":     "hello lower\n",
		".env":      "hello secret\n",
		"sub/c.txt": "nothing here\n",
	}
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// ignore_case defaults to true via the JSON schema.
	text := textOf(t, call(t, cs, "search_code", map[string]any{"query": "hello"}))
	if !strings.Contains(text, "a.txt:1:Hello world") || !strings.Contains(text, "b.txt:1:hello lower") {
		t.Errorf("case-insensitive default failed: %q", text)
	}
	if strings.Contains(text, ".env") {
		t.Errorf("sensitive file leaked into search: %q", text)
	}

	text = textOf(t, call(t, cs, "search_code", map[string]any{"query": "hello", "ignore_case": false}))
	if strings.Contains(text, "a.txt") || !strings.Contains(text, "b.txt") {
		t.Errorf("case-sensitive search wrong: %q", text)
	}

	text = textOf(t, call(t, cs, "search_code", map[string]any{"query": "h.llo"}))
	if !strings.Contains(text, "No matches") {
		t.Errorf("literal metacharacter search matched: %q", text)
	}
	text = textOf(t, call(t, cs, "search_code", map[string]any{"query": "h.llo", "regex": true}))
	if !strings.Contains(text, "a.txt") {
		t.Errorf("regex search missed match: %q", text)
	}
}

func TestGetFileTree(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	for rel, content := range map[string]string{
		"a.txt": "a", "dir/b.go": "package dir", "dir/nested/c.txt": "c",
		".env": "SECRET", "node_modules/x.js": "module",
	} {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	text := textOf(t, call(t, cs, "get_file_tree", map[string]any{}))
	for _, want := range []string{"a.txt", "dir/", "dir/b.go", "dir/nested/", "dir/nested/c.txt"} {
		if !strings.Contains(text, want) {
			t.Errorf("tree missing %q: %q", want, text)
		}
	}
	for _, hidden := range []string{".env", "node_modules"} {
		if strings.Contains(text, hidden) {
			t.Errorf("tree contains hidden %q: %q", hidden, text)
		}
	}
}

func TestGetFileTreePaginatesWithinOutputBudget(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	const total = 400
	prefix := strings.Repeat("a", 180)
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("%s-%03d.txt", prefix, i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		args := map[string]any{"depth": 1}
		if cursor != "" {
			args["cursor"] = cursor
		}
		text := textOf(t, call(t, cs, "get_file_tree", args))
		if len(text) > tools.MaxOutputBytes {
			t.Fatalf("page %d size = %d, want <= %d", pages, len(text), tools.MaxOutputBytes)
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			name := line[:strings.Index(line, " (")]
			if seen[name] {
				t.Errorf("entry %q repeated across pages", name)
			}
			seen[name] = true
		}
		pages++
		cursor = ""
		if idx := strings.LastIndex(text, `continue with cursor: "`); idx >= 0 {
			if !strings.HasSuffix(text, `"]`) {
				t.Fatalf("cursor footer was truncated: %q", text[len(text)-120:])
			}
			rest := text[idx+len(`continue with cursor: "`):]
			end := strings.Index(rest, `"`)
			if end < 0 {
				t.Fatal("malformed cursor footer")
			}
			cursor = rest[:end]
		}
		if cursor == "" {
			break
		}
		if pages > 20 {
			t.Fatal("tree pagination did not terminate")
		}
	}
	if len(seen) != total {
		t.Errorf("paginated tree exposed %d of %d entries", len(seen), total)
	}
	if pages < 2 {
		t.Errorf("pages = %d, want the 64KB budget to split this tree", pages)
	}
}

func TestMultiWorkspaceResolution(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, cs := channel(t, []ws.WorkspaceConfig{
		{Name: "alpha", Path: dirA, MaxPerm: ws.PermRead},
		{Name: "beta", Path: dirB, MaxPerm: ws.PermRead},
	})
	wantError(t, call(t, cs, "read_file", map[string]any{"path": "a.txt"}), "workspace", "alpha", "beta")
	wantError(t, call(t, cs, "read_file", map[string]any{"workspace": "nope", "path": "a.txt"}), "nope")
	text := textOf(t, call(t, cs, "read_file", map[string]any{"workspace": "alpha", "path": "a.txt"}))
	if !strings.Contains(text, "a") {
		t.Errorf("wrong workspace content: %q", text)
	}
}

func TestEditFileAndFailures(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermWrite)
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(original)
	hash := hex.EncodeToString(sum[:])

	res := call(t, cs, "edit_file", map[string]any{
		"path":            "a.txt",
		"expected_sha256": hash,
		"edits": []map[string]any{
			{"old_text": "beta", "new_text": "BETA"},
		},
	})
	if res.IsError {
		t.Fatalf("edit failed: %s", textOf(t, res))
	}
	text := textOf(t, res)
	for _, want := range []string{"+++", "-beta", "+BETA", "SHA256:", "Snapshot:"} {
		if !strings.Contains(text, want) {
			t.Errorf("edit output missing %q: %q", want, text)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "alpha\nBETA\n" {
		t.Fatalf("file content = %q, err = %v", data, err)
	}

	before := string(data)
	res = call(t, cs, "edit_file", map[string]any{
		"path": "a.txt",
		"edits": []map[string]any{
			{"old_text": "a", "new_text": "A"},
		},
	})
	wantError(t, res, "multiple", "1")
	data, err = os.ReadFile(path)
	if err != nil || string(data) != before {
		t.Fatalf("failed edit modified the file: %q, %v", data, err)
	}

	res = call(t, cs, "edit_file", map[string]any{
		"path": "a.txt", "expected_sha256": "deadbeef",
		"edits": []map[string]any{{"old_text": "alpha", "new_text": "ALPHA"}},
	})
	wantError(t, res, "mismatch")

	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res = call(t, cs, "edit_file", map[string]any{
		"path": "a.txt",
		"edits": []map[string]any{
			{"old_text": "alpha", "new_text": "AL\x00PHA"},
		},
	})
	wantError(t, res, "NUL")
	if after, err := os.ReadFile(path); err != nil || string(after) != string(data) {
		t.Errorf("rejected NUL edit modified the file: %q, %v", after, err)
	}

	res = call(t, cs, "edit_file", map[string]any{
		"path":  "a.txt",
		"edits": []map[string]any{{"old_text": "a", "new_text": "z", "replace_all": true}},
	})
	if res.IsError {
		t.Fatalf("replace_all failed: %s", textOf(t, res))
	}
	data, err = os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "a") {
		t.Fatalf("replace_all content = %q, %v", data, err)
	}
}

func TestWriteFileLifecycle(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermWrite)
	res := call(t, cs, "write_file", map[string]any{"path": "new.txt", "content": "hello\n"})
	if res.IsError {
		t.Fatalf("create failed: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "SHA256:") {
		t.Errorf("create output missing hash: %q", textOf(t, res))
	}
	data, err := os.ReadFile(filepath.Join(dir, "new.txt"))
	if err != nil || string(data) != "hello\n" {
		t.Fatalf("created content = %q, %v", data, err)
	}

	wantError(t, call(t, cs, "write_file", map[string]any{"path": "new.txt", "content": "x"}), "read_file")
	sum := sha256.Sum256(data)
	res = call(t, cs, "write_file", map[string]any{
		"path": "new.txt", "content": "changed\n", "expected_sha256": hex.EncodeToString(sum[:]),
	})
	if res.IsError {
		t.Fatalf("overwrite failed: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "Snapshot:") {
		t.Errorf("overwrite output missing snapshot: %q", textOf(t, res))
	}
	data, _ = os.ReadFile(filepath.Join(dir, "new.txt"))
	if string(data) != "changed\n" {
		t.Errorf("overwrite content = %q", data)
	}
	wantError(t, call(t, cs, "write_file", map[string]any{
		"path": "absent.txt", "content": "x", "expected_sha256": "deadbeef",
	}), "does not exist")
}

func TestWriteFileReportsPersistedSize(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermWrite)
	path := filepath.Join(dir, "win.txt")
	if err := os.WriteFile(path, []byte("old\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(original)
	res := call(t, cs, "write_file", map[string]any{
		"path":            "win.txt",
		"content":         "a\nb\n",
		"expected_sha256": hex.EncodeToString(sum[:]),
	})
	if res.IsError {
		t.Fatalf("overwrite failed: %s", textOf(t, res))
	}
	if want := "Wrote win.txt (6 bytes)"; !strings.Contains(textOf(t, res), want) {
		t.Errorf("output = %q, want %q", textOf(t, res), want)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "a\r\nb\r\n" {
		t.Errorf("persisted content = %q, err = %v", data, err)
	}
}

func TestPermissionEnforcement(t *testing.T) {
	dir, _, cs := singleWorkspace(t, ws.PermRead)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantError(t, call(t, cs, "edit_file", map[string]any{
		"path": "a.txt", "edits": []map[string]any{{"old_text": "a", "new_text": "b"}},
	}), "write permission")
	wantError(t, call(t, cs, "write_file", map[string]any{"path": "b.txt", "content": "b"}), "write permission")
	wantError(t, call(t, cs, "run_check", map[string]any{"name": "git_status"}), "check")
}

func TestRunCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir, _, cs := singleWorkspace(t, ws.PermCheck, "git_status")
	cmd := exec.Command("git", "init", "-q")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git init failed: %v", err)
	}
	res := call(t, cs, "run_check", map[string]any{"name": "git_status"})
	if res.IsError {
		t.Fatalf("run_check failed: %s", textOf(t, res))
	}
	text := textOf(t, res)
	for _, want := range []string{"Check: git_status", "Exit: 0"} {
		if !strings.Contains(text, want) {
			t.Errorf("run_check output missing %q: %q", want, text)
		}
	}
	wantError(t, call(t, cs, "run_check", map[string]any{"name": "git_diff"}), "not allowed")
}

func TestListWorkspacesRejectsUnknownFields(t *testing.T) {
	_, _, cs := singleWorkspace(t, ws.PermRead)
	wantError(t, call(t, cs, "list_workspaces", map[string]any{"extra": true}), "additional")
}
