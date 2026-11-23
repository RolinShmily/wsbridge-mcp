package control_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"wsbridge/internal/control"
)

func TestActiveWorkspacePersistence(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := control.LoadActiveWorkspace(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadActiveWorkspace missing = %v, want os.ErrNotExist", err)
	}

	want := control.ActiveWorkspace{Name: "demo", Path: filepath.Join(t.TempDir(), "demo")}
	if err := control.SaveActiveWorkspace(dataDir, want); err != nil {
		t.Fatalf("SaveActiveWorkspace: %v", err)
	}
	got, err := control.LoadActiveWorkspace(dataDir)
	if err != nil {
		t.Fatalf("LoadActiveWorkspace: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dataDir, "active-workspace.json"))
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("active-workspace.json mode = %o, want 600", mode)
		}
	}
}

func TestControlServerSwitchAuthAndOffline(t *testing.T) {
	dataDir := t.TempDir()
	projA := t.TempDir()
	projB := t.TempDir()

	// Before server starts, client reports ErrNotRunning.
	if _, err := control.GetWorkspaces(context.Background(), dataDir); !errors.Is(err, control.ErrNotRunning) {
		t.Fatalf("GetWorkspaces offline = %v, want ErrNotRunning", err)
	}
	if _, err := control.SwitchWorkspace(context.Background(), dataDir, projB, "proj-b"); !errors.Is(err, control.ErrNotRunning) {
		t.Fatalf("SwitchWorkspace offline = %v, want ErrNotRunning", err)
	}

	var mu sync.Mutex
	current := control.WorkspaceInfo{Name: "proj-a", Path: projA, MaxPerm: "check"}

	srv, err := control.Start(dataDir, control.Handlers{
		List: func() []control.WorkspaceInfo {
			mu.Lock()
			defer mu.Unlock()
			return []control.WorkspaceInfo{current}
		},
		Switch: func(path, name string) (control.WorkspaceInfo, error) {
			mu.Lock()
			defer mu.Unlock()
			if name == "" {
				name = filepath.Base(path)
			}
			current = control.WorkspaceInfo{Name: name, Path: path, MaxPerm: "check"}
			return current, nil
		},
	})
	if err != nil {
		t.Fatalf("control.Start: %v", err)
	}

	// Unauthenticated request to the loopback control server must be rejected.
	req, err := http.NewRequest(http.MethodGet, "http://"+srv.Addr()+"/v1/workspace", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// Wrong bearer token must also be rejected.
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d, want 401", resp.StatusCode)
	}

	// Authenticated list & switch via Client.
	list, err := control.GetWorkspaces(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("GetWorkspaces: %v", err)
	}
	if len(list) != 1 || list[0].Name != "proj-a" || list[0].Path != projA {
		t.Fatalf("list = %+v", list)
	}

	switched, err := control.SwitchWorkspace(context.Background(), dataDir, projB, "proj-b")
	if err != nil {
		t.Fatalf("SwitchWorkspace: %v", err)
	}
	if switched.Name != "proj-b" || switched.Path != projB {
		t.Fatalf("switched = %+v", switched)
	}

	list, err = control.GetWorkspaces(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("GetWorkspaces after switch: %v", err)
	}
	if len(list) != 1 || list[0].Name != "proj-b" || list[0].Path != projB {
		t.Fatalf("list after switch = %+v", list)
	}

	// Shutdown removes control.json and subsequent calls report ErrNotRunning.
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "control.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("control.json not removed on Close: %v", err)
	}
	if _, err := control.GetWorkspaces(context.Background(), dataDir); !errors.Is(err, control.ErrNotRunning) {
		t.Errorf("GetWorkspaces after Close = %v, want ErrNotRunning", err)
	}
	if strings.Contains(srv.Addr(), "0.0.0.0") {
		t.Errorf("control addr %q must be loopback", srv.Addr())
	}
}
