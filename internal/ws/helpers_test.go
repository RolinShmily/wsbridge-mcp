package ws_test

import (
	"testing"

	"github.com/RolinShmily/wsbridge-mcp/internal/ws"
)

func newTestManager(t *testing.T, configs []ws.WorkspaceConfig, opts ws.ManagerOptions) *ws.Manager {
	t.Helper()
	mgr, err := ws.NewManager(configs, opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}
