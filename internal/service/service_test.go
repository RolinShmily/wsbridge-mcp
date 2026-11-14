package service_test

import (
	"testing"

	"wsbridge/internal/service"
)

func TestConfigRunsServeWithConfigPath(t *testing.T) {
	cfg := service.Config(service.Options{ConfigPath: "/home/me/.config/wsbridge/config.toml"})
	if cfg.Name != service.Name {
		t.Errorf("Name = %q, want %q", cfg.Name, service.Name)
	}
	want := []string{"--config", "/home/me/.config/wsbridge/config.toml", "serve"}
	if len(cfg.Arguments) != len(want) {
		t.Fatalf("Arguments = %v, want %v", cfg.Arguments, want)
	}
	for i := range want {
		if cfg.Arguments[i] != want[i] {
			t.Fatalf("Arguments = %v, want %v", cfg.Arguments, want)
		}
	}
	if v, ok := cfg.Option["UserService"].(bool); !ok || !v {
		t.Error("UserService option is not enabled; the service must be user-level")
	}
}

func TestConfigKeepsExecutableOverride(t *testing.T) {
	cfg := service.Config(service.Options{ConfigPath: "cfg.toml", Executable: "/opt/wsbridge"})
	if cfg.Executable != "/opt/wsbridge" {
		t.Errorf("Executable = %q", cfg.Executable)
	}
}

func TestStatusString(t *testing.T) {
	cases := map[service.Status]string{
		service.StatusUnknown: "unknown",
		service.StatusRunning: "running",
		service.StatusStopped: "stopped",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", status, got, want)
		}
	}
}

func TestFuncProgramInvokesCallbacks(t *testing.T) {
	var started, stopped int
	p := &service.FuncProgram{
		StartFunc: func() error { started++; return nil },
		StopFunc:  func() error { stopped++; return nil },
	}
	if err := p.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if started != 1 || stopped != 1 {
		t.Errorf("started = %d, stopped = %d, want 1 and 1", started, stopped)
	}
}

func TestFuncProgramAllowsNilCallbacks(t *testing.T) {
	p := &service.FuncProgram{}
	if err := p.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
