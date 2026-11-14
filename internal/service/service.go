// Package service manages the current user's background wsbridge daemon.
//
// It is a thin wrapper around github.com/kardianos/service so the rest of the
// program, and its tests, never talk to the operating system service manager
// directly.
package service

import (
	"runtime"

	kservice "github.com/kardianos/service"
)

const (
	// Name is the stable service identifier used on every platform.
	Name = "wsbridge"
	// DisplayName is the name shown by the platform service manager.
	DisplayName = "wsbridge"
	// Description documents the service in the platform manager.
	Description = "Local workspace bridge for MCP clients (ChatGPT, Gemini, Claude)."
)

// Status is the state reported by the OS service manager.
type Status int

const (
	StatusUnknown Status = iota
	StatusRunning
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusRunning:
		return "running"
	case StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// ErrNotInstalled reports that the service is not registered with the OS.
var ErrNotInstalled = kservice.ErrNotInstalled

// Manager is the subset of kservice.Service used by the CLI.
type Manager interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Status() (Status, error)
}

// Options configures the service definition.
type Options struct {
	// ConfigPath is the absolute path passed to "serve" as --config.
	ConfigPath string
	// Executable overrides the binary path; empty means the running binary.
	Executable string
}

// Config returns the kardianos configuration for the wsbridge service.
func Config(opts Options) *kservice.Config {
	return &kservice.Config{
		Name:        Name,
		DisplayName: DisplayName,
		Description: Description,
		Executable:  opts.Executable,
		Arguments:   []string{"--config", opts.ConfigPath, "serve"},
		Option: kservice.KeyValue{
			// POSIX: install in the current user's service manager
			// (launchd LaunchAgents or systemd --user).
			"UserService": true,
			// POSIX: restart after unexpected exits.
			"Restart": "always",
			// Windows: restart after failures.
			"OnFailure": "restart",
		},
	}
}

// NewManager returns the platform service manager for the given config path.
func NewManager(configPath string) (Manager, error) {
	return newManager(Config(Options{ConfigPath: configPath}))
}

func newManager(cfg *kservice.Config) (Manager, error) {
	svc, err := kservice.New(&FuncProgram{}, cfg)
	if err != nil {
		return nil, err
	}
	return &manager{svc: svc}, nil
}

type manager struct{ svc kservice.Service }

func (m *manager) Install() error   { return m.svc.Install() }
func (m *manager) Uninstall() error { return m.svc.Uninstall() }
func (m *manager) Start() error     { return m.svc.Start() }
func (m *manager) Stop() error      { return m.svc.Stop() }

func (m *manager) Status() (Status, error) {
	status, err := m.svc.Status()
	if err != nil {
		return StatusUnknown, err
	}
	return fromKardianos(status), nil
}

func fromKardianos(status kservice.Status) Status {
	switch status {
	case kservice.StatusRunning:
		return StatusRunning
	case kservice.StatusStopped:
		return StatusStopped
	default:
		return StatusUnknown
	}
}

// FuncProgram adapts functions to the kardianos service interface. Management
// commands use it as a no-op; "serve" uses it to hand its lifetime to the
// Windows service control manager.
type FuncProgram struct {
	StartFunc func() error
	StopFunc  func() error
}

func (p *FuncProgram) Start(kservice.Service) error {
	if p.StartFunc == nil {
		return nil
	}
	return p.StartFunc()
}

func (p *FuncProgram) Stop(kservice.Service) error {
	if p.StopFunc == nil {
		return nil
	}
	return p.StopFunc()
}

// Hosted reports whether the process was started by the Windows service
// control manager and must hand its lifetime to Run. On POSIX systems the
// service manager supervises signals directly, so serve keeps its own signal
// handling.
func Hosted() bool {
	return runtime.GOOS == "windows" && !kservice.Interactive()
}

// Run blocks while the OS service manager supervises program. It must only be
// called when Hosted reports true.
func Run(program kservice.Interface) error {
	svc, err := kservice.New(program, &kservice.Config{Name: Name})
	if err != nil {
		return err
	}
	return svc.Run()
}

// Platform names the detected service manager, or "" when none was found.
func Platform() string { return kservice.Platform() }
