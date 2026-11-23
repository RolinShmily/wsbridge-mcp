// Command wsbridge is the single-binary local workspace bridge for MCP clients.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"wsbridge/internal/audit"
	"wsbridge/internal/config"
	"wsbridge/internal/control"
	"wsbridge/internal/httpx"
	"wsbridge/internal/mcpsrv"
	"wsbridge/internal/oauth"
	"wsbridge/internal/service"
	"wsbridge/internal/term"
	"wsbridge/internal/tunnel"
	"wsbridge/internal/ws"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	configFlag, rest, err := extractConfigFlag(args)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge: %v\n\n", err)
		printUsage(stderr)
		return exitUsage
	}
	if len(rest) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	command, commandArgs := rest[0], rest[1:]
	switch command {
	case "help", "-h", "--help":
		printUsage(stdout)
		return exitOK
	case "init":
		return runInit(configFlag, commandArgs, stdout, stderr)
	case "serve":
		return runServe(configFlag, commandArgs, stdout, stderr)
	case "use":
		return runUse(configFlag, commandArgs, stdout, stderr)
	case "passwd":
		return runPasswd(configFlag, commandArgs, os.Stdin, stdout, stderr)
	case "grants":
		return runGrants(configFlag, commandArgs, stdout, stderr)
	case "doctor":
		return runDoctor(configFlag, commandArgs, stdout, stderr)
	case "service":
		return runService(configFlag, commandArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "wsbridge: unknown command %q\n\n", command)
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `wsbridge - local workspace bridge for MCP clients

Usage:
  wsbridge [--config <path>] <command> [options]

Commands:
  serve    Start the HTTP bridge (defaults to current directory)
  use      Hot-switch the active workspace directory (defaults to .)
  init     Create config.toml and set up tunnel + passphrase
  passwd   Set the administrator password
  grants   List, revoke, or prune OAuth grants
  doctor   Diagnose configuration and public connectivity
  service  Manage the user-level background service
  help     Show this help

Global options:
  --config <path>  Path to config.toml
                   (default: <user config dir>/wsbridge/config.toml)
`)
}

// extractConfigFlag removes the global --config flag from args so every
// subcommand can accept it before or after the command name.
func extractConfigFlag(args []string) (string, []string, error) {
	var cfgPath string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("flag %s requires a value", arg)
			}
			i++
			cfgPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			cfgPath = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-config="):
			cfgPath = strings.TrimPrefix(arg, "-config=")
		default:
			rest = append(rest, arg)
		}
	}
	if cfgPath == "" && len(args) > 0 && containsConfigFlag(args) {
		return "", nil, fmt.Errorf("flag --config requires a non-empty value")
	}
	return cfgPath, rest, nil
}

func containsConfigFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--config" || arg == "-config" || strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			return true
		}
	}
	return false
}

func resolveConfigPath(flagPath string) (string, error) {
	if flagPath != "" {
		return filepath.Abs(flagPath)
	}
	return config.DefaultPath()
}

func runInit(configFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "overwrite an existing configuration file")
	nonInteractive := fs.Bool("non-interactive", false, "write the example config without prompting")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "wsbridge init: unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}

	cfgPath, err := resolveConfigPath(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		fmt.Fprintf(stderr, "wsbridge init: config already exists at %s (use --force to overwrite)\n", cfgPath)
		return exitError
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "wsbridge init: inspect %s: %v\n", cfgPath, err)
		return exitError
	}

	if !*nonInteractive && term.IsTerminal(os.Stdin) {
		return runInitInteractive(cfgPath, os.Stdin, stdout, stderr, func() (string, error) {
			return term.ReadPassword(os.Stdin)
		})
	}

	if err := config.WriteExample(cfgPath); err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: generated config is invalid: %v\n", err)
		return exitError
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "wsbridge init: create data directory %s: %v\n", dataDir, err)
		return exitError
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dataDir, 0o700); err != nil {
			fmt.Fprintf(stderr, "wsbridge init: secure data directory %s: %v\n", dataDir, err)
			return exitError
		}
	}

	fmt.Fprintf(stdout, "Created %s\n\n", cfgPath)
	fmt.Fprintf(stdout, "Next steps:\n")
	fmt.Fprintf(stdout, "  1. Edit %s and set public_url (plus [tunnel] if using cloudflared).\n", cfgPath)
	fmt.Fprintf(stdout, "  2. Run: wsbridge passwd   (set the administrator password)\n")
	fmt.Fprintf(stdout, "  3. Run: wsbridge serve    (from any project directory, or switch live with \"wsbridge use <dir>\")\n")
	return exitOK
}

func runInitInteractive(cfgPath string, in io.Reader, stdout, stderr io.Writer, readSecret func() (string, error)) int {
	reader := bufio.NewReader(in)
	prompt := func(label, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(stdout, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(stdout, "%s: ", label)
		}
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		val := strings.TrimSpace(line)
		if val == "" {
			return def, nil
		}
		return val, nil
	}

	fmt.Fprintln(stdout, "wsbridge interactive setup")
	fmt.Fprintf(stdout, "Config file: %s\n", cfgPath)
	fmt.Fprintln(stdout, "--------------------------")
	fmt.Fprintln(stdout, "Workspaces follow your working directory automatically (or switch live with \"wsbridge use\").")
	fmt.Fprintln(stdout, "Connection permissions are managed in the browser OAuth consent page.")

	fmt.Fprintln(stdout, "\nTunnel setup:")
	fmt.Fprintln(stdout, "  1) cloudflared (managed by wsbridge, recommended)")
	fmt.Fprintln(stdout, "  2) tailscale funnel (external: tailscale funnel --bg 8787)")
	fmt.Fprintln(stdout, "  3) none / custom reverse proxy")
	choice, err := prompt("Select tunnel option (1/2/3)", "1")
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	var tun config.Tunnel
	switch choice {
	case "1", "cloudflared":
		tun.Provider = "cloudflared"
		for {
			fmt.Fprint(stdout, "Paste Cloudflare tunnel token: ")
			rawTok, err := readSecret()
			fmt.Fprintln(stdout)
			if err != nil {
				fmt.Fprintf(stderr, "wsbridge init: read tunnel token: %v\n", err)
				return exitError
			}
			tok := extractCloudflaredToken(rawTok)
			if tok == "" {
				fmt.Fprintln(stderr, "wsbridge init: tunnel token cannot be empty")
				continue
			}
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
				fmt.Fprintf(stderr, "wsbridge init: create config directory: %v\n", err)
				return exitError
			}
			tokenPath := filepath.Join(filepath.Dir(cfgPath), "cloudflared-token")
			if err := os.WriteFile(tokenPath, []byte(tok), 0o600); err != nil {
				fmt.Fprintf(stderr, "wsbridge init: write tunnel token: %v\n", err)
				return exitError
			}
			tun.TokenFile = "cloudflared-token"
			fmt.Fprintf(stdout, "Saved tunnel token to %s (0600)\n", tokenPath)
			break
		}
	case "2", "tailscale":
		tun.Provider = "none"
	default:
		tun.Provider = "none"
	}

	publicURL, err := prompt("\nPublic HTTPS URL (e.g. https://bridge.example.com)", "")
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	listen, err := prompt("Local listen address", config.DefaultListen)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}

	cfg := &config.Config{
		PublicURL:            publicURL,
		Listen:               listen,
		MaxSnapshotsPerGrant: config.DefaultMaxSnapshotsPerGrant,
		Tunnel:               tun,
	}
	if err := cfg.Save(cfgPath); err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	cfg, err = config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: invalid configuration: %v\n", err)
		return exitError
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "wsbridge init: create data directory %s: %v\n", dataDir, err)
		return exitError
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dataDir, 0o700)
	}

	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge init: open database: %v\n", err)
		return exitError
	}
	existingHash, err := store.AdminHash()
	if err == nil && strings.TrimSpace(existingHash) == "" {
		setPass, err := prompt("\nSet administrator passphrase now? (Y/n)", "y")
		if err == nil && (strings.EqualFold(setPass, "y") || strings.EqualFold(setPass, "yes")) {
			for {
				fmt.Fprint(stdout, "New administrator passphrase (min 10 chars): ")
				first, err := readSecret()
				fmt.Fprintln(stdout)
				if err != nil {
					_ = store.Close()
					fmt.Fprintf(stderr, "wsbridge init: read passphrase: %v\n", err)
					return exitError
				}
				if utf8.RuneCountInString(first) < 10 {
					fmt.Fprintln(stderr, "wsbridge init: passphrase must be at least 10 characters")
					continue
				}
				fmt.Fprint(stdout, "Confirm passphrase: ")
				second, err := readSecret()
				fmt.Fprintln(stdout)
				if err != nil {
					_ = store.Close()
					fmt.Fprintf(stderr, "wsbridge init: read passphrase: %v\n", err)
					return exitError
				}
				if first != second {
					fmt.Fprintln(stderr, "wsbridge init: passphrases do not match")
					continue
				}
				hash, err := oauth.HashAdminPassphrase(first, oauth.DefaultArgon2Params)
				if err != nil {
					_ = store.Close()
					fmt.Fprintf(stderr, "wsbridge init: hash passphrase: %v\n", err)
					return exitError
				}
				if err := store.SetAdminHash(hash); err != nil {
					_ = store.Close()
					fmt.Fprintf(stderr, "wsbridge init: save passphrase: %v\n", err)
					return exitError
				}
				break
			}
		}
	}
	_ = store.Close()

	fmt.Fprintf(stdout, "\nSaved configuration: %s\n", cfgPath)
	fmt.Fprintf(stdout, "MCP Endpoint URL:    %s/mcp\n\n", strings.TrimRight(cfg.PublicURL, "/"))
	fmt.Fprintln(stdout, "Next steps:")
	if choice == "2" || choice == "tailscale" {
		fmt.Fprintf(stdout, "  1. Start Tailscale Funnel: tailscale funnel --bg %s\n", portFromListen(cfg.Listen))
		fmt.Fprintln(stdout, "  2. In any project directory, run: wsbridge serve")
		fmt.Fprintln(stdout, "     (or switch a running daemon anytime with: wsbridge use <dir>)")
		fmt.Fprintln(stdout, "  3. Run: wsbridge doctor --timeout 10s")
	} else {
		fmt.Fprintln(stdout, "  1. In any project directory, run: wsbridge serve")
		fmt.Fprintln(stdout, "     (or switch a running daemon anytime with: wsbridge use <dir>)")
		fmt.Fprintln(stdout, "  2. Run: wsbridge doctor --timeout 10s")
	}
	return exitOK
}

func portFromListen(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "8787"
	}
	return port
}

func extractCloudflaredToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) >= 2 && strings.Contains(strings.ToLower(fields[0]), "cloudflared") {
		return fields[len(fields)-1]
	}
	return trimmed
}

func runServe(configFlag string, args []string, stdout, stderr io.Writer) int {
	return runServeContext(context.Background(), configFlag, args, stdout, stderr)
}

func runServeContext(parent context.Context, configFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	debugOAuth := fs.Bool("debug-oauth", false, "log sanitized OAuth handshake details")
	devCORS := fs.Bool("dev-cors", false, "allow localhost browser clients (MCP Inspector)")
	iKnow := fs.Bool("i-know-what-i-am-doing", false, "allow running as root/SYSTEM")
	allowHTTP := fs.Bool("allow-http-public-url", false, "allow an http:// public_url (loopback tests only)")
	maxPermFlag := fs.String("max-perm", "", "optional local permission cap (read, write, or check)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "wsbridge serve: expected at most 1 workspace directory, got: %v\n", fs.Args())
		return exitUsage
	}
	dirArg := ""
	if fs.NArg() == 1 {
		dirArg = fs.Arg(0)
	}

	cfgPath, err := resolveConfigPath(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	cfg, err := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: *allowHTTP})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}

	localCap, err := ws.ParsePermission(string(cfg.EffectiveMaxPerm()))
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	if strings.TrimSpace(*maxPermFlag) != "" {
		overrideCap, err := ws.ParsePermission(*maxPermFlag)
		if err != nil {
			fmt.Fprintf(stderr, "wsbridge serve: --max-perm: %v\n", err)
			return exitUsage
		}
		localCap = ws.MinPermission(localCap, overrideCap)
	}

	if !*iKnow {
		if account, elevated := elevatedAccount(); elevated {
			fmt.Fprintf(stderr, "wsbridge serve: refusing to run as %s; use an unprivileged user or pass --i-know-what-i-am-doing\n", account)
			return exitError
		}
	}

	level := slog.LevelInfo
	if *debugOAuth {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if *debugOAuth {
		logger.Info("debug-oauth enabled; sensitive values are redacted")
	}

	listen := cfg.Listen

	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	workspaces, err := resolveInitialWorkspaces(cfg, dataDir, dirArg, localCap, service.Hosted(), logger)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	manager, err := ws.NewManager(workspaces, ws.ManagerOptions{
		DataDir:              dataDir,
		MaxSnapshotsPerGrant: cfg.MaxSnapshotsPerGrant,
		DenyPatterns:         cfg.DenyPatterns,
	})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	defer manager.Close()

	auditLogger, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	defer auditLogger.Close()

	mux := http.NewServeMux()
	store, err := oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	defer store.Close()
	if store.IssuerChanged() {
		logger.Warn("public_url issuer changed; all existing grants and tokens were revoked")
	}
	adminHash, err := store.AdminHash()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	if strings.TrimSpace(adminHash) == "" {
		fmt.Fprintln(stderr, "wsbridge serve: administrator passphrase is not set; run \"wsbridge passwd\" first")
		return exitError
	}
	authServer, err := oauth.New(oauth.Config{
		Issuer:             cfg.PublicURL,
		Store:              store,
		Audit:              auditLogger,
		Logger:             logger,
		AllowRedirectHosts: cfg.AllowRedirectHosts,
		WorkspacesProvider: func() []oauth.WorkspaceChoice {
			return managerWorkspaceChoices(manager)
		},
		LocalMaxPerm: localCap,
	})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	authServer.Mount(mux)
	stopGC := store.StartGC(oauth.GCInterval)
	defer stopGC()

	mcpServer, err := mcpsrv.New(mcpsrv.Options{
		Manager: manager,
		Version: version,
		Logger:  logger,
		Audit:   auditLogger,
		Scope:   mcpsrv.GrantScope(manager),
		Auth: &mcpsrv.AuthConfig{
			Verifier:            store,
			ResourceURL:         authServer.ResourceURL(),
			ResourceMetadataURL: authServer.ResourceMetadataURL(),
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: %v\n", err)
		return exitError
	}
	mcpServer.Mount(mux)

	ctrlServer, err := control.Start(dataDir, control.Handlers{
		List: func() []control.WorkspaceInfo {
			return managerControlWorkspaces(manager)
		},
		Switch: func(targetPath, customName string) (control.WorkspaceInfo, error) {
			absPath, name, err := resolveWorkspaceDir(targetPath, customName)
			if err != nil {
				return control.WorkspaceInfo{}, err
			}
			active, err := manager.SetActive(ws.WorkspaceConfig{
				Name:    name,
				Path:    absPath,
				MaxPerm: localCap,
			})
			if err != nil {
				return control.WorkspaceInfo{}, err
			}
			if saveErr := control.SaveActiveWorkspace(dataDir, control.ActiveWorkspace{
				Name: active.Name(),
				Path: active.HostPath(),
			}); saveErr != nil {
				logger.Warn("save active workspace state failed", "error", saveErr)
			}
			if logErr := auditLogger.Log("workspace_switch", map[string]any{
				"workspace": active.Name(),
				"path":      active.HostPath(),
			}); logErr != nil {
				logger.Warn("audit write failed", "event", "workspace_switch", "error", logErr)
			}
			logger.Info("active workspace switched", "workspace", active.Name(), "path", active.HostPath())
			return control.WorkspaceInfo{
				Name:    active.Name(),
				Path:    active.HostPath(),
				MaxPerm: active.MaxPerm().String(),
			}, nil
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge serve: start local control server: %v\n", err)
		return exitError
	}
	defer func() { _ = ctrlServer.Close(context.Background()) }()

	srv := httpx.New(httpx.Options{
		Addr:       listen,
		Handler:    mux,
		Logger:     logger,
		DebugOAuth: *debugOAuth,
		DevCORS:    *devCORS,
	})

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tunnelDone chan error
	if cfg.Tunnel.Provider == "cloudflared" {
		runner := tunnel.NewCloudflaredRunner(tunnel.CloudflaredOptions{
			Binary:    cfg.Tunnel.Binary,
			TokenFile: cfg.Tunnel.TokenFile,
			TokenEnv:  cfg.Tunnel.TokenEnv,
			Listen:    listen,
			Logger:    logger,
		})
		tunnelDone = make(chan error, 1)
		go func() {
			err := runner.Run(ctx)
			if err != nil {
				logger.Error("managed tunnel failed", "error", err)
				stop()
			}
			tunnelDone <- err
		}()
	}

	activeNames := manager.Names()
	logger.Info("wsbridge starting", "listen", listen, "public_url", cfg.PublicURL, "workspaces", activeNames, "max_perm", localCap.String())
	var exitCode int
	if service.Hosted() {
		exitCode = runHostedServe(ctx, stop, srv, logger)
	} else if err := srv.Start(ctx); err != nil {
		logger.Error("wsbridge stopped", "error", err)
		exitCode = exitError
	} else {
		logger.Info("wsbridge stopped")
		exitCode = exitOK
	}
	stop()
	if tunnelDone != nil {
		if err := <-tunnelDone; err != nil && exitCode == exitOK {
			exitCode = exitError
		}
	}
	return exitCode
}

// runHostedServe hands the process lifetime to the Windows service control
// manager. Start launches the HTTP server in the background because the
// service manager requires Start to return quickly; Stop cancels the server
// context so Start performs a graceful shutdown.
func runHostedServe(ctx context.Context, stop context.CancelFunc, srv *httpx.Server, logger *slog.Logger) int {
	return runHostedServeWith(ctx, stop, srv, logger, func(program *service.FuncProgram) error {
		return service.Run(program)
	})
}

// runHostedServeWith is runHostedServe with an injectable service runner so
// the shutdown sequence can be tested on every platform.
func runHostedServeWith(ctx context.Context, stop context.CancelFunc, srv *httpx.Server, logger *slog.Logger, run func(*service.FuncProgram) error) int {
	var started atomic.Bool
	serveErr := make(chan error, 1)
	program := &service.FuncProgram{
		StartFunc: func() error {
			started.Store(true)
			go func() { serveErr <- srv.Start(ctx) }()
			return nil
		},
		StopFunc: func() error {
			stop()
			return nil
		},
	}
	runErr := run(program)
	// The manager may exit without sending a stop request (for example after
	// a fatal SCM error), so always cancel the server context.
	stop()
	var err error
	if started.Load() {
		err = <-serveErr
	}
	if runErr != nil {
		logger.Error("windows service control failed", "error", runErr)
		return exitError
	}
	if err != nil {
		logger.Error("wsbridge stopped", "error", err)
		return exitError
	}
	logger.Info("wsbridge stopped")
	return exitOK
}

func resolveInitialWorkspaces(cfg *config.Config, dataDir, dirArg string, localCap ws.Permission, hosted bool, logger *slog.Logger) ([]ws.WorkspaceConfig, error) {
	if strings.TrimSpace(dirArg) != "" {
		absPath, name, err := resolveWorkspaceDir(dirArg, "")
		if err != nil {
			return nil, err
		}
		if err := control.SaveActiveWorkspace(dataDir, control.ActiveWorkspace{Name: name, Path: absPath}); err != nil && logger != nil {
			logger.Warn("save active workspace state failed", "error", err)
		}
		return []ws.WorkspaceConfig{{Name: name, Path: absPath, MaxPerm: localCap}}, nil
	}
	if len(cfg.Workspaces) > 0 {
		out, err := workspaceConfigs(cfg)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].MaxPerm = ws.MinPermission(out[i].MaxPerm, localCap)
		}
		return out, nil
	}
	if hosted {
		saved, err := control.LoadActiveWorkspace(dataDir)
		if err == nil {
			absPath, name, dirErr := resolveWorkspaceDir(saved.Path, saved.Name)
			if dirErr == nil {
				return []ws.WorkspaceConfig{{Name: name, Path: absPath, MaxPerm: localCap}}, nil
			}
			if logger != nil {
				logger.Warn("saved active workspace is not accessible; starting without an active workspace", "path", saved.Path, "error", dirErr)
			}
		} else if logger != nil {
			logger.Info(`no active workspace selected yet; run "wsbridge use <dir>" to select a project`)
		}
		return nil, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	absPath, name, err := resolveWorkspaceDir(cwd, "")
	if err != nil {
		return nil, err
	}
	if err := control.SaveActiveWorkspace(dataDir, control.ActiveWorkspace{Name: name, Path: absPath}); err != nil && logger != nil {
		logger.Warn("save active workspace state failed", "error", err)
	}
	return []ws.WorkspaceConfig{{Name: name, Path: absPath, MaxPerm: localCap}}, nil
}

func resolveWorkspaceDir(rawPath, customName string) (absPath, name string, err error) {
	target := strings.TrimSpace(rawPath)
	if target == "" {
		target = "."
	}
	absPath, err = filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("resolve directory %q: %w", rawPath, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", "", fmt.Errorf("directory %q is not accessible: %w", absPath, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("%q is not a directory", absPath)
	}
	name = strings.TrimSpace(customName)
	if name == "" {
		name = ws.DeriveWorkspaceName(absPath)
	}
	return absPath, name, nil
}

func managerWorkspaceChoices(manager *ws.Manager) []oauth.WorkspaceChoice {
	active := manager.Workspaces()
	out := make([]oauth.WorkspaceChoice, 0, len(active))
	for _, w := range active {
		out = append(out, oauth.WorkspaceChoice{
			Name:    w.Name(),
			Path:    w.HostPath(),
			MaxPerm: w.MaxPerm(),
			Checks:  w.AllowedChecks(),
		})
	}
	return out
}

func managerControlWorkspaces(manager *ws.Manager) []control.WorkspaceInfo {
	active := manager.Workspaces()
	out := make([]control.WorkspaceInfo, 0, len(active))
	for _, w := range active {
		out = append(out, control.WorkspaceInfo{
			Name:    w.Name(),
			Path:    w.HostPath(),
			MaxPerm: w.MaxPerm().String(),
		})
	}
	return out
}

func runUse(configFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	fs.SetOutput(stderr)
	nameFlag := fs.String("name", "", "optional workspace name (defaults to directory basename)")
	show := fs.Bool("show", false, "display the currently active workspace without switching")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *show && fs.NArg() != 0 {
		fmt.Fprintln(stderr, "wsbridge use: --show does not take a directory argument")
		return exitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "wsbridge use: expected at most 1 directory argument, got: %v\n", fs.Args())
		return exitUsage
	}

	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge use: %v\n", err)
		return exitError
	}

	if *show {
		live, err := control.GetWorkspaces(context.Background(), dataDir)
		if err == nil {
			if len(live) == 0 {
				fmt.Fprintln(stdout, "No active workspace selected (wsbridge serve is running).")
				return exitOK
			}
			for _, w := range live {
				fmt.Fprintf(stdout, "%s\t%s\t(max_perm=%s, live)\n", w.Name, w.Path, w.MaxPerm)
			}
			return exitOK
		}
		if !errors.Is(err, control.ErrNotRunning) {
			fmt.Fprintf(stderr, "wsbridge use: query running server: %v\n", err)
			return exitError
		}
		if saved, loadErr := control.LoadActiveWorkspace(dataDir); loadErr == nil {
			fmt.Fprintf(stdout, "%s\t%s\t(saved, server not running)\n", saved.Name, saved.Path)
			return exitOK
		}
		if len(cfg.Workspaces) > 0 {
			for _, w := range cfg.Workspaces {
				fmt.Fprintf(stdout, "%s\t%s\t(configured, server not running)\n", w.Name, w.Path)
			}
			return exitOK
		}
		fmt.Fprintln(stdout, "No active workspace saved (wsbridge serve is not running).")
		return exitOK
	}

	target := "."
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	absPath, name, err := resolveWorkspaceDir(target, *nameFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge use: %v\n", err)
		return exitError
	}
	if err := control.SaveActiveWorkspace(dataDir, control.ActiveWorkspace{Name: name, Path: absPath}); err != nil {
		fmt.Fprintf(stderr, "wsbridge use: %v\n", err)
		return exitError
	}

	switched, err := control.SwitchWorkspace(context.Background(), dataDir, absPath, name)
	if err == nil {
		fmt.Fprintf(stdout, "Switched active workspace to %s (%s)\n", switched.Name, switched.Path)
		return exitOK
	}
	if errors.Is(err, control.ErrNotRunning) {
		fmt.Fprintf(stdout, "Saved active workspace: %s (%s)\n", name, absPath)
		fmt.Fprintln(stdout, "Note: wsbridge serve is not running; this workspace will be used on next start.")
		return exitOK
	}
	fmt.Fprintf(stderr, "wsbridge use: %v\n", err)
	return exitError
}

func workspaceConfigs(cfg *config.Config) ([]ws.WorkspaceConfig, error) {
	out := make([]ws.WorkspaceConfig, 0, len(cfg.Workspaces))
	for _, wsCfg := range cfg.Workspaces {
		permRaw := wsCfg.MaxPerm
		if permRaw == "" {
			permRaw = cfg.EffectiveMaxPerm()
		}
		perm, err := ws.ParsePermission(string(permRaw))
		if err != nil {
			return nil, fmt.Errorf("workspace %q: %w", wsCfg.Name, err)
		}
		out = append(out, ws.WorkspaceConfig{
			Name:    wsCfg.Name,
			Path:    wsCfg.Path,
			MaxPerm: perm,
			Checks:  wsCfg.Checks,
		})
	}
	return out, nil
}

func loadConfigAndDataDir(configFlag string) (*config.Config, string, error) {
	cfgPath, err := resolveConfigPath(configFlag)
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// Local maintenance commands may operate on loopback-only test
		// configurations that use an http:// public_url. serve still requires
		// the explicit --allow-http-public-url flag.
		relaxed, relaxedErr := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: true})
		if relaxedErr != nil || !isLoopbackListen(relaxed.Listen) {
			return nil, "", err
		}
		cfg = relaxed
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		return nil, "", err
	}
	return cfg, dataDir, nil
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func openCLIStore(cfg *config.Config, dataDir string) (*oauth.Store, error) {
	return oauth.OpenStore(filepath.Join(dataDir, "wsbridge.db"), oauth.StoreOptions{Issuer: cfg.PublicURL})
}

func runPasswd(configFlag string, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: wsbridge passwd")
		return exitUsage
	}
	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: %v\n", err)
		return exitError
	}

	fmt.Fprint(stderr, "New administrator passphrase (at least 10 characters): ")
	first, err := term.ReadPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: read passphrase: %v\n", err)
		return exitError
	}
	if utf8.RuneCountInString(first) < 10 {
		fmt.Fprintln(stderr, "wsbridge passwd: passphrase must be at least 10 characters")
		return exitError
	}
	fmt.Fprint(stderr, "Confirm administrator passphrase: ")
	second, err := term.ReadPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: read confirmation: %v\n", err)
		return exitError
	}
	if first != second {
		fmt.Fprintln(stderr, "wsbridge passwd: passphrases do not match")
		return exitError
	}

	hash, err := oauth.HashAdminPassphrase(first, oauth.DefaultArgon2Params)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: %v\n", err)
		return exitError
	}
	store, err := openCLIStore(cfg, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: %v\n", err)
		return exitError
	}
	defer store.Close()
	if err := store.SetAdminHash(hash); err != nil {
		fmt.Fprintf(stderr, "wsbridge passwd: store passphrase hash: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "Administrator passphrase updated in %s\n", filepath.Join(dataDir, "wsbridge.db"))
	return exitOK
}

func runGrants(configFlag string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: wsbridge grants <list|revoke <grant_id>|revoke --all|prune>")
		return exitUsage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "wsbridge grants list: unexpected arguments")
			return exitUsage
		}
		return grantsList(configFlag, stdout, stderr)
	case "prune":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "wsbridge grants prune: unexpected arguments")
			return exitUsage
		}
		return grantsPrune(configFlag, stdout, stderr)
	case "revoke":
		if len(args) == 2 && args[1] == "--all" {
			return grantsRevokeAll(configFlag, stdout, stderr)
		}
		if len(args) == 2 && args[1] != "" && !strings.HasPrefix(args[1], "-") {
			return grantsRevoke(configFlag, args[1], stdout, stderr)
		}
		fmt.Fprintln(stderr, "usage: wsbridge grants revoke <grant_id> | --all")
		return exitUsage
	default:
		fmt.Fprintf(stderr, "wsbridge grants: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func grantsList(configFlag string, stdout, stderr io.Writer) int {
	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants list: %v\n", err)
		return exitError
	}
	store, err := openCLIStore(cfg, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants list: %v\n", err)
		return exitError
	}
	defer store.Close()
	grants, err := store.ListGrants()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants list: %v\n", err)
		return exitError
	}
	if len(grants) == 0 {
		fmt.Fprintln(stdout, "No grants.")
		return exitOK
	}
	now := time.Now()
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT ID\tCLIENT\tWORKSPACES\tCREATED\tEXPIRES\tSTATUS")
	for _, g := range grants {
		client := g.ClientName
		if client == "" {
			client = g.ClientID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			g.GrantID, client, formatGrantWorkspaces(g.Workspaces),
			g.CreatedAt.Local().Format("2006-01-02 15:04"),
			g.ExpiresAt.Local().Format("2006-01-02 15:04"),
			g.Status(now))
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "wsbridge grants list: write output: %v\n", err)
		return exitError
	}
	return exitOK
}

func formatGrantWorkspaces(workspaces map[string]ws.Permission) string {
	names := make([]string, 0, len(workspaces))
	for name := range workspaces {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		label := name
		if name == oauth.WildcardWorkspace {
			label = "all(dynamic)"
		}
		parts = append(parts, fmt.Sprintf("%s:%s", label, workspaces[name]))
	}
	return strings.Join(parts, ", ")
}

func grantsRevoke(configFlag, grantID string, stdout, stderr io.Writer) int {
	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	store, err := openCLIStore(cfg, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	defer store.Close()
	found, err := store.RevokeGrant(grantID)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	if !found {
		fmt.Fprintf(stderr, "wsbridge grants revoke: grant %q not found\n", grantID)
		return exitError
	}
	appendAudit(dataDir, stderr, "grant_revoke", map[string]any{
		"grant_id": grantID, "reason": "cli",
	})
	fmt.Fprintf(stdout, "Revoked grant %s\n", grantID)
	return exitOK
}

func grantsRevokeAll(configFlag string, stdout, stderr io.Writer) int {
	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	store, err := openCLIStore(cfg, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	defer store.Close()
	count, err := store.RevokeAll()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants revoke: %v\n", err)
		return exitError
	}
	appendAudit(dataDir, stderr, "grant_revoke", map[string]any{
		"reason": "cli_all", "count": count,
	})
	fmt.Fprintf(stdout, "Revoked %d grant(s)\n", count)
	return exitOK
}

func grantsPrune(configFlag string, stdout, stderr io.Writer) int {
	cfg, dataDir, err := loadConfigAndDataDir(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants prune: %v\n", err)
		return exitError
	}
	store, err := openCLIStore(cfg, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants prune: %v\n", err)
		return exitError
	}
	defer store.Close()
	grants, tokens, err := store.Prune()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants prune: %v\n", err)
		return exitError
	}
	remaining, err := store.ListGrants()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants prune: list remaining grants: %v\n", err)
		return exitError
	}
	active := make(map[string]bool, len(remaining))
	for _, g := range remaining {
		active[g.GrantID] = true
	}
	snapshots, err := pruneOrphanSnapshots(dataDir, active)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge grants prune: remove orphaned snapshots: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "Pruned %d grant(s), %d token record(s), and %d orphaned snapshot director(ies)\n",
		len(grants), tokens, snapshots)
	return exitOK
}

// pruneOrphanSnapshots removes snapshot directories whose grant no longer
// exists in the database.
func pruneOrphanSnapshots(dataDir string, active map[string]bool) (int, error) {
	dir := filepath.Join(dataDir, "snapshots")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if active[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func appendAudit(dataDir string, stderr io.Writer, event string, fields map[string]any) {
	logger, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge: warning: audit log: %v\n", err)
		return
	}
	defer logger.Close()
	if err := logger.Log(event, fields); err != nil {
		fmt.Fprintf(stderr, "wsbridge: warning: audit log: %v\n", err)
	}
}

func runDoctor(configFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	allowHTTP := fs.Bool("allow-http-public-url", false, "allow an http:// public_url (loopback tests only)")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout for each public connectivity check")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "wsbridge doctor: unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	cfgPath, err := resolveConfigPath(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge doctor: %v\n", err)
		return exitError
	}
	cfg, err := config.LoadWithOptions(cfgPath, config.LoadOptions{AllowHTTPPublicURL: *allowHTTP})
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge doctor: %v\n", err)
		return exitError
	}
	dataDir, err := cfg.ResolvedDataDir()
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge doctor: %v\n", err)
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	checks := tunnel.Run(ctx, tunnel.Options{Config: cfg, DataDir: dataDir, Timeout: *timeout})
	fmt.Fprintln(stdout, "wsbridge doctor")
	for _, check := range checks {
		fmt.Fprintf(stdout, "[%s] %s: %s\n", check.Level, check.Name, check.Detail)
	}
	failures := tunnel.Count(checks, tunnel.Fail)
	warnings := tunnel.Count(checks, tunnel.Warn)
	if failures > 0 {
		fmt.Fprintf(stdout, "\n%d critical issue(s), %d warning(s).\n", failures, warnings)
		return exitError
	}
	fmt.Fprintf(stdout, "\nAll critical checks passed (%d warning(s)).\n", warnings)
	return exitOK
}

// serviceManagerFactory builds the platform service manager for a config path.
// Tests substitute a fake so no real service is installed.
type serviceManagerFactory func(configPath string) (service.Manager, error)

func runService(configFlag string, args []string, stdout, stderr io.Writer) int {
	return runServiceWith(service.NewManager, configFlag, args, stdout, stderr)
}

func runServiceWith(newManager serviceManagerFactory, configFlag string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: wsbridge service <install|uninstall|start|stop|status>")
		return exitUsage
	}
	action := args[0]
	switch action {
	case "install", "uninstall", "start", "stop", "status":
	default:
		fmt.Fprintf(stderr, "wsbridge service: unknown subcommand %q\n", action)
		return exitUsage
	}

	cfgPath, err := resolveConfigPath(configFlag)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge service: %v\n", err)
		return exitError
	}
	absPath, err := filepath.Abs(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge service: %v\n", err)
		return exitError
	}
	if action == "install" {
		// The installed service always runs "--config <absPath> serve", so the
		// configuration must already be valid; otherwise the service would
		// install successfully and then crash-loop.
		if _, err := config.Load(absPath); err != nil {
			fmt.Fprintf(stderr, "wsbridge service install: %v\n", err)
			return exitError
		}
	}

	manager, err := newManager(absPath)
	if err != nil {
		fmt.Fprintf(stderr, "wsbridge service: %v\n", err)
		return exitError
	}

	switch action {
	case "install":
		if err := manager.Install(); err != nil {
			printServiceError(action, err, stderr)
			return exitError
		}
		fmt.Fprintf(stdout, "Service %q installed for the current user.\n", service.Name)
		fmt.Fprintf(stdout, "  Config: %s\n", absPath)
		fmt.Fprintf(stdout, "  Start:  wsbridge service start\n")
	case "uninstall":
		if err := manager.Uninstall(); err != nil {
			printServiceError(action, err, stderr)
			return exitError
		}
		fmt.Fprintf(stdout, "Service %q uninstalled.\n", service.Name)
	case "start":
		if err := manager.Start(); err != nil {
			printServiceError(action, err, stderr)
			return exitError
		}
		fmt.Fprintf(stdout, "Service %q started.\n", service.Name)
	case "stop":
		if err := manager.Stop(); err != nil {
			printServiceError(action, err, stderr)
			return exitError
		}
		fmt.Fprintf(stdout, "Service %q stopped.\n", service.Name)
	case "status":
		status, err := manager.Status()
		if err != nil {
			printServiceError(action, err, stderr)
			return exitError
		}
		if status == service.StatusUnknown {
			fmt.Fprintf(stdout, "Service %q status is unknown.\n", service.Name)
			return exitError
		}
		fmt.Fprintf(stdout, "Service %q is %s.\n", service.Name, status)
	}
	return exitOK
}

func printServiceError(action string, err error, stderr io.Writer) {
	if errors.Is(err, service.ErrNotInstalled) {
		fmt.Fprintf(stderr, "wsbridge service %s: service is not installed; run \"wsbridge service install\"\n", action)
		return
	}
	fmt.Fprintf(stderr, "wsbridge service %s: %v\n", action, err)
}

// elevatedAccount reports the privileged account name when wsbridge must
// refuse to start without an explicit override.
func elevatedAccount() (string, bool) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return "root", true
	}
	u, err := user.Current()
	if err != nil {
		return "", false
	}
	if runtime.GOOS == "windows" && isSystemAccount(u.Username) {
		return u.Username, true
	}
	return "", false
}

// isSystemAccount matches the Windows SYSTEM account, including domain forms
// such as NT AUTHORITY\SYSTEM.
func isSystemAccount(username string) bool {
	name := username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return strings.EqualFold(name, "SYSTEM")
}
