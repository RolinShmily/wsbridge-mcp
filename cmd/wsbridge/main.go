// Command wsbridge is the single-binary local workspace bridge for MCP clients.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"wsbridge/internal/config"
	"wsbridge/internal/httpx"
)

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
	case "passwd":
		return runPasswd(commandArgs, stderr)
	case "grants":
		return runGrants(commandArgs, stderr)
	case "doctor":
		return runDoctor(commandArgs, stderr)
	case "service":
		return runService(commandArgs, stderr)
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
  serve    Start the HTTP bridge
  init     Create an example config.toml
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
	fmt.Fprintf(stdout, "  1. Edit %s and set public_url plus at least one [[workspace]].\n", cfgPath)
	fmt.Fprintf(stdout, "  2. Run: wsbridge passwd   (set the administrator password)\n")
	fmt.Fprintf(stdout, "  3. Run: wsbridge serve    (start the bridge behind your HTTPS tunnel)\n")
	return exitOK
}

func runServe(configFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	debugOAuth := fs.Bool("debug-oauth", false, "log sanitized OAuth handshake details")
	devCORS := fs.Bool("dev-cors", false, "allow localhost browser clients (MCP Inspector)")
	iKnow := fs.Bool("i-know-what-i-am-doing", false, "allow running as root/SYSTEM")
	allowHTTP := fs.Bool("allow-http-public-url", false, "allow an http:// public_url (loopback tests only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "wsbridge serve: unexpected arguments: %v\n", fs.Args())
		return exitUsage
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

	// M1 mounts the MCP endpoint here; M2 adds OAuth routes. The empty mux
	// deliberately produces 404 (never 3xx) for every path.
	mux := http.NewServeMux()
	srv := httpx.New(httpx.Options{
		Addr:       cfg.Listen,
		Handler:    mux,
		Logger:     logger,
		DebugOAuth: *debugOAuth,
		DevCORS:    *devCORS,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("wsbridge starting", "listen", cfg.Listen, "public_url", cfg.PublicURL)
	if err := srv.Start(ctx); err != nil {
		logger.Error("wsbridge stopped", "error", err)
		return exitError
	}
	logger.Info("wsbridge stopped")
	return exitOK
}

func runPasswd(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: wsbridge passwd")
		return exitUsage
	}
	return notImplemented("passwd", stderr)
}

func runGrants(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: wsbridge grants <list|revoke <grant_id>|revoke --all|prune>")
		return exitUsage
	}
	switch args[0] {
	case "list", "prune":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "wsbridge grants %s: unexpected arguments\n", args[0])
			return exitUsage
		}
		return notImplemented("grants "+args[0], stderr)
	case "revoke":
		if len(args) == 2 && args[1] == "--all" {
			return notImplemented("grants revoke --all", stderr)
		}
		if len(args) == 2 && args[1] != "" && !strings.HasPrefix(args[1], "-") {
			return notImplemented("grants revoke", stderr)
		}
		fmt.Fprintln(stderr, "usage: wsbridge grants revoke <grant_id> | --all")
		return exitUsage
	default:
		fmt.Fprintf(stderr, "wsbridge grants: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func runDoctor(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: wsbridge doctor")
		return exitUsage
	}
	return notImplemented("doctor", stderr)
}

func runService(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: wsbridge service <install|uninstall|start|stop|status>")
		return exitUsage
	}
	switch args[0] {
	case "install", "uninstall", "start", "stop", "status":
		return notImplemented("service "+args[0], stderr)
	default:
		fmt.Fprintf(stderr, "wsbridge service: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func notImplemented(name string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "wsbridge: %s is not implemented yet (see docs/development/04-milestones-and-tasks.md)\n", name)
	return exitError
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
