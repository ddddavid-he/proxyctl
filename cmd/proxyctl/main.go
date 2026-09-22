// Command proxyctl is the local-only control CLI for the private proxy
// skeleton. It has no data plane, no external command execution, and no
// network listeners. See docs/proxyctl-cli.md for the full contract.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"proxyctl/internal/preflight"
	"proxyctl/internal/render"
	"proxyctl/internal/safex"
	"proxyctl/internal/status"
	"proxyctl/internal/verify"
)

// version metadata injected via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

const usageText = `proxyctl - local-only proxy control skeleton (L1)

Usage:
  proxyctl preflight --role gateway|egress [--offline] [--config PATH]
  proxyctl render --role gateway|egress --template-dir DIR --config PATH --out-dir DIR
  proxyctl verify --profile loopback|canary
  proxyctl status [--json] [--state-dir DIR]
  proxyctl version

Flags are parsed strictly: unknown flags, unknown commands and invalid
enum values fail with a stable non-zero exit code and a safe error.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return safex.CodeUsage.ExitCode()
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "preflight":
		return cmdPreflight(rest)
	case "render":
		return cmdRender(rest)
	case "verify":
		return cmdVerify(rest)
	case "status":
		return cmdStatus(rest)
	case "version":
		return cmdVersion()
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	default:
		return fail(safex.New(safex.CodeUnknownCommand, "unknown command %q", cmd))
	}
}

// strictFlagSet creates a FlagSet that errors on unknown flags and does
// not print its own diagnostics (we own the output format).
func strictFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {}
	return fs
}

func unknownFlagError(cmd string, err error) *safex.Error {
	return safex.New(safex.CodeUnknownFlag, "unknown or malformed flag in %s: %v", cmd, err)
}

func cmdPreflight(args []string) int {
	fs := strictFlagSet("preflight")
	role := fs.String("role", "", "host role: gateway or egress")
	offline := fs.Bool("offline", false, "skip any environment probing (no DNS/network)")
	configPath := fs.String("config", "", "optional role config for static checks")
	if err := fs.Parse(args); err != nil {
		return fail(unknownFlagError("preflight", err))
	}
	if fs.NArg() > 0 {
		return fail(safex.New(safex.CodeUnknownFlag, "unexpected positional arguments to preflight"))
	}
	if *role == "" {
		return fail(safex.New(safex.CodeUsage, "preflight requires --role gateway|egress"))
	}
	res, err := preflight.Run(preflight.Options{
		Role: *role, Offline: *offline, ConfigPath: *configPath,
	})
	if err != nil {
		return fail(err)
	}
	printJSON(res)
	if !res.OK {
		return safex.CodeConfigRejected.ExitCode()
	}
	return 0
}

func cmdRender(args []string) int {
	fs := strictFlagSet("render")
	role := fs.String("role", "", "host role: gateway or egress")
	templateDir := fs.String("template-dir", "", "directory containing the allowlisted templates")
	configPath := fs.String("config", "", "role config document (placeholders only)")
	outDir := fs.String("out-dir", "", "explicit caller-isolated output directory (must exist)")
	if err := fs.Parse(args); err != nil {
		return fail(unknownFlagError("render", err))
	}
	if fs.NArg() > 0 {
		return fail(safex.New(safex.CodeUnknownFlag, "unexpected positional arguments to render"))
	}
	if *role == "" {
		return fail(safex.New(safex.CodeUsage, "render requires --role gateway|egress"))
	}
	res, err := render.Run(render.Options{
		Role: *role, TemplateDir: *templateDir, ConfigPath: *configPath, OutDir: *outDir,
	})
	if err != nil {
		return fail(err)
	}
	printJSON(res)
	return 0
}

func cmdVerify(args []string) int {
	fs := strictFlagSet("verify")
	profile := fs.String("profile", "", "verification profile: loopback or canary")
	if err := fs.Parse(args); err != nil {
		return fail(unknownFlagError("verify", err))
	}
	if fs.NArg() > 0 {
		return fail(safex.New(safex.CodeUnknownFlag, "unexpected positional arguments to verify"))
	}
	if *profile == "" {
		return fail(safex.New(safex.CodeUsage, "verify requires --profile loopback|canary"))
	}
	res, err := verify.Run(verify.Options{Profile: *profile})
	if err != nil {
		return fail(err)
	}
	printJSON(res)
	if !res.OK {
		return safex.CodeConfigRejected.ExitCode()
	}
	return 0
}

func cmdStatus(args []string) int {
	fs := strictFlagSet("status")
	asJSON := fs.Bool("json", false, "output JSON")
	stateDir := fs.String("state-dir", "", "optional caller-isolated state directory")
	if err := fs.Parse(args); err != nil {
		return fail(unknownFlagError("status", err))
	}
	if fs.NArg() > 0 {
		return fail(safex.New(safex.CodeUnknownFlag, "unexpected positional arguments to status"))
	}
	status.Version, status.Commit, status.BuildTime = version, commit, buildTime
	rep, err := status.Collect(status.Options{StateDir: *stateDir})
	if err != nil {
		return fail(err)
	}
	if *asJSON {
		printJSON(rep)
		return 0
	}
	fmt.Printf("proxyctl %s (commit %s, built %s)\n", rep.Version, rep.Commit, rep.BuildTime)
	fmt.Printf("restricted mode: %v\n", rep.Restricted)
	for _, r := range rep.Restrictions {
		fmt.Printf("  - %s\n", r)
	}
	if rep.LastVerify != nil {
		fmt.Printf("last verify: profile=%s ok=%v at=%s duration=%s\n",
			rep.LastVerify.Profile, rep.LastVerify.OK,
			rep.LastVerify.StartedAt.Format(time.RFC3339), rep.LastVerify.Duration)
	} else {
		fmt.Printf("last verify: none recorded\n")
	}
	return 0
}

func cmdVersion() int {
	fmt.Printf("proxyctl %s (commit %s, built %s)\n", version, commit, buildTime)
	return 0
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// fail prints a safe error line to stderr and returns the stable exit
// code. The error message has already been redacted at construction.
func fail(err error) int {
	var se *safex.Error
	if e, ok := err.(*safex.Error); ok {
		se = e
	} else {
		se = safex.New(safex.CodeInternal, "internal error")
	}
	fmt.Fprintf(os.Stderr, `{"error": {"code": %q, "message": %q}}`+"\n", se.Code, se.Message)
	return se.Code.ExitCode()
}
