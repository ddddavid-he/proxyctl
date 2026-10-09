//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"proxyctl/internal/safex"
	"syscall"
)

// Runtime commands execute only fixed siblings of the installed release.
// Existing offline control commands retain their original behavior.
func cmdRuntime(command string, args []string) int {
	executable, err := os.Executable()
	if err != nil {
		return fail(safex.New(safex.CodeInternal, "cannot locate runtime release"))
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fail(safex.New(safex.CodeInternal, "cannot resolve runtime release"))
	}
	root := filepath.Dir(executable)
	var program string
	var argv []string
	if command == "gateway" {
		fs := strictFlagSet("gateway")
		config := fs.String("config", "", "rendered Mihomo configuration")
		spool := fs.String("accounting-dir", "", "private durable accounting spool")
		if err := fs.Parse(args); err != nil {
			return fail(unknownFlagError("gateway", err))
		}
		if fs.NArg() != 0 || *config == "" || *spool == "" || !filepath.IsAbs(*config) || !filepath.IsAbs(*spool) {
			return fail(safex.New(safex.CodeUsage, "gateway requires absolute --config and --accounting-dir"))
		}
		program = filepath.Join(root, "mihomo")
		argv = []string{program, "-f", *config}
		if err := os.Setenv("PROXYCTL_ACCOUNTING_DIR", *spool); err != nil {
			return fail(safex.New(safex.CodeInternal, "cannot configure accounting"))
		}
	} else {
		program = "/usr/bin/python3"
		argv = append([]string{program, filepath.Join(root, "deploy/traffic/traffic.py")}, args...)
	}
	if err := syscall.Exec(program, argv, os.Environ()); err != nil {
		return fail(safex.New(safex.CodeInternal, "cannot start installed runtime component"))
	}
	return 1
}
