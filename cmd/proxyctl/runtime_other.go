//go:build !linux && !darwin

package main

import "proxyctl/internal/safex"

func cmdRuntime(command string, args []string) int {
	return fail(safex.New(safex.CodeUsage, "runtime commands require Linux or macOS"))
}
