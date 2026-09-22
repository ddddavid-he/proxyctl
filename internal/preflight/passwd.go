package preflight

import (
	"fmt"
	"strconv"
	"strings"
)

// This file holds the pure /etc/passwd parsing helpers: no OS calls,
// no build tags, so deterministic tests run on any host. The file
// reading itself is Linux-only (see probe_linux.go).

// Bounds for the account database and its content. The file size is
// checked from Lstat before reading; line count and width are checked
// by the parser.
const (
	// maxPasswdSize is the fixed maximum /etc/passwd file size.
	maxPasswdSize = 1 << 20 // 1 MiB
	// maxPasswdLines bounds the parsed line count.
	maxPasswdLines = 1 << 20
	// maxPasswdLineLen bounds one line.
	maxPasswdLineLen = 4096
)

// parsePasswdUIDGID extracts the numeric UID/GID for the exact account
// name from /etc/passwd content. IDs must be nonnegative decimal
// integers; malformed matching lines and duplicate accounts fail.
func parsePasswdUIDGID(data, name string) (int, int, error) {
	lines := strings.Split(data, "\n")
	if len(lines) > maxPasswdLines {
		return 0, 0, fmt.Errorf("account database too large")
	}
	found := false
	var uid, gid int
	for _, line := range lines {
		if len(line) > maxPasswdLineLen {
			return 0, 0, fmt.Errorf("account database line too long")
		}
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue // not a well-formed account line; ignore
		}
		if fields[0] != name {
			continue
		}
		if found {
			return 0, 0, fmt.Errorf("duplicate account entry")
		}
		found = true
		u, err := parseNonnegativeInt(fields[2])
		if err != nil {
			return 0, 0, fmt.Errorf("account uid invalid")
		}
		g, err := parseNonnegativeInt(fields[3])
		if err != nil {
			return 0, 0, fmt.Errorf("account gid invalid")
		}
		uid, gid = u, g
	}
	if !found {
		return 0, 0, fmt.Errorf("account not found")
	}
	return uid, gid, nil
}

// parseNonnegativeInt parses a decimal string as a nonnegative int.
func parseNonnegativeInt(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("not a nonnegative integer")
	}
	return v, nil
}
