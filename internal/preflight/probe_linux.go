//go:build linux

package preflight

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// readFile is the internal file-reading boundary for the fixed host
// tables. It is a variable so deterministic tests can substitute
// fixtures without touching the real filesystem.
var readFile = os.ReadFile

// Fixed host files read by the Linux probe. No path ever comes from
// the caller, the CLI, or untrusted probe data.
const (
	passwdPath     = "/etc/passwd"
	procNetTCPPath = "/proc/net/tcp"
	procNetUDPPath = "/proc/net/udp"
	procNetTCP6    = "/proc/net/tcp6"
	procNetUDP6    = "/proc/net/udp6"
	runDirFallback = "/run"
)

// linuxProbe is the real read-only Linux default Probe. It uses only
// standard-library host reads of fixed paths (/proc/net tables,
// /etc/passwd, /run/private-proxy). It executes no external commands,
// opens no sockets, and performs no NSS, DNS or network access. It
// accepts no caller-supplied paths or commands.
type linuxProbe struct{}

// Environment performs no network access on this platform: the real
// environment facts are gathered by the typed fact methods.
func (linuxProbe) Environment() error { return nil }

// AvailableBytes stats the filesystem of the fixed runtime target. The
// ephemeral runtime directory may legitimately not exist yet (systemd
// creates it at service start); in that case the parent /run filesystem
// is measured instead.
func (linuxProbe) AvailableBytes() (uint64, error) {
	var st syscall.Statfs_t
	err := syscall.Statfs(runtimeTargetDir, &st)
	if errors.Is(err, os.ErrNotExist) {
		err = syscall.Statfs(runDirFallback, &st)
	}
	if err != nil {
		return 0, err
	}
	if st.Bavail > ^uint64(0)/uint64(st.Bsize) {
		return ^uint64(0), nil // overflow guard (unreachable on Linux)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// Identity resolves the fixed privateproxy account from a bounded parse
// of /etc/passwd (never NSS: os/user can invoke network-backed sources)
// and Lstats the fixed runtime directory for mode and numeric
// ownership, rejecting symlinks and non-directories.
func (linuxProbe) Identity() (IdentityFacts, error) {
	data, err := readPasswd()
	if err != nil {
		return IdentityFacts{}, err
	}
	uid, gid, err := parsePasswdUIDGID(string(data), expectedServiceAccount)
	if err != nil {
		return IdentityFacts{}, err
	}
	f := IdentityFacts{Name: expectedServiceAccount, UID: uid, GID: gid}
	fi, err := os.Lstat(runtimeTargetDir)
	if errors.Is(err, os.ErrNotExist) {
		f.DirMissing = true
		return f, nil
	}
	if err != nil {
		return IdentityFacts{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return IdentityFacts{}, fmt.Errorf("runtime target is a symlink")
	}
	if !fi.IsDir() {
		return IdentityFacts{}, fmt.Errorf("runtime target is not a directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return IdentityFacts{}, fmt.Errorf("ownership facts unavailable")
	}
	f.DirMode = fi.Mode()
	f.DirUID = int(st.Uid)
	f.DirGID = int(st.Gid)
	return f, nil
}

// readPasswd reads the fixed /etc/passwd file, refusing symlinks and
// non-regular files and enforcing the fixed maximum size before
// reading.
func readPasswd() ([]byte, error) {
	fi, err := os.Lstat(passwdPath)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("account database is a symlink")
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("account database is not a regular file")
	}
	if fi.Size() > maxPasswdSize {
		return nil, fmt.Errorf("account database too large")
	}
	return readFile(passwdPath)
}

// Listeners reads the fixed /proc/net tcp/tcp6/udp/udp6 tables. TCP
// rows are filtered to LISTEN; every bound UDP entry is returned as a
// conflict candidate. The scan fails closed: the required IPv4 tcp/udp
// tables must be readable, any readable table with malformed rows
// fails, and only an ENOENT on the IPv6 tables may be skipped (IPv6
// can be disabled); any other IPv6 read error fails.
func (linuxProbe) Listeners() ([]Listener, error) {
	tables := []struct {
		path     string
		proto    string
		is6      bool
		required bool
	}{
		{procNetTCPPath, "tcp", false, true},
		{procNetUDPPath, "udp", false, true},
		{procNetTCP6, "tcp", true, false},
		{procNetUDP6, "udp", true, false},
	}
	var out []Listener
	for _, tb := range tables {
		data, err := readFile(tb.path)
		if err != nil {
			if !tb.required && errors.Is(err, os.ErrNotExist) {
				continue // IPv6 disabled: only this case is skippable
			}
			return nil, fmt.Errorf("required listener table unreadable")
		}
		ls, err := parseProcNet(string(data), tb.proto, tb.is6)
		if err != nil {
			return nil, fmt.Errorf("listener table malformed")
		}
		out = append(out, ls...)
	}
	return out, nil
}
