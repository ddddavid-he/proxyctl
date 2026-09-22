// Package status reports binary version, restricted state and the most
// recent verification summary. It never reads or displays passwords,
// auth headers, or full target URLs, and it executes no external
// commands.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxyctl/internal/safex"
)

// Version metadata injected at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Report is the stable JSON shape of proxyctl status.
type Report struct {
	Version      string     `json:"version"`
	Commit       string     `json:"commit"`
	BuildTime    string     `json:"build_time"`
	Restricted   bool       `json:"restricted"`
	Restrictions []string   `json:"restrictions"`
	LastVerify   *VerifySum `json:"last_verify,omitempty"`
}

// VerifySum is a redacted summary of a stored verification result.
type VerifySum struct {
	Profile   string    `json:"profile"`
	OK        bool      `json:"ok"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
}

// stateFileName is the file (inside the caller-isolated state dir)
// holding the last verification summary. It contains no secrets by
// construction (written from verify.Result).
const stateFileName = "last-verify.json"

// Options controls a status run.
type Options struct {
	// StateDir is an optional caller-isolated directory holding the
	// last-verify summary.
	StateDir string
}

// Collect gathers the status report.
func Collect(opts Options) (*Report, error) {
	rep := &Report{
		Version:    Version,
		Commit:     Commit,
		BuildTime:  BuildTime,
		Restricted: true,
		Restrictions: []string{
			"no external command execution",
			"no network listeners",
			"no secrets in output (redacted centrally)",
			"fail-closed: no DIRECT fallback",
		},
	}
	if opts.StateDir != "" {
		sum, err := readLastVerify(opts.StateDir)
		if err != nil {
			return nil, err
		}
		if sum != nil {
			rep.LastVerify = sum
		}
	}
	return rep, nil
}

// readLastVerify reads the redacted summary file. The caller-supplied
// state dir is validated first: raw-string traversal components are
// rejected (no prior Clean) and the final component must be a real
// directory, not a symlink. The state file itself is also
// symlink-refused.
func readLastVerify(stateDir string) (*VerifySum, error) {
	for _, part := range strings.Split(stateDir, string(filepath.Separator)) {
		if part == ".." {
			return nil, safex.New(safex.RenderUnsafe, "state dir contains '..' traversal component")
		}
	}
	fi, err := os.Lstat(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, safex.New(safex.CodeIO, "cannot stat state dir").Wrap(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, safex.New(safex.RenderUnsafe, "state dir must not be a symlink")
	}
	if !fi.IsDir() {
		return nil, safex.New(safex.CodeUsage, "state dir is not a directory")
	}
	path := filepath.Join(stateDir, stateFileName)
	sfi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, safex.New(safex.CodeIO, "cannot stat state file").Wrap(err)
	}
	if sfi.Mode()&os.ModeSymlink != 0 {
		return nil, safex.New(safex.RenderUnsafe, "state file is a symlink; refusing to read")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, safex.New(safex.CodeIO, "cannot read state file").Wrap(err)
	}
	var sum VerifySum
	if err := json.Unmarshal(data, &sum); err != nil {
		return nil, safex.New(safex.CodeInternal, "state file is corrupt").Wrap(err)
	}
	return &sum, nil
}
