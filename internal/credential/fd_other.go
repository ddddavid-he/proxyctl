//go:build !linux

package credential

import "proxyctl/internal/safex"

// dirFD is the unsupported-target stub. The descriptor-relative
// traversal used by the production target (Linux) is not available
// here, so the credential source fails closed with a fixed internal
// error BEFORE any filesystem access rather than silently weakening
// the no-follow/confinement guarantees. This file exists so the
// package still COMPILES on other targets (macOS/Windows/...), which
// keeps the pure allowlist/validation tests portable.
type dirFD struct {
	fd int
}

func (d *dirFD) close() {}

func openDirNoFollow(dirfd int, path string) (*dirFD, error) {
	return nil, errUnsupported
}

func (d *dirFD) metadata() (credentialMetadata, error) {
	return credentialMetadata{}, errUnsupported
}

func (d *dirFD) readNames() ([]string, error) {
	return nil, errUnsupported
}

func (d *dirFD) readFile(name string) ([]byte, error) {
	return nil, errUnsupported
}

// errUnsupported is the fixed fail-closed error for non-Linux targets.
var errUnsupported = safex.New(safex.CodeInternal, "credential source unsupported on this platform")
