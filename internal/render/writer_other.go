//go:build !linux

package render

import (
	"os"

	"proxyctl/internal/safex"
)

// errUnsupportedWriter is the fixed fail-closed error for the
// production entry point on non-Linux targets.
//
// The production transaction depends on descriptor-relative
// operations (the *at family) and an atomic no-replace publish
// (linkat / renameat2 RENAME_NOREPLACE). Those primitives are not
// available through the maintained standard-library syscall surface
// on this target, so the production writer refuses to run BEFORE any
// filesystem access rather than silently weakening its guarantees
// (following the same policy as internal/credential/fd_other.go).
var errUnsupportedWriter = safex.New(safex.CodeInternal,
	"credential writer unsupported on this platform")

// defaultBackend is the fail-closed backend for unsupported targets.
// Every operation returns the same fixed error; nothing is written.
// The transaction logic itself stays portable and is exercised through
// writeTransactionWithBackend with an explicit backend.
func defaultBackend() backend {
	closed := func() error { return errUnsupportedWriter }
	return backend{
		openDir: func(string) (*dirHandle, error) { return nil, errUnsupportedWriter },
		openSubdir: func(*dirHandle, string) (*dirHandle, error) {
			return nil, errUnsupportedWriter
		},
		closeDir: func(*dirHandle) error { return nil },
		lstatAt:  func(*dirHandle, string) (os.FileInfo, error) { return nil, errUnsupportedWriter },
		createAt: func(*dirHandle, string, os.FileMode) (file, inodeID, error) {
			return nil, inodeID{}, errUnsupportedWriter
		},
		mkdirAt: func(*dirHandle, string, os.FileMode) error { return closed() },
		// Nothing is ever linked, so the "final link created" report is
		// always false: the fail-closed backend cannot leave a
		// published file behind.
		publish: func(*dirHandle, *dirHandle, string) (bool, error) { return false, closed() },
		removeIfSameAt: func(*dirHandle, string, inodeID) error {
			return closed()
		},
		rmdirAt:      func(*dirHandle, string) error { return closed() },
		syncDir:      func(*dirHandle) error { return closed() },
		randomSuffix: func() (string, error) { return "", errUnsupportedWriter },
	}
}
