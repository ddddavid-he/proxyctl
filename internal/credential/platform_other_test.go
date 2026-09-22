//go:build !linux

package credential

import (
	"testing"

	"proxyctl/internal/safex"
)

// On non-Linux targets the production source fails closed with a fixed
// internal error BEFORE any filesystem access. This test runs on Darwin
// (and any other unsupported target) to pin that contract: even with a
// syntactically valid absolute CREDENTIALS_DIRECTORY, LoadSystemd with
// a VALID role must return CodeInternal, never touch the filesystem.
func TestLoadSystemdUnsupportedPlatformFailsClosed(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/some-unit")
	_, err := LoadSystemd("egress")
	assertCode(t, err, safex.CodeInternal)
	assertNoLeak(t, err)

	// gateway role likewise.
	_, err = LoadSystemd("gateway")
	assertCode(t, err, safex.CodeInternal)
}
