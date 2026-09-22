package credential

import (
	"proxyctl/internal/config"
)

// Test-only hooks. These symbols are compiled only into the test binary
// and are unreachable from the CLI: the CLI never accepts a credential
// path, root, or environment override flag, and LoadSystemd remains the
// only production entry point.

// loadFromTestRoot is the test analogue of LoadSystemd: it confines
// $CREDENTIALS_DIRECTORY (supplied by the test as credDir) beneath the
// isolated test root instead of /run/credentials, then loads the role's
// fixed allowlist. Tests use isolated t.TempDir() hierarchies only.
func loadFromTestRoot(role, root, credDir string) (*Bundle, error) {
	r, err := config.ParseRole(role)
	if err != nil {
		return nil, err
	}
	src := newSystemdSource(root, func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return credDir
		}
		return ""
	})
	return load(r, src)
}
