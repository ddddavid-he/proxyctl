package credential

import (
	"os"
	"path/filepath"
	"strings"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// productionRoot is the only root the production source may read from.
// systemd passes $CREDENTIALS_DIRECTORY as /run/credentials/<unit>
// (or a nested path below it); anything outside this root is refused.
const productionRoot = "/run/credentials"

// getenv is the environment lookup used by the production source. It is
// a package-level variable so the white-box test hooks can substitute a
// deterministic fake; production code always sees os.Getenv.
var getenv = os.Getenv

// systemdSource is the production source: it reads only from
// $CREDENTIALS_DIRECTORY, strictly confined beneath its allowed root
// (production: /run/credentials; tests: a package-private trusted
// root). It performs no shell and no network access.
//
// Lifecycle (finding: single verified descriptor): open() resolves and
// verifies the unit credential directory ONCE and holds the descriptor;
// checkDuplicates and every read then operate on that SAME descriptor;
// close releases it. Because all reads are descriptor-relative
// (openat-style), renaming or replacing the path after open cannot mix
// credentials from a different directory into one load.
type systemdSource struct {
	// allowedRoot is the confinement root. Production passes
	// productionRoot; tests inject an isolated temp dir via
	// loadFromTestRoot (export_test.go only).
	allowedRoot string
	// lookupEnv supplies CREDENTIALS_DIRECTORY.
	lookupEnv func(string) string

	// afterOpen is a test-only hook invoked after the unit directory
	// has been opened (and verified) but before any reads. It lets a
	// deterministic test swap the on-disk path and prove the held
	// descriptor still governs the reads. Nil in production.
	afterOpen func()

	dir   *dirFD // non-nil between open() and close()
	reads int    // read-call counter bounding per-load work
}

func newSystemdSource(allowedRoot string, lookup func(string) string) *systemdSource {
	return &systemdSource{allowedRoot: allowedRoot, lookupEnv: lookup}
}

// open resolves and verifies the unit credential directory and holds
// its descriptor until close. It must be called before checkDuplicates
// or read, and exactly once per load.
func (s *systemdSource) open() error {
	if s.dir != nil {
		return safex.New(safex.CodeInternal, "credential source already open")
	}
	parts, err := s.relUnitDir()
	if err != nil {
		return err
	}
	d, err := openDirNoFollow(-1, s.allowedRoot)
	if err != nil {
		return err
	}
	for _, comp := range parts {
		next, err := openDirNoFollow(d.fd, comp)
		d.close()
		if err != nil {
			return err
		}
		d = next
	}
	s.dir = d
	// Reset the per-load read counter so a reused source cannot inherit
	// reads from an earlier load (open() is exactly-once per load, so
	// this is belt and braces against a future refactor).
	s.reads = 0
	if err := s.checkUnitDirMode(); err != nil {
		s.close()
		return err
	}
	if s.afterOpen != nil {
		s.afterOpen()
	}
	return nil
}

// checkUnitDirMode rejects a group/world-accessible unit credential
// directory: it holds private material, so its permission bits must
// not allow group or other access (systemd provisions it 0700).
func (s *systemdSource) checkUnitDirMode() error {
	m, err := s.dir.mode()
	if err != nil {
		return err
	}
	if m&0o077 != 0 {
		return safex.New(safex.CodePermission, "credentials directory is group/world-accessible")
	}
	return nil
}

// close releases the held directory descriptor. Idempotent.
func (s *systemdSource) close() {
	if s.dir != nil {
		s.dir.close()
		s.dir = nil
	}
}

// relUnitDir validates $CREDENTIALS_DIRECTORY and returns the path of
// the unit credential directory RELATIVE to the allowed root (each
// component a plain, non-traversal name). Rejects: unset/empty,
// relative paths, ".." traversal, "." components, and anything not
// strictly beneath the allowed root.
func (s *systemdSource) relUnitDir() ([]string, error) {
	lookup := s.lookupEnv
	if lookup == nil {
		lookup = getenv
	}
	dir := lookup("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return nil, safex.New(safex.CodeNotFound, "credentials directory is not set")
	}
	if !filepath.IsAbs(dir) {
		return nil, safex.New(safex.RenderUnsafe, "credentials directory must be an absolute path")
	}
	if hasTraversal(dir) {
		return nil, safex.New(safex.RenderUnsafe, "credentials directory contains a traversal component")
	}
	clean := filepath.Clean(dir)
	cleanRoot := filepath.Clean(s.allowedRoot)
	rel, err := filepath.Rel(cleanRoot, clean)
	if err != nil || rel == "." {
		return nil, safex.New(safex.RenderUnsafe, "credentials directory is outside the allowed root")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, safex.New(safex.RenderUnsafe, "credentials directory is outside the allowed root")
		}
	}
	return parts, nil
}

// checkDuplicates fails closed when the credential directory contains
// duplicate or ASCII case-colliding entry names.
func (s *systemdSource) checkDuplicates() error {
	if s.dir == nil {
		return safex.New(safex.CodeInternal, "credential source not open")
	}
	names, err := s.dir.readNames()
	if err != nil {
		return err
	}
	return checkNameCollisions(names)
}

// read returns the content of one allowlisted credential file. The
// number of reads per load is hard-capped (maxCredentialReads): the
// allowlists are fixed and tiny, so an over-cap read sequence indicates
// a bug or a hostile caller, and fails closed with a fixed message.
func (s *systemdSource) read(name string) ([]byte, error) {
	if s.dir == nil {
		return nil, safex.New(safex.CodeInternal, "credential source not open")
	}
	if s.reads >= maxCredentialReads {
		return nil, safex.New(safex.CodeConfigRejected, "credential load exceeds read limit")
	}
	s.reads++
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') {
		return nil, safex.New(safex.RenderUnsafe, "credential name is not a plain file name")
	}
	return s.dir.readFile(name)
}

// hasTraversal rejects any ".." path component on the RAW path, before
// any Clean/Join (so ".." can never be silently collapsed away).
func hasTraversal(p string) bool {
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

// checkNameCollisions fails closed when two entry names collide under
// ASCII case-insensitive comparison. systemd credential names are plain
// ASCII file names on a case-sensitive filesystem; a same-name-
// different-case pair is ambiguous for operators and for any future
// case-insensitive mount, so fail closed. (Deliberately NOT Unicode
// case-folding: names are ASCII, so a byte A-Z/a-z comparison is exact
// and locale-independent.)
func checkNameCollisions(names []string) error {
	seen := map[string]string{}
	for _, n := range names {
		folded := asciiLower(n)
		if prev, ok := seen[folded]; ok && prev != n {
			return safex.New(safex.RenderUnsafe, "ambiguous duplicate credential names present")
		}
		seen[folded] = n
	}
	return nil
}

// asciiLower lowercases ASCII A-Z only; all other bytes are unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// LoadSystemd is the production entry point and the ONLY public loader:
// it reads the role's fixed allowlist from $CREDENTIALS_DIRECTORY,
// confined beneath the fixed /run/credentials root. role must be "gateway"
// or "egress" (anything else fails closed, before any filesystem access).
// Callers cannot choose the root, the directory, or any credential
// name.
func LoadSystemd(role string) (*Bundle, error) {
	r, err := config.ParseRole(role)
	if err != nil {
		return nil, err
	}
	return load(r, newSystemdSource(productionRoot, getenv))
}
