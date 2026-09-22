// loader.go: scalar/asset content validation, the source boundary
// interface and the load() orchestration.

package credential

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// source is the package-private boundary between the allowlist logic
// and the storage backend. Production uses systemdSource rooted at the
// fixed /run/credentials; tests inject a source rooted in an isolated
// temp dir. Neither callers nor the CLI can choose names or roots.
//
// Lifecycle: open() verifies and holds the backend directory ONCE;
// checkDuplicates and every read operate on that same verified handle;
// close releases it. This guarantees one load never mixes credentials
// from two different directories.
type source interface {
	// open verifies and holds the backend directory. Called once.
	open() error
	// read returns the full content of one allowlisted credential name
	// (always a plain file name from the hardcoded allowlists).
	read(name string) ([]byte, error)
	// checkDuplicates fails closed when the backend contains duplicate
	// or ambiguous (ASCII case-colliding) entry names.
	checkDuplicates() error
	// close releases the held directory. Idempotent.
	close()
}

// errNotFound is the sole stable, ignorable condition for OPTIONAL
// credentials: the entry is absent (ENOENT/ENOTDIR only). Anything
// else (permission, symlink, malformed, oversize, ...) is a hard
// failure even for optional names.
var errNotFound = safex.New(safex.CodeNotFound, "credential not available")

// load reads and validates the full bundle for role from src.
// Required scalars/assets must be present and well-formed. Optional
// assets are skipped ONLY on stable not-found; any other failure
// aborts the whole load (fail-closed).
func load(role config.Role, src source) (*Bundle, error) {
	// Unknown role: fail closed. The allowlists are per-role; an
	// unrecognized role must never silently degrade to an empty
	// allowlist (which would "succeed" with zero credentials).
	if requiredScalars(role) == nil && requiredAssets(role) == nil {
		return nil, safex.New(safex.CodeInvalidEnum, "invalid role: must be gateway or egress")
	}
	if err := src.open(); err != nil {
		return nil, err
	}
	defer src.close()

	if err := src.checkDuplicates(); err != nil {
		return nil, err
	}

	b := &Bundle{
		role:    role,
		scalars: map[scalarName]string{},
		assets:  map[assetName][]byte{},
	}

	for _, name := range requiredScalars(role) {
		data, err := src.read(string(name))
		if err != nil {
			return nil, err
		}
		v, err := validateScalar(data)
		if err != nil {
			return nil, err
		}
		b.scalars[name] = v
	}

	for _, name := range requiredAssets(role) {
		data, err := src.read(string(name))
		if err != nil {
			return nil, err
		}
		if err := validateAsset(data); err != nil {
			return nil, err
		}
		b.assets[name] = data
	}

	for _, name := range optionalAssets(role) {
		data, err := src.read(string(name))
		if err != nil {
			if err == errNotFound {
				continue // optional: absence is fine
			}
			return nil, err // anything else fails closed
		}
		if err := validateAsset(data); err != nil {
			return nil, err
		}
		b.assets[name] = data
		b.optional = append(b.optional, name)
	}

	return b, nil
}

// validateScalar enforces the scalar secret contract:
//   - at most one trailing LF is tolerated (text-file convention) and
//     stripped;
//   - after that, ANY remaining CR or LF is rejected (no multiline
//     injection into rendered config lines);
//   - NUL bytes, invalid UTF-8 and other C0/DEL control bytes are
//     rejected (no control-sequence injection);
//   - the value must be non-empty and within the size cap.
func validateScalar(data []byte) (string, error) {
	if len(data) > maxScalarBytes {
		return "", safex.New(safex.CodeConfigRejected, "credential value exceeds size limit")
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return "", safex.New(safex.CodeConfigRejected, "credential value contains NUL byte")
	}
	if !utf8.Valid(data) {
		return "", safex.New(safex.CodeConfigRejected, "credential value is not valid UTF-8")
	}
	v := string(data)
	if strings.HasSuffix(v, "\n") {
		v = v[:len(v)-1] // tolerate exactly one trailing LF
	}
	if strings.ContainsAny(v, "\r\n") {
		return "", safex.New(safex.CodeConfigRejected, "credential value contains a line break")
	}
	if strings.IndexFunc(v, isControl) >= 0 {
		return "", safex.New(safex.CodeConfigRejected, "credential value contains a control character")
	}
	if v == "" {
		return "", safex.New(safex.CodeConfigRejected, "required credential is empty")
	}
	return v, nil
}

// isControl reports whether r is a C0 control byte or DEL.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// validateAsset enforces the runtime asset contract: non-empty and
// bounded size. NUL bytes are not rejected (PEM/DER material is opaque
// bytes), but size is capped.
func validateAsset(data []byte) error {
	if len(data) == 0 {
		return safex.New(safex.CodeConfigRejected, "required credential asset is empty")
	}
	if len(data) > maxAssetBytes {
		return safex.New(safex.CodeConfigRejected, "credential asset exceeds size limit")
	}
	return nil
}
