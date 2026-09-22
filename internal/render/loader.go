// loader.go: the injectable credential-bundle boundary of render.
//
// Production renders resolve credentials through exactly one path:
// SystemdLoader -> credential.LoadSystemd(role), which reads the
// role's FIXED name allowlist from $CREDENTIALS_DIRECTORY confined
// beneath the FIXED /run/credentials root. Nothing here accepts a
// credential root, directory, file name, environment variable name,
// stdin stream, URL or arbitrary path, and the CLI has no flag that
// could supply one.
//
// The seam exists so tests can inject a synthetic in-memory bundle.
// It is a per-call value passed through Options — there is no
// package-level mutable loader, so concurrent renders can neither
// observe nor disturb each other's bundle.

package render

import (
	"reflect"

	"proxyctl/internal/credential"
	"proxyctl/internal/safex"
)

// Bundle is the full view of a loaded credential bundle that render
// needs: the value lookups of BundleSource plus the role identity used
// to refuse wrong-role material and the lifecycle hook used to
// minimize secret lifetime.
//
// *credential.Bundle satisfies it; tests supply a pure in-memory fake.
type Bundle interface {
	BundleSource
	// Role reports the role whose fixed allowlist the bundle was
	// loaded for. It is a hardcoded, secret-free identity.
	Role() string
	// Close releases the material as early as possible (asset bytes
	// are zeroized in place) and makes later lookups fail closed. It
	// is idempotent.
	Close()
}

// Loader obtains the credential bundle for one role.
//
// role is always a value that already passed config.ParseRole ("gateway" or
// "egress"): a Loader never has to parse or trust caller text, and it
// never receives a path.
type Loader interface {
	Load(role string) (Bundle, error)
}

// SystemdLoader is the production Loader and the only one reachable
// from the CLI. It delegates to credential.LoadSystemd, which owns the
// fixed root, the fixed per-role name allowlist and every fail-closed
// check (permissions, symlinks, duplicates, size, control bytes).
type SystemdLoader struct{}

// Load returns the role's systemd credential bundle.
//
// The error is returned WITHOUT the bundle: handing back a typed nil
// pointer inside a non-nil interface would let a caller invoke methods
// on a bundle that was never loaded, so the failure path yields a
// literal nil interface instead.
func (SystemdLoader) Load(role string) (Bundle, error) {
	b, err := credential.LoadSystemd(role)
	if err != nil {
		return nil, err
	}
	return bundleOrFailClosed(b)
}

// bundleOrFailClosed is the single guarded conversion from
// *credential.Bundle to the Bundle interface.
//
// It exists because a TYPED NIL is invisible to a plain `== nil` test:
// `var b *credential.Bundle; var i Bundle = b` produces a NON-nil
// interface, so `i == nil` is false and the usual nil branch is skipped.
//
// Calling a method on that value is NOT benign. *credential.Bundle's
// methods have pointer receivers that read fields directly — Role()
// evaluates b.role and Scalar() evaluates b.closed — so each one
// dereferences a nil pointer and PANICS. (Only a nil *map read* would
// have been safe; these are field accesses on a nil struct pointer.) A
// panic in a credential path is a crash with a stack trace instead of a
// stable, redacted refusal, which is precisely what must not happen.
//
// The guard therefore refuses any nil or typed-nil bundle from ANY
// loader, not just the production one, before the first method call, and
// returns a fixed error that names no credential, path or secret.
func bundleOrFailClosed(b *credential.Bundle) (Bundle, error) {
	if b == nil {
		return nil, safex.New(safex.CodeInternal, "credential bundle unavailable")
	}
	var i Bundle = b
	if isNilBundle(i) {
		return nil, safex.New(safex.CodeInternal, "credential bundle unavailable")
	}
	return i, nil
}

// isNilBundle reports whether a non-nil Bundle interface holds a nil
// pointer or nil map/slice underneath. reflect is used only for this
// defensive identity check — never to touch secret material — and only
// on the kinds a Bundle can legitimately be.
func isNilBundle(b Bundle) bool {
	if b == nil {
		return true
	}
	v := reflect.ValueOf(b)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}
