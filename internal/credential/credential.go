// Package credential loads the small, fixed set of secrets and runtime
// assets proxyctl needs from a systemd credential directory, as exposed
// to a unit via LoadCredential= ($CREDENTIALS_DIRECTORY).
//
// Design rules (fail-closed, local-only):
//   - Credential names are a role-specific hardcoded allowlist derived
//     from the placeholder names in the committed templates and fixtures.
//     Callers can NEVER supply credential
//     names or directories; the only production entry point is
//     LoadSystemd(role) with the fixed /run/credentials root.
//   - The production source rejects unset/relative/traversal/outside
//     roots, symlinked root/intermediate/final components, non-regular
//     files, group/world-accessible files, duplicate/ambiguous names,
//     oversize values/assets, NUL/control bytes in scalar secrets and
//     empty required credentials.
//   - Path traversal is descriptor-relative (openat-style): the allowed
//     root and every directory component are held open with
//     O_NOFOLLOW|O_DIRECTORY and files are opened relative to those
//     descriptors, so swapping an intermediate directory for a symlink
//     after validation cannot redirect a read (see fd_linux_impl.go).
//     Supported on Linux (the production target); every other target
//     compiles and fails closed with a fixed internal error.
//   - Returned errors never contain secret bytes, source paths,
//     canaries or arbitrary underlying OS error text: every error is a
//     *safex.Error with a fixed message.
//   - No shell, no subprocess, no network. Standard library only.
//   - Bundle.Close minimizes secret lifetime: asset bytes are zeroized
//     in place and every later lookup fails closed. Callers should
//     defer it immediately after a successful load.
//
// The render slice consumes a loaded Bundle through its own narrow
// BundleSource/Loader seam (internal/render); LoadSystemd(role) with
// the fixed root and fixed allowlist remains the ONLY production
// entry point, and nothing caller-controlled can reach it.
package credential

import (
	"sort"
	"strings"

	"proxyctl/internal/config"
)

// Size limits (hard caps; anything larger is rejected before use).
const (
	// maxScalarBytes caps a scalar secret (password/username credential
	// values). Real secrets are dozens of bytes; 1 KiB is generous.
	maxScalarBytes = 1024
	// maxAssetBytes caps a runtime asset (cert/key PEM material).
	maxAssetBytes = 256 * 1024
	// maxCredentialEntries caps how many entries a single unit
	// credential directory enumeration may yield. systemd provisions a
	// handful of files (the fixed allowlists plus optional mTLS
	// material); 128 is orders of magnitude above that and bounds the
	// duplicate-collision scan. Beyond the cap the load fails closed.
	maxCredentialEntries = 128
	// maxCredentialReads caps how many individual credential reads one
	// load() may perform. One load needs at most the role's required
	// scalars+assets plus the allowlisted optionals (8 today); 64
	// leaves generous headroom while bounding per-load work. Beyond
	// the cap the load fails closed.
	maxCredentialReads = 64
)

// scalarName is one allowlisted scalar credential (systemd credential
// file name; identical to the placeholder name used in templates).
type scalarName string

// Scalar credentials shared by both roles or role-specific. These are
// the ONLY scalar names proxyctl will ever read.
const (
	// scalarGatewayEgressPassword is the single shared gateway-to-egress machine
	// credential (placeholder ${GATEWAY_EGRESS_PASSWORD_1}). The historical
	// fixture name GATEWAY_NODE_PASSWORD_1 is an ALIAS of the same fixed
	// credential, never a second secret.
	scalarGatewayEgressPassword scalarName = "GATEWAY_EGRESS_PASSWORD_1"
	scalarTrojanUser            scalarName = "TROJAN_USER_1"
	scalarTrojanPass            scalarName = "TROJAN_PASSWORD_1"
	scalarHTTPSUser             scalarName = "HTTPS_USER_1"
	scalarHTTPSPassword         scalarName = "HTTPS_PASSWORD_1"
)

// gatewayNodePasswordAlias is the legacy fixture name for the gateway->egress machine
// credential. Any reference to it resolves to scalarGatewayEgressPassword (one
// fixed credential, not a second secret).
const gatewayNodePasswordAlias = "GATEWAY_NODE_PASSWORD_1"

// assetName is one allowlisted runtime asset (systemd credential file
// name, e.g. "gateway.crt"). Asset names double as the fixed destination
// file names inside the runtime directory; they are never
// caller-provided.
type assetName string

const (
	assetGatewayCrt assetName = "gateway.crt"
	assetGatewayKey assetName = "gateway.key"
	assetEgressCrt  assetName = "egress.crt"
	assetEgressKey  assetName = "egress.key"
)

// Bundle is the loaded credential material for one role.
//
// Bundle is OPAQUE: it exposes no secret-bearing fields, and its fmt
// and JSON representations never contain secret material. String and
// GoString are implemented so %v/%+v/%s/%#v all print only the fixed,
// secret-free Summary; the fields are unexported so default JSON
// marshaling yields "{}" with no values. The only way to obtain
// values is through the narrowly-scoped lookup and materialization
// methods below, intended for the render slice.
//
// Scalar replacements (text substituted into ${VAR} placeholders) and
// runtime assets (opaque bytes written to fixed destination names) are
// strictly distinct: Scalar never returns asset bytes and Materialize
// only ever yields the fixed asset destination names.
type Bundle struct {
	role    config.Role
	scalars map[scalarName]string
	// assets maps fixed destination file name -> opaque bytes.
	assets map[assetName][]byte
	// optional records allowlisted optional assets (e.g. future mTLS
	// material) that were found and loaded.
	optional []assetName
	// closed records that Close has run. Every value accessor then
	// fails closed (ok=false / no assets), so a use-after-close can
	// never silently return stale or partially wiped material.
	closed bool
}

// Role returns the role whose fixed allowlist this bundle was loaded
// for ("gateway" or "egress"). It is a hardcoded, secret-free identity, and it
// is what lets a consumer refuse a bundle that belongs to the OTHER
// role instead of rendering it (wrong-role material must fail closed,
// not be substituted).
func (b *Bundle) Role() string { return string(b.role) }

// Close minimizes the lifetime of the loaded material and makes every
// later value lookup fail closed.
//
// What it does, exactly:
//
//   - Asset bytes are OVERWRITTEN IN PLACE with zeros before the map is
//     dropped, so the plaintext PEM/DER material stops existing in the
//     process image at a deterministic point instead of whenever the
//     collector happens to run.
//   - The scalar map is dropped. Scalar values are Go strings, which
//     are immutable by language contract and may share backing storage
//     with other values; overwriting their bytes would require unsafe
//     aliasing of memory this package does not own, which is exactly
//     the kind of trick that turns a "wipe" into a corruption bug. They
//     are therefore released for collection, NOT scribbled over. This
//     is a deliberate, documented limit of the zeroization.
//   - closed is set, so Scalar returns ok=false and Materialize returns
//     no assets afterwards.
//
// Zeroizing is safe with respect to already-returned material because
// Materialize hands out DEEP COPIES: wiping the bundle can never
// corrupt a copy a caller is still using (no aliasing between the two).
//
// Close is idempotent and safe to defer immediately after a load.
func (b *Bundle) Close() {
	if b == nil || b.closed {
		return
	}
	b.closed = true
	for name, data := range b.assets {
		for i := range data {
			data[i] = 0
		}
		delete(b.assets, name)
	}
	b.assets = nil
	b.scalars = nil
	b.optional = nil
}

// String makes fmt %v/%+v/%s safe: secret bytes are unreachable. The
// value receiver covers both Bundle and *Bundle formatting.
func (b Bundle) String() string { return b.Summary() }

// GoString makes fmt %#v safe: the %v-verb family does not guarantee
// use of String for %#v, so GoString is provided explicitly (value
// receiver covers both Bundle and *Bundle).
func (b Bundle) GoString() string { return b.Summary() }

// Summary returns a secret-free one-line description of the bundle
// (role and allowlist names only, never values). Safe for logs/status.
// A closed bundle says so and lists nothing.
func (b Bundle) Summary() string {
	if b.closed {
		return "role=" + string(b.role) + " closed"
	}
	return "role=" + string(b.role) +
		" scalars=[" + strings.Join(b.sortedScalarNames(), ",") + "]" +
		" assets=" + b.assetSummary()
}

func (b Bundle) sortedScalarNames() []string {
	out := make([]string, 0, len(b.scalars))
	for k := range b.scalars {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

func (b Bundle) assetSummary() string {
	names := make([]string, 0, len(b.assets))
	for k := range b.assets {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return "[" + strings.Join(names, ",") + "]"
}

// Scalar returns the scalar replacement value for a template
// placeholder name (e.g. "GATEWAY_EGRESS_PASSWORD_1", "TROJAN_USER_1"). The
// legacy placeholder "GATEWAY_NODE_PASSWORD_1" resolves to the same fixed
// GATEWAY_EGRESS_PASSWORD_1 credential (an alias, never a second secret).
// Unknown/unloaded placeholder names return ok=false, and so does
// every lookup after Close (use-after-close fails closed).
func (b *Bundle) Scalar(placeholder string) (string, bool) {
	if b.closed {
		return "", false
	}
	name, ok := scalarForPlaceholder(placeholder)
	if !ok {
		return "", false
	}
	v, ok := b.scalars[name]
	return v, ok
}

// scalarForPlaceholder maps a template placeholder name to the fixed
// scalar credential it refers to, applying the legacy alias.
func scalarForPlaceholder(placeholder string) (scalarName, bool) {
	if placeholder == gatewayNodePasswordAlias {
		return scalarGatewayEgressPassword, true
	}
	n := scalarName(placeholder)
	switch n {
	case scalarGatewayEgressPassword, scalarTrojanUser, scalarTrojanPass,
		scalarHTTPSUser, scalarHTTPSPassword:
		return n, true
	}
	return "", false
}

// MaterializedAsset pairs a fixed destination file name with its
// opaque bytes. Dest is always one of the hardcoded asset names; it is
// never caller-provided and contains no directory components.
//
// fmt AND json are redacted: String/GoString print only the fixed Dest
// name and byte length, and MarshalJSON emits fixed metadata (dest +
// byte length) only — never the bytes.
type MaterializedAsset struct {
	Dest string
	Data []byte
}

// String hides the bytes for %v/%+v/%s.
func (a MaterializedAsset) String() string {
	return "asset dest=" + a.Dest + " bytes=" + itoa(len(a.Data))
}

// GoString hides the bytes for %#v.
func (a MaterializedAsset) GoString() string { return a.String() }

// MarshalJSON emits only fixed metadata; secret bytes are never
// serialized even if a caller generically JSON-encodes the asset.
func (a MaterializedAsset) MarshalJSON() ([]byte, error) {
	// Fixed shape; Dest is a hardcoded asset name (safe to print).
	return []byte(`{"dest":` + quoteASCII(a.Dest) + `,"bytes":` + itoa(len(a.Data)) + `}`), nil
}

// quoteASCII renders s as a JSON string. Asset names are hardcoded
// ASCII (gateway.crt, ...), so simple quoting suffices; non-ASCII/control
// bytes (which cannot occur) are escaped defensively.
func quoteASCII(s string) string {
	b := []byte{'"'}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		default:
			// Defensive escape for any unexpected byte.
			const hex = "0123456789abcdef"
			b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
	}
	b = append(b, '"')
	return string(b)
}

// itoa is a tiny allocation-free-enough int printer (avoids pulling
// strconv into the redaction path for a single number).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Materialize returns the loaded runtime assets (fixed destination
// names + bytes) in deterministic name order, for the render slice to
// write into the runtime directory. Scalar secrets are never included.
//
// Every returned Data is a DEEP COPY of the bundle's bytes: mutating a
// returned slice (or a slice from an earlier Materialize call) must
// never alter the Bundle itself, so no caller can corrupt shared
// credential material by accident or malice. The copy is also what
// makes Close's in-place zeroization safe: wiping the bundle cannot
// reach into a copy a caller still holds.
//
// After Close the result is always empty (use-after-close fails
// closed), never a partially zeroized asset.
func (b *Bundle) Materialize() []MaterializedAsset {
	if b.closed {
		return nil
	}
	names := make([]string, 0, len(b.assets))
	for k := range b.assets {
		names = append(names, string(k))
	}
	sort.Strings(names)
	out := make([]MaterializedAsset, 0, len(names))
	for _, n := range names {
		src := b.assets[assetName(n)]
		data := make([]byte, len(src))
		copy(data, src)
		out = append(out, MaterializedAsset{Dest: n, Data: data})
	}
	return out
}

// OptionalLoaded reports which allowlisted optional (future mTLS)
// assets were present and loaded. Names only; never bytes. After Close
// the list is empty.
func (b *Bundle) OptionalLoaded() []string {
	out := make([]string, 0, len(b.optional))
	for _, n := range b.optional {
		out = append(out, string(n))
	}
	sort.Strings(out)
	return out
}

// requiredScalars is the hardcoded role-specific scalar allowlist.
func requiredScalars(role config.Role) []scalarName {
	switch role {
	case config.RoleGateway:
		return []scalarName{
			scalarGatewayEgressPassword,
			scalarTrojanUser, scalarTrojanPass,
			scalarHTTPSUser, scalarHTTPSPassword,
		}
	case config.RoleEgress:
		// GATEWAY_NODE_PASSWORD_1 is an alias of GATEWAY_EGRESS_PASSWORD_1: the egress
		// role reads the same single fixed credential.
		return []scalarName{scalarGatewayEgressPassword}
	}
	return nil
}

// requiredAssets is the hardcoded role-specific asset allowlist.
func requiredAssets(role config.Role) []assetName {
	switch role {
	case config.RoleGateway:
		return []assetName{assetGatewayCrt, assetGatewayKey}
	case config.RoleEgress:
		return []assetName{assetEgressCrt, assetEgressKey}
	}
	return nil
}

// optionalAssets lists future mTLS assets that MAY be present but are
// not required in this slice.
func optionalAssets(role config.Role) []assetName {
	switch role {
	case config.RoleGateway:
		return []assetName{"gateway-client.crt", "gateway-client.key"}
	case config.RoleEgress:
		return []assetName{"gateway-client-ca.crt"}
	}
	return nil
}
