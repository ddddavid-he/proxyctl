package render

import "proxyctl/internal/credential"

// BundleSource is the narrow, package-facing view of a loaded
// credential bundle. It is satisfied by *credential.Bundle; tests may
// inject a pure in-memory fake. It is NOT exposed through the CLI:
// production code obtains a bundle exclusively via
// credential.LoadSystemd with its fixed allowlist and fixed
// /run/credentials root.
type BundleSource interface {
	// Scalar returns the replacement value for one allowlisted
	// template placeholder name, or ok=false when the placeholder is
	// not a known credential.
	Scalar(placeholder string) (string, bool)
	// Materialize returns the runtime assets (fixed destination names
	// plus deep-copied bytes) to be written alongside the rendered
	// config. Scalar secrets are never included.
	Materialize() []credential.MaterializedAsset
}

// placeholderKind is the emission type of a schema placeholder.
type placeholderKind int

const (
	// kindString is a non-secret string (always emitted as a YAML
	// double-quoted scalar).
	kindString placeholderKind = iota
	// kindSecret is credential material (always emitted as a YAML
	// double-quoted scalar; validated single-line, no controls, never
	// placeholder-shaped).
	kindSecret
	// kindNumber is a non-negative integer in strict unsigned-decimal
	// grammar; it is the only kind emitted raw (unquoted).
	kindNumber
	// kindAddress is a validated network address (IPv4/IPv6 literal,
	// IPv4:port, [IPv6]:port, or a DNS-label hostname); emitted quoted
	// so YAML reserved words cannot become special scalar types.
	kindAddress
)

// placeholderSchema is the explicit, exhaustive declaration of every
// ${NAME} that may appear in any template. A name absent from this
// table is rejected as unknown (template validation) and a name
// declared here but left unresolved fails the render; nothing outside
// the schema can ever reach an output file.
var placeholderSchema = map[string]placeholderKind{
	// gateway role, config phase: numbers raw; validated addresses quoted.
	"MIXED_PORT":          kindNumber,
	"BIND_ADDRESS":        kindAddress,
	"CONTROLLER_LISTEN":   kindAddress,
	"GATEWAY_EGRESS_USER": kindString,
	"EGRESS_SERVER":       kindAddress,
	"EGRESS_PORT":         kindNumber,
	"EGRESS_SNI":          kindString,
	// egress role, config phase.
	"LISTEN":            kindAddress,
	"LISTEN_ADDRESS":    kindAddress,
	"PORT":              kindNumber,
	"SNI":               kindString,
	"GATEWAY_NODE_USER": kindString,
	"MAX_USERS":         kindNumber,
	// Credential placeholders, bundle phase (fixed set; the config
	// phase leaves exactly these names untouched).
	// GATEWAY_EGRESS_AUTH is derived from the validated gateway-egress-user config value
	// and the fixed GATEWAY_EGRESS_PASSWORD_1 credential for Hysteria userpass.
	"GATEWAY_EGRESS_AUTH":       kindSecret,
	"GATEWAY_EGRESS_PASSWORD_1": kindSecret,
	"GATEWAY_NODE_PASSWORD_1":   kindSecret, // fixed alias of GATEWAY_EGRESS_PASSWORD_1
	"TROJAN_USER_1":             kindSecret,
	"TROJAN_PASSWORD_1":         kindSecret,
	"HTTPS_USER_1":              kindSecret,
	"HTTPS_PASSWORD_1":          kindSecret,
}

// kindBounds bounds raw numeric emission per schema placeholder:
// [min, max] inclusive. Only schema-declared names appear here; the
// bounds are part of the schema contract (a port is 1..65535, a user
// cap is a small positive count) so an attacker-controlled config
// number can never emit an absurd raw value.
var kindBounds = map[string][2]int{
	"MIXED_PORT":  {1, 65535},
	"PORT":        {1, 65535},
	"EGRESS_PORT": {1, 65535},
	"MAX_USERS":   {1, 100000},
}

// schemaNames returns the declared placeholder names in deterministic
// order, optionally restricted to one kind.
func schemaNames(kinds ...placeholderKind) []string {
	var out []string
	for name, k := range placeholderSchema {
		for _, want := range kinds {
			if k == want {
				out = append(out, name)
				break
			}
		}
	}
	// Deterministic order for stable validation diagnostics.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
