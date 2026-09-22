// netprobe.go: the closed, typed, injectable DNS and certificate
// evidence boundary of preflight.
//
// SCOPE, stated exactly. This file defines the CONTRACT and the
// EVALUATION of DNS and certificate facts. It deliberately implements
// NO real network access: no DNS resolution, no resolver configuration,
// no ACME or provider call, no certificate issuance or renewal, and no
// read of a real host certificate. The production default probe reports
// both fact kinds as unavailable, which fails closed (see
// probe_linux.go / preflight.go). A future slice may supply a real
// implementation behind this same interface without changing the
// evaluation logic or the CLI surface.
//
// CLOSED TARGETS. A probe is never asked about a hostname. It is asked
// about a Target: a fixed, code-declared entry point of one role
// (label + protocol + port), enumerated from the VALIDATED role only.
// There is no constructor that turns caller text into a Target, and the
// CLI has no flag that could name one, so no arbitrary hostname, URL,
// path, command or resolver can reach a probe.
//
// EVIDENCE, NOT PROOF. DNS evidence and certificate evidence are kept
// strictly separate and are reported as two independent checks. A
// passing DNS check is NOT certificate proof, and neither check claims
// that a host or a domain is "configured": both report only that the
// observed evidence is consistent with the role's expectations.
//
// UNTRUSTED FACTS. Every string a probe returns (owner names, SANs) is
// attacker-controlled input. It is validated structurally and compared
// against fixed expectations; it is NEVER echoed into a Check detail,
// so no hostname, certificate byte or error text can be reflected into
// output.

package preflight

import (
	"net/netip"
	"reflect"
	"strings"
	"time"
)

// Target is one fixed entry point whose DNS and certificate evidence a
// role depends on. Targets are declared here in code; nothing
// caller-supplied can name or forge one, and an unrecognized value
// fails closed (targetSpec returns ok=false).
type Target int

const (
	// TargetMihomoGateway is the gateway Mihomo/Trojan user entry point.
	TargetMihomoGateway Target = iota
	// TargetNativeGateway is the gateway HTTPS CONNECT user entry point.
	TargetNativeGateway
	// TargetProxyEgress is the egress Hysteria2 main-link entry point.
	TargetProxyEgress
)

// targetSpec is the fixed, code-declared description of a Target.
type targetSpec struct {
	// label is the expected FIRST DNS label of the target's name. The
	// deployment's base domain is deliberately NOT committed to this
	// repository (templates carry a ${SNI}/<domain> placeholder), so
	// the stable, checkable expectation is the label that binds a name
	// to its role and entry point — never a full FQDN baked into code.
	label string
	// proto and port document which listener the name fronts. They are
	// used for the fixed check labels only.
	proto string
	port  uint16
	// role is the only role allowed to probe this target.
	role string
}

// targetSpecs is the complete Target allowlist.
var targetSpecs = map[Target]targetSpec{
	TargetMihomoGateway: {label: "mihomo-gateway", proto: "tcp", port: 8443, role: "gateway"},
	TargetNativeGateway: {label: "native-gateway", proto: "tcp", port: 8444, role: "gateway"},
	TargetProxyEgress:   {label: "proxy-egress", proto: "udp", port: 443, role: "egress"},
}

// targetSpec looks up a Target's fixed description. An unknown value
// (for example an integer cast by a third party) fails closed.
func (t Target) spec() (targetSpec, bool) {
	s, ok := targetSpecs[t]
	return s, ok
}

// roleTargets returns the fixed targets of a role, in declaration
// order. The list is derived from the VALIDATED role string only.
func roleTargets(role string) []Target {
	var out []Target
	for _, t := range []Target{TargetMihomoGateway, TargetNativeGateway, TargetProxyEgress} {
		if s, ok := t.spec(); ok && s.role == role {
			out = append(out, t)
		}
	}
	return out
}

// DNSFacts is the typed DNS evidence for one Target.
//
// Every field is UNTRUSTED probe output. Name in particular is
// attacker-controlled text: it is validated structurally and compared
// against the target's fixed label, and it is never echoed.
type DNSFacts struct {
	// Target echoes the target the facts describe. A mismatch against
	// the requested target fails closed (a probe must not answer a
	// different question than the one asked).
	Target Target
	// Resolved reports whether any record set was observed at all.
	// false means "no record" — a missing record, not an error.
	Resolved bool
	// Name is the owner name the resolver reported for the answer. Its
	// FIRST label must equal the target's expected label; this is what
	// binds a record to its role and entry point without hardcoding a
	// deployment domain.
	Name string
	// Addresses are the observed addresses as numeric literal strings.
	// They are validated as literals and checked for a usable scope; a
	// public entry point resolving to loopback or an unspecified
	// address is wrong evidence.
	Addresses []string
}

// CertificateFacts is the typed certificate evidence for one Target.
//
// It is deliberately a set of FACTS ABOUT a certificate, never
// certificate bytes: no DER, no PEM, no private key and no chain is
// carried through this boundary, so nothing secret or raw can be
// reflected into output.
type CertificateFacts struct {
	// Target echoes the target the facts describe.
	Target Target
	// Present reports whether any certificate evidence was observed.
	Present bool
	// DNSNames are the subject alternative names observed on the leaf
	// certificate. Untrusted text: matched against the observed DNS
	// name, never echoed.
	DNSNames []string
	// NotBefore / NotAfter are the leaf validity bounds.
	NotBefore time.Time
	NotAfter  time.Time
	// Trusted reports the probe's own chain-verification result. It is
	// EVIDENCE from the probe, not a claim this package makes: false
	// (an untrusted, self-signed or unverifiable chain) fails closed.
	Trusted bool
}

// NetProbe is the DNS/certificate evidence boundary. It is a separate
// interface from Probe so a caller can supply host facts without
// implying it can answer name or certificate questions, and so the
// evidence methods are never reachable in offline mode.
//
// Methods take a Target — never a hostname, URL, path, command or
// resolver address. All returned data is untrusted; all returned error
// text is discarded and replaced with a fixed message.
type NetProbe interface {
	// DNS returns the DNS evidence for one allowlisted target.
	DNS(t Target) (DNSFacts, error)
	// Certificate returns the certificate evidence for one allowlisted
	// target. It must never read a real host certificate in this
	// slice's production default (see unavailableNetProbe).
	Certificate(t Target) (CertificateFacts, error)
}

// certRenewalMargin is the fixed minimum remaining validity a
// certificate must have to pass preflight. A certificate that is still
// technically valid but expires inside this window is a scheduled
// outage, so the gate fails closed rather than passing it silently.
const certRenewalMargin = 14 * 24 * time.Hour

// maxProbeNames bounds how many untrusted strings a single fact set may
// carry. A probe returning an unbounded SAN or address list is refused
// rather than iterated.
const maxProbeNames = 64

// unavailableNetProbe is the PRODUCTION DEFAULT. It performs no DNS
// resolution, no ACME or provider call, no certificate issuance or
// renewal and no read of any real certificate: this slice deliberately
// implements no live name or certificate access. Both methods report a
// fixed unavailability error, which the checks turn into a stable
// sanitized FAILURE — never a pass, and never a skip that could be
// mistaken for a pass.
type unavailableNetProbe struct{}

// errProbeUnavailable is the fixed, sanitized unavailability error. It
// names no host, no path and no resolver.
var errProbeUnavailable = errProbe("name and certificate evidence unavailable with the default probe")

// errProbe is a fixed-message probe error type. It carries no host
// detail by construction.
type errProbe string

func (e errProbe) Error() string { return string(e) }

func (unavailableNetProbe) DNS(Target) (DNSFacts, error) {
	return DNSFacts{}, errProbeUnavailable
}

func (unavailableNetProbe) Certificate(Target) (CertificateFacts, error) {
	return CertificateFacts{}, errProbeUnavailable
}

// isNilNetProbe reports whether a NetProbe interface value is nil or
// holds a nil pointer underneath (a TYPED NIL).
//
// A plain `== nil` test is false for a typed nil, so the caller's nil
// branch would be skipped and the evidence methods would be invoked on a
// nil receiver. Whether that panics depends on the implementation — a
// pointer-receiver method that touches any field panics, and one that
// touches none silently returns zero facts, which would read as
// "unresolved / not present" from a probe that was never really there.
// Both outcomes are wrong: the first is a crash instead of a stable
// refusal, the second is fabricated evidence. Detecting the typed nil
// and substituting the fail-closed default rules out both.
//
// This check is scoped to NetProbe only: the older host `Probe` boundary
// is deliberately left unchanged in this slice.
//
// reflect is used purely for this defensive identity test; it never
// touches returned fact data.
func isNilNetProbe(p NetProbe) bool {
	if p == nil {
		return true
	}
	switch v := reflect.ValueOf(p); v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// checkDNS evaluates the DNS evidence for every target of the role.
//
// It reports evidence consistency ONLY. It never claims the host or the
// domain is configured, and it is never treated as certificate proof:
// certificate evidence is a separate check (checkCertificate).
//
// Every failure Detail is a fixed string. Probe-supplied names,
// addresses and error text are never echoed.
//
// DNS evidence has no time component: unlike a certificate, a record
// set has no validity window, so no clock is taken here.
func checkDNS(role string, p NetProbe) Check {
	targets := roleTargets(role)
	if len(targets) == 0 {
		// Unknown role reaching here would mean the role allowlist and
		// the target allowlist disagree: fail closed.
		return Check{Status: "fail", Detail: "no DNS targets declared for this role"}
	}
	for _, t := range targets {
		spec, ok := t.spec()
		if !ok {
			return Check{Status: "fail", Detail: "DNS target is not in the allowlist"}
		}
		facts, err := p.DNS(t)
		if err != nil {
			// Probe error, timeout or unavailability: fixed detail, the
			// underlying text is untrusted and deliberately dropped.
			return Check{Status: "fail", Detail: "DNS evidence unavailable (details withheld)"}
		}
		if facts.Target != t {
			// The probe answered a different question than the one
			// asked; its facts cannot be attributed to this target.
			return Check{Status: "fail", Detail: "DNS evidence does not correspond to the requested target"}
		}
		if !facts.Resolved {
			return Check{Status: "fail", Detail: "no DNS record observed for a required role entry point"}
		}
		if !isSafeProbeName(facts.Name) {
			return Check{Status: "fail", Detail: "observed DNS name is malformed or unsafe"}
		}
		if !hasExpectedLabel(facts.Name, spec.label) {
			return Check{Status: "fail", Detail: "observed DNS name does not match the expected role entry-point label"}
		}
		if len(facts.Addresses) == 0 {
			return Check{Status: "fail", Detail: "DNS record carries no address"}
		}
		if len(facts.Addresses) > maxProbeNames {
			return Check{Status: "fail", Detail: "DNS record carries an implausible number of addresses"}
		}
		for _, a := range facts.Addresses {
			addr, perr := parseProbeAddr(a)
			if perr != nil {
				return Check{Status: "fail", Detail: "DNS record carries a malformed address"}
			}
			if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
				return Check{Status: "fail", Detail: "DNS record points at a loopback, unspecified or multicast address"}
			}
		}
	}
	// Wording is deliberate: it reports what was OBSERVED and states its
	// limits, without ever asserting readiness of a host or a domain.
	return Check{
		Status: "pass",
		Detail: "observed DNS evidence matches the role's expected entry-point labels " +
			"(evidence only, not certificate proof; asserts nothing about host or domain readiness)",
	}
}

// checkCertificate evaluates the certificate evidence for every target
// of the role. It is deliberately INDEPENDENT of checkDNS: a passing
// DNS check proves nothing about a certificate, so this check fails
// closed on its own evidence even when DNS passed.
//
// Every failure Detail is a fixed string: SANs, observed names, validity
// dates and probe error text are never echoed.
func checkCertificate(role string, p NetProbe, now time.Time) Check {
	targets := roleTargets(role)
	if len(targets) == 0 {
		return Check{Status: "fail", Detail: "no certificate targets declared for this role"}
	}
	for _, t := range targets {
		spec, ok := t.spec()
		if !ok {
			return Check{Status: "fail", Detail: "certificate target is not in the allowlist"}
		}
		facts, err := p.Certificate(t)
		if err != nil {
			return Check{Status: "fail", Detail: "certificate evidence unavailable (details withheld)"}
		}
		if facts.Target != t {
			return Check{Status: "fail", Detail: "certificate evidence does not correspond to the requested target"}
		}
		if !facts.Present {
			return Check{Status: "fail", Detail: "no certificate evidence observed for a required role entry point"}
		}
		if !facts.Trusted {
			// An untrusted, self-signed or unverifiable chain is never
			// accepted: production forbids verification bypasses.
			return Check{Status: "fail", Detail: "certificate chain is untrusted or could not be verified"}
		}
		if facts.NotBefore.IsZero() || facts.NotAfter.IsZero() {
			return Check{Status: "fail", Detail: "certificate validity window is missing"}
		}
		if !facts.NotAfter.After(facts.NotBefore) {
			return Check{Status: "fail", Detail: "certificate validity window is invalid"}
		}
		if now.Before(facts.NotBefore) {
			return Check{Status: "fail", Detail: "certificate is not yet valid"}
		}
		if !now.Before(facts.NotAfter) {
			return Check{Status: "fail", Detail: "certificate has expired"}
		}
		if facts.NotAfter.Sub(now) < certRenewalMargin {
			return Check{Status: "fail", Detail: "certificate expires inside the required renewal margin"}
		}
		if len(facts.DNSNames) == 0 {
			return Check{Status: "fail", Detail: "certificate carries no subject alternative name"}
		}
		if len(facts.DNSNames) > maxProbeNames {
			return Check{Status: "fail", Detail: "certificate carries an implausible number of subject alternative names"}
		}
		if !sanMatchesLabel(facts.DNSNames, spec.label) {
			return Check{Status: "fail", Detail: "no certificate subject alternative name matches the expected role entry-point label"}
		}
	}
	return Check{
		Status: "pass",
		Detail: "observed certificate evidence is trusted, in date and name-matched for the role's entry points " +
			"(evidence only; asserts nothing about host or domain readiness)",
	}
}

// sanMatchesLabel reports whether any SAN is a safe hostname whose
// first label equals want. A wildcard SAN ("*.example") is deliberately
// NOT accepted as a match for a specific entry-point label: it proves
// nothing about which name the operator intended to serve here.
func sanMatchesLabel(sans []string, want string) bool {
	for _, s := range sans {
		if !isSafeProbeName(s) {
			continue
		}
		if hasExpectedLabel(s, want) {
			return true
		}
	}
	return false
}

// hasExpectedLabel reports whether name's FIRST DNS label equals want
// exactly (ASCII case-insensitive, as DNS labels are).
//
// It is an exact label comparison, never a prefix or substring test: a
// name like "mihomo-gateway-evil.example" must NOT match the label
// "mihomo-gateway", and neither must a wildcard.
func hasExpectedLabel(name, want string) bool {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		// A single-label name has no domain part: not a deployment
		// entry point.
		return false
	}
	return asciiEqualFold(name[:i], want)
}

// asciiEqualFold compares two ASCII strings case-insensitively.
// Deliberately ASCII-only: DNS labels compared here are ASCII (an
// internationalized name arrives as its A-label), so a byte comparison
// is exact and locale-independent.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLowerByte(a[i]) != asciiLowerByte(b[i]) {
			return false
		}
	}
	return true
}

func asciiLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// parseProbeAddr parses an untrusted probe-supplied address as a
// NUMERIC IP literal.
//
// netip.ParseAddr performs no name resolution whatsoever, which is
// exactly why it is used here: a probe cannot smuggle a hostname into
// this path and cause a lookup.
//
// The input is NOT trimmed. Surrounding whitespace in a record value is
// not a formatting quirk to be forgiven, it is a sign the value did not
// come from a well-formed record, so it is refused along with zoned
// addresses and every non-literal form.
func parseProbeAddr(s string) (netip.Addr, error) {
	if s != strings.TrimSpace(s) {
		return netip.Addr{}, errProbe("address carries surrounding whitespace")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errProbe("zoned address is not a valid record target")
	}
	return addr, nil
}

// isSafeProbeName reports whether an untrusted probe-supplied name is a
// syntactically valid, injection-free DNS hostname.
//
// This is the gate that stops hostile probe data from ever being
// meaningful: control characters, whitespace, quotes, YAML/JSON
// metacharacters, wildcards, empty or over-long labels and trailing
// dots are all rejected. A rejected name fails the check with a fixed
// message and is never echoed.
func isSafeProbeName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	// A trailing dot is a legal FQDN form but is refused here so the
	// label arithmetic below has exactly one meaning.
	if strings.HasSuffix(name, ".") || strings.HasPrefix(name, ".") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c == '-':
			default:
				// Anything else — including '*', '"', ':', '\n', '\x00',
				// spaces and every other injection vector — is refused.
				return false
			}
		}
	}
	return true
}
