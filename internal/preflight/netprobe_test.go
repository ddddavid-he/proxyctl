package preflight

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// goSourceFiles returns the NON-test Go sources of dir, keyed by name.
// Test files are excluded on purpose: the source-level guard below is
// about what production code may call, and a test may legitimately
// mention a banned identifier in an assertion.
func goSourceFiles(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = string(data)
	}
	return out, nil
}

// Synthetic DNS/certificate evidence tests. Everything here is
// in-memory: no DNS query, no ACME or provider call, no certificate
// issuance or renewal, and no read of any real certificate is performed
// by these tests or by the code they exercise.

// Canary tokens planted in probe facts and probe errors. Every check
// detail is asserted NOT to contain them, which is what proves untrusted
// probe data cannot be reflected into output.
const (
	canaryHost     = "SYNTH-CANARY-secret-host.internal.invalid"
	canarySAN      = "SYNTH-CANARY-san.internal.invalid"
	canaryAddr     = "203.0.113.77"
	canaryErrText  = "dial 203.0.113.77:443: SYNTH-CANARY-probe-error-detail"
	canaryResolver = "SYNTH-CANARY-resolver.invalid"
)

// probeCanaries lists every planted token. Detail strings are checked
// against all of them.
var probeCanaries = []string{
	canaryHost, canarySAN, canaryAddr, canaryErrText, canaryResolver,
	"SYNTH-CANARY", "203.0.113.77", "internal.invalid",
}

// fixedNow is the deterministic evaluation instant. Certificate cases
// are expressed relative to it so the tests never depend on the clock.
var fixedNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// fakeNetProbe is a synthetic NetProbe: it serves canned facts/errors
// per target and counts calls, so offline behavior can be asserted as
// "zero calls" rather than inferred.
type fakeNetProbe struct {
	dnsFacts  map[Target]DNSFacts
	dnsErrs   map[Target]error
	certFacts map[Target]CertificateFacts
	certErrs  map[Target]error

	dnsCalls  int
	certCalls int
	// seen records which targets were asked about, proving only
	// allowlisted targets of the role are probed.
	seen []Target
}

func (p *fakeNetProbe) DNS(t Target) (DNSFacts, error) {
	p.dnsCalls++
	p.seen = append(p.seen, t)
	if err, ok := p.dnsErrs[t]; ok {
		return DNSFacts{}, err
	}
	f, ok := p.dnsFacts[t]
	if !ok {
		return DNSFacts{Target: t}, nil // unresolved
	}
	return f, nil
}

func (p *fakeNetProbe) Certificate(t Target) (CertificateFacts, error) {
	p.certCalls++
	p.seen = append(p.seen, t)
	if err, ok := p.certErrs[t]; ok {
		return CertificateFacts{}, err
	}
	f, ok := p.certFacts[t]
	if !ok {
		return CertificateFacts{Target: t}, nil // absent
	}
	return f, nil
}

func (p *fakeNetProbe) totalCalls() int { return p.dnsCalls + p.certCalls }

// goodDNS returns consistent DNS evidence for a target.
func goodDNS(t Target) DNSFacts {
	spec := targetSpecs[t]
	return DNSFacts{
		Target:    t,
		Resolved:  true,
		Name:      spec.label + ".example.com",
		Addresses: []string{"198.51.100.10"},
	}
}

// goodCert returns consistent certificate evidence for a target.
func goodCert(t Target) CertificateFacts {
	spec := targetSpecs[t]
	return CertificateFacts{
		Target:    t,
		Present:   true,
		DNSNames:  []string{spec.label + ".example.com"},
		NotBefore: fixedNow.Add(-30 * 24 * time.Hour),
		NotAfter:  fixedNow.Add(60 * 24 * time.Hour),
		Trusted:   true,
	}
}

// goodNetProbe returns a probe with consistent evidence for every
// target of every role.
func goodNetProbe() *fakeNetProbe {
	p := &fakeNetProbe{
		dnsFacts:  map[Target]DNSFacts{},
		certFacts: map[Target]CertificateFacts{},
		dnsErrs:   map[Target]error{},
		certErrs:  map[Target]error{},
	}
	for _, t := range []Target{TargetMihomoGateway, TargetNativeGateway, TargetProxyEgress} {
		p.dnsFacts[t] = goodDNS(t)
		p.certFacts[t] = goodCert(t)
	}
	return p
}

// runNet executes an online preflight with the synthetic net probe at
// the fixed instant.
func runNet(t *testing.T, role string, np NetProbe) *Result {
	t.Helper()
	res, err := Run(Options{
		Role: role, Offline: false,
		Probe: goodOnlineProbe(), NetProbe: np, now: fixedNow,
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return res
}

// assertNoProbeLeak fails when a check detail carries any planted token
// or a control character.
func assertNoProbeLeak(t *testing.T, c *Check) {
	t.Helper()
	if c == nil {
		return
	}
	for _, tok := range probeCanaries {
		if strings.Contains(c.Detail, tok) {
			t.Errorf("check %q detail leaks %q: %q", c.Name, tok, c.Detail)
		}
	}
	if strings.ContainsAny(c.Detail, "\r\n\t\x00") {
		t.Errorf("check %q detail carries control characters: %q", c.Name, c.Detail)
	}
}

// --- offline: zero probe calls ---------------------------------------

// TestOfflineMakesZeroDNSAndCertificateProbeCalls is the offline
// contract: --offline must make EXACTLY zero DNS and certificate probe
// calls, and must emit neither evidence check.
func TestOfflineMakesZeroDNSAndCertificateProbeCalls(t *testing.T) {
	for _, role := range []string{"gateway", "egress"} {
		np := goodNetProbe()
		hostProbe := &fakeProbe{}
		res, err := Run(Options{
			Role: role, Offline: true,
			Probe: hostProbe, NetProbe: np, now: fixedNow,
		})
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
		if np.totalCalls() != 0 {
			t.Errorf("role %s: offline made %d DNS/certificate probe calls (dns=%d cert=%d); want 0",
				role, np.totalCalls(), np.dnsCalls, np.certCalls)
		}
		if hostProbe.totalCalls() != 0 {
			t.Errorf("role %s: offline invoked the host probe %d times; want 0", role, hostProbe.totalCalls())
		}
		for _, name := range []string{"dns-evidence", "certificate-evidence"} {
			if c := findCheck(res, name); c != nil {
				t.Errorf("role %s: offline run emitted a %s check: %+v", role, name, *c)
			}
		}
		// The offline marker must state that no certificate probe ran.
		c := findCheck(res, "offline-mode")
		if c == nil || c.Status != "pass" {
			t.Fatalf("role %s: offline-mode marker missing: %+v", role, c)
		}
		if !strings.Contains(c.Detail, "certificate") {
			t.Errorf("role %s: offline marker does not mention certificates: %q", role, c.Detail)
		}
		// The run may still be non-OK for an unrelated reason: the arch
		// check compares GOARCH against the role's expectation, which
		// fails on any host that is not the role's target architecture.
		// Only require OK when the evidence-independent checks passed.
		arch := findCheck(res, "arch")
		if arch != nil && arch.Status == "pass" && !res.OK {
			t.Errorf("role %s: offline run not OK despite a passing arch check", role)
		}
	}
}

// TestOfflineWithFailingProbeStillMakesNoCalls proves offline short-
// circuits before the probe, even when the probe would error.
func TestOfflineWithFailingProbeStillMakesNoCalls(t *testing.T) {
	np := &fakeNetProbe{
		dnsErrs:  map[Target]error{TargetMihomoGateway: errors.New(canaryErrText)},
		certErrs: map[Target]error{TargetMihomoGateway: errors.New(canaryErrText)},
	}
	res, err := Run(Options{Role: "gateway", Offline: true, NetProbe: np, now: fixedNow})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if np.totalCalls() != 0 {
		t.Errorf("offline made %d probe calls; want 0", np.totalCalls())
	}
	for _, c := range res.Checks {
		assertNoProbeLeak(t, &c)
	}
}

// --- production default fails closed ---------------------------------

// TestDefaultNetProbeFailsClosed proves a nil NetProbe (the production
// default) yields FAILING dns and certificate checks with sanitized
// details — never a pass, and never a skip that reads like a pass.
func TestDefaultNetProbeFailsClosed(t *testing.T) {
	for _, role := range []string{"gateway", "egress"} {
		res, err := Run(Options{
			Role: role, Offline: false,
			Probe: goodOnlineProbe(), now: fixedNow,
			// NetProbe deliberately nil.
		})
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
		for _, name := range []string{"dns-evidence", "certificate-evidence"} {
			c := findCheck(res, name)
			if c == nil {
				t.Fatalf("role %s: %s check missing", role, name)
			}
			if c.Status != "fail" {
				t.Errorf("role %s: %s = %q (%s); want fail (unavailable evidence must fail closed)",
					role, name, c.Status, c.Detail)
			}
			assertNoProbeLeak(t, c)
		}
		if res.OK {
			t.Errorf("role %s: result OK despite unavailable name/certificate evidence", role)
		}
	}
}

// --- typed-nil NetProbe ------------------------------------------------

// ptrNetProbe is a POINTER-receiver NetProbe implementation, so a nil
// *ptrNetProbe can be stored in a NetProbe interface: the interface is
// then non-nil (`== nil` is false) while every method call runs on a nil
// receiver. That is the typed-nil case the guard must catch.
type ptrNetProbe struct {
	dnsCalls  int
	certCalls int
}

func (p *ptrNetProbe) DNS(t Target) (DNSFacts, error) {
	// A real implementation would touch p here and panic on nil.
	p.dnsCalls++
	return goodDNS(t), nil
}

func (p *ptrNetProbe) Certificate(t Target) (CertificateFacts, error) {
	p.certCalls++
	return goodCert(t), nil
}

// TestTypedNilNetProbeFailsClosed proves a typed-nil NetProbe produces a
// stable fail-closed result: no panic, both evidence checks fail, and
// the probe is never actually invoked.
func TestTypedNilNetProbeFailsClosed(t *testing.T) {
	var typed *ptrNetProbe // nil pointer
	var np NetProbe = typed
	if np == nil {
		t.Fatal("test premise broken: typed nil compared equal to nil")
	}
	for _, role := range []string{"gateway", "egress"} {
		// Recover so a panic is reported as a failure rather than
		// aborting the whole test binary.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("role %s: typed-nil NetProbe panicked: %v", role, r)
				}
			}()
			res, err := Run(Options{
				Role: role, Offline: false,
				Probe: goodOnlineProbe(), NetProbe: np, now: fixedNow,
			})
			if err != nil {
				t.Errorf("role %s: run returned an error: %v", role, err)
				return
			}
			for _, name := range []string{"dns-evidence", "certificate-evidence"} {
				c := findCheck(res, name)
				if c == nil {
					t.Errorf("role %s: %s check missing", role, name)
					continue
				}
				if c.Status != "fail" {
					t.Errorf("role %s: %s = %q (%s); want fail (typed-nil probe must fail closed)",
						role, name, c.Status, c.Detail)
				}
				assertNoProbeLeak(t, c)
			}
			if res.OK {
				t.Errorf("role %s: result OK with a typed-nil probe", role)
			}
		}()
	}
	// The nil probe must never have been invoked.
	if typed != nil {
		t.Error("probe pointer was replaced")
	}
}

// TestIsNilNetProbeCoversNilForms pins the helper against a literal nil
// interface, a typed nil, and a real implementation.
func TestIsNilNetProbeCoversNilForms(t *testing.T) {
	var typed *ptrNetProbe
	cases := []struct {
		name string
		p    NetProbe
		want bool
	}{
		{"literal nil interface", nil, true},
		{"typed nil pointer", typed, true},
		{"real probe", goodNetProbe(), false},
		{"default unavailable probe", unavailableNetProbe{}, false},
	}
	for _, tc := range cases {
		if got := isNilNetProbe(tc.p); got != tc.want {
			t.Errorf("%s: isNilNetProbe = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestUnavailableNetProbeMakesNoNetworkClaims proves the default probe
// itself reports unavailability rather than fabricating facts.
func TestUnavailableNetProbeMakesNoNetworkClaims(t *testing.T) {
	var p NetProbe = unavailableNetProbe{}
	for _, target := range []Target{TargetMihomoGateway, TargetNativeGateway, TargetProxyEgress} {
		df, derr := p.DNS(target)
		if derr == nil {
			t.Errorf("default DNS probe returned success for target %v", target)
		}
		if df.Resolved || len(df.Addresses) != 0 || df.Name != "" {
			t.Errorf("default DNS probe fabricated facts: %+v", df)
		}
		cf, cerr := p.Certificate(target)
		if cerr == nil {
			t.Errorf("default certificate probe returned success for target %v", target)
		}
		if cf.Present || cf.Trusted || len(cf.DNSNames) != 0 {
			t.Errorf("default certificate probe fabricated facts: %+v", cf)
		}
	}
	// The fixed unavailability message names no host, path or resolver.
	msg := errProbeUnavailable.Error()
	for _, banned := range []string{"/", "http", "://", "resolv", "@"} {
		if strings.Contains(msg, banned) {
			t.Errorf("unavailability message leaks %q: %q", banned, msg)
		}
	}
}

// --- happy path -------------------------------------------------------

// TestDNSAndCertificateEvidencePass proves consistent synthetic
// evidence passes BOTH checks, for both roles, and that only the role's
// own allowlisted targets are probed.
func TestDNSAndCertificateEvidencePass(t *testing.T) {
	for _, tc := range []struct {
		role  string
		want  []Target
		other Target
	}{
		{"gateway", []Target{TargetMihomoGateway, TargetNativeGateway}, TargetProxyEgress},
		{"egress", []Target{TargetProxyEgress}, TargetMihomoGateway},
	} {
		np := goodNetProbe()
		res := runNet(t, tc.role, np)
		for _, name := range []string{"dns-evidence", "certificate-evidence"} {
			c := findCheck(res, name)
			if c == nil {
				t.Fatalf("role %s: %s check missing", tc.role, name)
			}
			if c.Status != "pass" {
				t.Errorf("role %s: %s = %q (%s); want pass", tc.role, name, c.Status, c.Detail)
			}
			assertNoProbeLeak(t, c)
		}
		// Exactly the role's targets were probed, each once per method.
		if np.dnsCalls != len(tc.want) || np.certCalls != len(tc.want) {
			t.Errorf("role %s: calls dns=%d cert=%d; want %d each",
				tc.role, np.dnsCalls, np.certCalls, len(tc.want))
		}
		for _, seen := range np.seen {
			if seen == tc.other {
				t.Errorf("role %s: probed the other role's target %v", tc.role, tc.other)
			}
		}
	}
}

// TestEvidenceChecksMakeNoConfiguredClaim proves the passing details
// state they are evidence only and never claim a host or domain is
// configured.
func TestEvidenceChecksMakeNoConfiguredClaim(t *testing.T) {
	res := runNet(t, "gateway", goodNetProbe())
	for _, name := range []string{"dns-evidence", "certificate-evidence"} {
		c := findCheck(res, name)
		if c == nil {
			t.Fatalf("%s missing", name)
		}
		low := strings.ToLower(c.Detail)
		if !strings.Contains(low, "evidence only") {
			t.Errorf("%s detail must mark itself evidence-only: %q", name, c.Detail)
		}
		// The detail must disclaim readiness rather than assert it.
		if !strings.Contains(low, "asserts nothing about host or domain readiness") {
			t.Errorf("%s detail must disclaim host/domain readiness: %q", name, c.Detail)
		}
		for _, overclaim := range []string{
			"host is configured", "domain is configured",
			"correctly configured", "verified working", "is deployed",
			"is ready", "fully configured",
		} {
			if strings.Contains(low, overclaim) {
				t.Errorf("%s detail overclaims (%q): %q", name, overclaim, c.Detail)
			}
		}
	}
	// The DNS pass must explicitly disclaim being certificate proof.
	dns := findCheck(res, "dns-evidence")
	if !strings.Contains(strings.ToLower(dns.Detail), "not certificate proof") {
		t.Errorf("DNS pass detail must disclaim certificate proof: %q", dns.Detail)
	}
}

// --- DNS failure matrix ----------------------------------------------

// TestDNSEvidenceFailureMatrix covers expected name/role matching,
// missing records, malformed and hostile names, and unusable addresses.
// Every case must fail with a sanitized fixed detail.
func TestDNSEvidenceFailureMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DNSFacts)
	}{
		{"no record", func(f *DNSFacts) { f.Resolved = false; f.Addresses = nil }},
		{"wrong entry-point label", func(f *DNSFacts) { f.Name = "other-entry.example.com" }},
		{"label prefix is not a match", func(f *DNSFacts) { f.Name = "mihomo-gateway-evil.example.com" }},
		{"label suffix is not a match", func(f *DNSFacts) { f.Name = "evil-mihomo-gateway.example.com" }},
		{"wildcard name", func(f *DNSFacts) { f.Name = "*.example.com" }},
		{"single-label name", func(f *DNSFacts) { f.Name = "mihomo-gateway" }},
		{"trailing dot name", func(f *DNSFacts) { f.Name = "mihomo-gateway.example.com." }},
		{"canary host name", func(f *DNSFacts) { f.Name = canaryHost }},
		{"newline injected name", func(f *DNSFacts) { f.Name = "mihomo-gateway.example.com\nok: true" }},
		{"nul injected name", func(f *DNSFacts) { f.Name = "mihomo-gateway.example.com\x00" }},
		{"quote injected name", func(f *DNSFacts) { f.Name = `mihomo-gateway.example.com" evil: "1` }},
		{"space in name", func(f *DNSFacts) { f.Name = "mihomo-gateway .example.com" }},
		{"empty label", func(f *DNSFacts) { f.Name = "mihomo-gateway..example.com" }},
		{"empty name", func(f *DNSFacts) { f.Name = "" }},
		{"overlong name", func(f *DNSFacts) { f.Name = strings.Repeat("a", 250) + ".example.com" }},
		{"no address", func(f *DNSFacts) { f.Addresses = nil }},
		{"malformed address", func(f *DNSFacts) { f.Addresses = []string{"999.1.1.1"} }},
		{"hostname as address", func(f *DNSFacts) { f.Addresses = []string{"mihomo-gateway.example.com"} }},
		{"loopback address", func(f *DNSFacts) { f.Addresses = []string{"127.0.0.1"} }},
		{"ipv6 loopback address", func(f *DNSFacts) { f.Addresses = []string{"::1"} }},
		{"unspecified address", func(f *DNSFacts) { f.Addresses = []string{"0.0.0.0"} }},
		{"multicast address", func(f *DNSFacts) { f.Addresses = []string{"224.0.0.1"} }},
		{"one bad among good", func(f *DNSFacts) {
			f.Addresses = []string{"198.51.100.10", "127.0.0.1"}
		}},
		{"implausible address count", func(f *DNSFacts) {
			f.Addresses = make([]string, maxProbeNames+1)
			for i := range f.Addresses {
				f.Addresses[i] = "198.51.100.10"
			}
		}},
		{"target mismatch", func(f *DNSFacts) { f.Target = TargetProxyEgress }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			np := goodNetProbe()
			facts := goodDNS(TargetMihomoGateway)
			tc.mutate(&facts)
			np.dnsFacts[TargetMihomoGateway] = facts
			res := runNet(t, "gateway", np)
			c := findCheck(res, "dns-evidence")
			if c == nil {
				t.Fatal("dns-evidence check missing")
			}
			if c.Status != "fail" {
				t.Errorf("dns-evidence = %q (%s); want fail", c.Status, c.Detail)
			}
			assertNoProbeLeak(t, c)
			if res.OK {
				t.Error("result OK despite failing DNS evidence")
			}
		})
	}
}

// TestDNSProbeErrorIsSanitized proves a probe error (including a
// timeout) becomes a fixed detail with no underlying text.
func TestDNSProbeErrorIsSanitized(t *testing.T) {
	for _, probeErr := range []error{
		errors.New(canaryErrText),
		fmt.Errorf("lookup %s: i/o timeout", canaryHost),
		fmt.Errorf("resolver %s refused query for %s", canaryResolver, canaryHost),
		errProbe(canaryErrText),
	} {
		np := goodNetProbe()
		np.dnsErrs[TargetMihomoGateway] = probeErr
		res := runNet(t, "gateway", np)
		c := findCheck(res, "dns-evidence")
		if c == nil || c.Status != "fail" {
			t.Fatalf("dns-evidence = %+v; want fail", c)
		}
		assertNoProbeLeak(t, c)
		for _, tok := range []string{"timeout", "refused", "lookup", "resolver"} {
			if strings.Contains(strings.ToLower(c.Detail), tok) {
				t.Errorf("detail echoes probe error token %q: %q", tok, c.Detail)
			}
		}
	}
}

// --- certificate failure matrix --------------------------------------

// TestCertificateEvidenceFailureMatrix covers mismatched name/SAN,
// expired and not-yet-valid certificates, untrusted/invalid evidence and
// missing evidence. Every case fails with a sanitized fixed detail.
func TestCertificateEvidenceFailureMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CertificateFacts)
	}{
		{"absent", func(f *CertificateFacts) { f.Present = false }},
		{"untrusted chain", func(f *CertificateFacts) { f.Trusted = false }},
		{"expired", func(f *CertificateFacts) {
			f.NotBefore = fixedNow.Add(-60 * 24 * time.Hour)
			f.NotAfter = fixedNow.Add(-1 * time.Hour)
		}},
		{"expired exactly now", func(f *CertificateFacts) { f.NotAfter = fixedNow }},
		{"not yet valid", func(f *CertificateFacts) {
			f.NotBefore = fixedNow.Add(1 * time.Hour)
			f.NotAfter = fixedNow.Add(90 * 24 * time.Hour)
		}},
		{"inside renewal margin", func(f *CertificateFacts) {
			f.NotAfter = fixedNow.Add(certRenewalMargin - time.Hour)
		}},
		{"zero validity window", func(f *CertificateFacts) {
			f.NotBefore = time.Time{}
			f.NotAfter = time.Time{}
		}},
		{"zero not-after only", func(f *CertificateFacts) { f.NotAfter = time.Time{} }},
		{"inverted window", func(f *CertificateFacts) {
			f.NotBefore = fixedNow.Add(10 * 24 * time.Hour)
			f.NotAfter = fixedNow.Add(-10 * 24 * time.Hour)
		}},
		{"no SAN", func(f *CertificateFacts) { f.DNSNames = nil }},
		{"mismatched SAN", func(f *CertificateFacts) { f.DNSNames = []string{"other-entry.example.com"} }},
		{"canary SAN", func(f *CertificateFacts) { f.DNSNames = []string{canarySAN} }},
		{"wildcard SAN does not match a label", func(f *CertificateFacts) {
			f.DNSNames = []string{"*.example.com"}
		}},
		{"SAN label prefix is not a match", func(f *CertificateFacts) {
			f.DNSNames = []string{"mihomo-gateway-evil.example.com"}
		}},
		{"injected SAN", func(f *CertificateFacts) {
			f.DNSNames = []string{"mihomo-gateway.example.com\nevil: true"}
		}},
		{"nul in SAN", func(f *CertificateFacts) {
			f.DNSNames = []string{"mihomo-gateway.example.com\x00"}
		}},
		{"implausible SAN count", func(f *CertificateFacts) {
			f.DNSNames = make([]string, maxProbeNames+1)
			for i := range f.DNSNames {
				f.DNSNames[i] = "other.example.com"
			}
		}},
		{"target mismatch", func(f *CertificateFacts) { f.Target = TargetProxyEgress }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			np := goodNetProbe()
			facts := goodCert(TargetMihomoGateway)
			tc.mutate(&facts)
			np.certFacts[TargetMihomoGateway] = facts
			res := runNet(t, "gateway", np)
			c := findCheck(res, "certificate-evidence")
			if c == nil {
				t.Fatal("certificate-evidence check missing")
			}
			if c.Status != "fail" {
				t.Errorf("certificate-evidence = %q (%s); want fail", c.Status, c.Detail)
			}
			assertNoProbeLeak(t, c)
			if res.OK {
				t.Error("result OK despite failing certificate evidence")
			}
		})
	}
}

// TestCertificateValidityBoundaries pins the exact accept/reject
// boundary of the validity window and the renewal margin.
func TestCertificateValidityBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      string
	}{
		{"comfortably valid", fixedNow.Add(-24 * time.Hour), fixedNow.Add(90 * 24 * time.Hour), "pass"},
		{"exactly at renewal margin", fixedNow.Add(-24 * time.Hour), fixedNow.Add(certRenewalMargin), "pass"},
		{"one second inside margin", fixedNow.Add(-24 * time.Hour), fixedNow.Add(certRenewalMargin - time.Second), "fail"},
		{"valid from exactly now", fixedNow, fixedNow.Add(90 * 24 * time.Hour), "pass"},
		{"valid from one second ahead", fixedNow.Add(time.Second), fixedNow.Add(90 * 24 * time.Hour), "fail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			np := goodNetProbe()
			f := goodCert(TargetMihomoGateway)
			f.NotBefore, f.NotAfter = tc.notBefore, tc.notAfter
			np.certFacts[TargetMihomoGateway] = f
			res := runNet(t, "gateway", np)
			c := findCheck(res, "certificate-evidence")
			if c == nil {
				t.Fatal("certificate-evidence missing")
			}
			if c.Status != tc.want {
				t.Errorf("certificate-evidence = %q (%s); want %q", c.Status, c.Detail, tc.want)
			}
			assertNoProbeLeak(t, c)
		})
	}
}

// TestCertificateProbeErrorIsSanitized proves a certificate probe error
// or timeout becomes a fixed detail.
func TestCertificateProbeErrorIsSanitized(t *testing.T) {
	for _, probeErr := range []error{
		errors.New(canaryErrText),
		fmt.Errorf("tls handshake with %s: i/o timeout", canaryHost),
		fmt.Errorf("x509: certificate is valid for %s, not %s", canarySAN, canaryHost),
	} {
		np := goodNetProbe()
		np.certErrs[TargetMihomoGateway] = probeErr
		res := runNet(t, "gateway", np)
		c := findCheck(res, "certificate-evidence")
		if c == nil || c.Status != "fail" {
			t.Fatalf("certificate-evidence = %+v; want fail", c)
		}
		assertNoProbeLeak(t, c)
		for _, tok := range []string{"x509", "handshake", "timeout"} {
			if strings.Contains(strings.ToLower(c.Detail), tok) {
				t.Errorf("detail echoes probe error token %q: %q", tok, c.Detail)
			}
		}
	}
}

// --- DNS and certificate evidence are independent --------------------

// TestPassingDNSIsNotCertificateProof is the separation contract: DNS
// evidence that fully passes must NOT rescue absent, untrusted, expired
// or name-mismatched certificate evidence, and vice versa.
func TestPassingDNSIsNotCertificateProof(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*fakeNetProbe)
		wantDNS string
		wantCrt string
	}{
		{"good DNS, absent certificate", func(p *fakeNetProbe) {
			f := goodCert(TargetMihomoGateway)
			f.Present = false
			p.certFacts[TargetMihomoGateway] = f
		}, "pass", "fail"},
		{"good DNS, untrusted certificate", func(p *fakeNetProbe) {
			f := goodCert(TargetMihomoGateway)
			f.Trusted = false
			p.certFacts[TargetMihomoGateway] = f
		}, "pass", "fail"},
		{"good DNS, expired certificate", func(p *fakeNetProbe) {
			f := goodCert(TargetMihomoGateway)
			f.NotAfter = fixedNow.Add(-time.Hour)
			p.certFacts[TargetMihomoGateway] = f
		}, "pass", "fail"},
		{"good certificate, missing DNS", func(p *fakeNetProbe) {
			f := goodDNS(TargetMihomoGateway)
			f.Resolved = false
			p.dnsFacts[TargetMihomoGateway] = f
		}, "fail", "pass"},
		{"good certificate, mismatched DNS name", func(p *fakeNetProbe) {
			f := goodDNS(TargetMihomoGateway)
			f.Name = "other-entry.example.com"
			p.dnsFacts[TargetMihomoGateway] = f
		}, "fail", "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			np := goodNetProbe()
			tc.mutate(np)
			res := runNet(t, "gateway", np)
			dns := findCheck(res, "dns-evidence")
			crt := findCheck(res, "certificate-evidence")
			if dns == nil || crt == nil {
				t.Fatal("evidence checks missing")
			}
			if dns.Status != tc.wantDNS {
				t.Errorf("dns-evidence = %q (%s); want %q", dns.Status, dns.Detail, tc.wantDNS)
			}
			if crt.Status != tc.wantCrt {
				t.Errorf("certificate-evidence = %q (%s); want %q", crt.Status, crt.Detail, tc.wantCrt)
			}
			// A single failing evidence check fails the whole run.
			if res.OK {
				t.Error("result OK despite one failing evidence check")
			}
			assertNoProbeLeak(t, dns)
			assertNoProbeLeak(t, crt)
		})
	}
}

// --- target allowlist -------------------------------------------------

// TestTargetsAreRoleScopedAndClosed proves the target allowlist is
// closed: every declared target belongs to exactly one role, and an
// out-of-range Target value fails closed instead of being probed.
func TestTargetsAreRoleScopedAndClosed(t *testing.T) {
	gateway := roleTargets("gateway")
	egress := roleTargets("egress")
	if len(gateway) != 2 || len(egress) != 1 {
		t.Fatalf("role targets: gateway=%v egress=%v", gateway, egress)
	}
	for _, c := range gateway {
		for _, u := range egress {
			if c == u {
				t.Errorf("target %v is shared between roles", c)
			}
		}
	}
	// An unknown role gets no targets (and the check fails closed).
	for _, role := range []string{"", "unknown", "GATEWAY", "all"} {
		if got := roleTargets(role); len(got) != 0 {
			t.Errorf("roleTargets(%q) = %v, want none", role, got)
		}
	}
	// An out-of-range Target has no spec.
	for _, bogus := range []Target{Target(-1), Target(99), Target(1000)} {
		if _, ok := bogus.spec(); ok {
			t.Errorf("bogus target %v resolved to a spec", bogus)
		}
	}
}

// TestUnknownRoleEvidenceFailsClosed proves an unknown role reaching the
// evidence checks directly fails closed rather than passing vacuously
// on an empty target list.
func TestUnknownRoleEvidenceFailsClosed(t *testing.T) {
	np := goodNetProbe()
	for _, role := range []string{"", "unknown", "GATEWAY"} {
		if c := checkDNS(role, np); c.Status != "fail" {
			t.Errorf("checkDNS(%q) = %q; want fail", role, c.Status)
		}
		if c := checkCertificate(role, np, fixedNow); c.Status != "fail" {
			t.Errorf("checkCertificate(%q) = %q; want fail", role, c.Status)
		}
	}
	// No probe call is needed to reject an unknown role.
	if np.totalCalls() != 0 {
		t.Errorf("unknown role caused %d probe calls; want 0", np.totalCalls())
	}
}

// --- name validation helpers ------------------------------------------

// TestIsSafeProbeName pins the untrusted-name gate.
func TestIsSafeProbeName(t *testing.T) {
	safe := []string{
		"mihomo-gateway.example.com", "a.b", "x1-y2.z3.example",
		strings.Repeat("a", 63) + ".example.com",
	}
	for _, n := range safe {
		if !isSafeProbeName(n) {
			t.Errorf("isSafeProbeName(%q) = false, want true", n)
		}
	}
	unsafe := []string{
		"", ".", "..", "single", "trailing.dot.", ".leading.dot",
		"*.example.com", "a..b", "-bad.example.com", "bad-.example.com",
		"has space.example.com", "has\ttab.example.com",
		"has\nnewline.example.com", "has\x00nul.example.com",
		`has"quote.example.com`, "has'quote.example.com",
		"has:colon.example.com", "has#hash.example.com",
		"has${dollar}.example.com", "under_score.example.com",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 200) + "example.com",
		"café.example.com",
	}
	for _, n := range unsafe {
		if isSafeProbeName(n) {
			t.Errorf("isSafeProbeName(%q) = true, want false", n)
		}
	}
}

// TestHasExpectedLabel pins exact first-label matching: no prefix,
// suffix, substring or wildcard match is ever accepted.
func TestHasExpectedLabel(t *testing.T) {
	match := []string{
		"mihomo-gateway.example.com", "MIHOMO-gateway.example.com",
		"Mihomo-Gateway.a.b.c",
	}
	for _, n := range match {
		if !hasExpectedLabel(n, "mihomo-gateway") {
			t.Errorf("hasExpectedLabel(%q) = false, want true", n)
		}
	}
	noMatch := []string{
		"mihomo-gateway-evil.example.com", "evil-mihomo-gateway.example.com",
		"xmihomo-gateway.example.com", "mihomo.example.com",
		"mihomo-gateway", "*.example.com", "", "native-gateway.example.com",
	}
	for _, n := range noMatch {
		if hasExpectedLabel(n, "mihomo-gateway") {
			t.Errorf("hasExpectedLabel(%q) = true, want false", n)
		}
	}
}

// TestParseProbeAddrRejectsNonLiterals proves the address parser never
// resolves a name and refuses zoned/garbage input.
func TestParseProbeAddrRejectsNonLiterals(t *testing.T) {
	ok := []string{"198.51.100.10", "2001:db8::1"}
	for _, s := range ok {
		if _, err := parseProbeAddr(s); err != nil {
			t.Errorf("parseProbeAddr(%q) = %v, want success", s, err)
		}
	}
	bad := []string{
		"", "localhost", "example.com", "mihomo-gateway.example.com",
		"999.1.1.1", "198.51.100.10:443", "fe80::1%eth0",
		"198.51.100.10\n", " 198.51.100.10 ", "198.51.100.10 ",
		"not an ip",
	}
	for _, s := range bad {
		if _, err := parseProbeAddr(s); err == nil {
			t.Errorf("parseProbeAddr(%q) succeeded, want failure", s)
		}
	}
}

// --- whole-result sanitization ---------------------------------------

// TestResultJSONNeverCarriesProbeData proves the full serialized result
// (what the CLI prints on stdout) carries no probe-supplied token, even
// when every fact is hostile.
func TestResultJSONNeverCarriesProbeData(t *testing.T) {
	np := goodNetProbe()
	hostile := DNSFacts{
		Target:    TargetMihomoGateway,
		Resolved:  true,
		Name:      canaryHost,
		Addresses: []string{canaryAddr, "127.0.0.1"},
	}
	np.dnsFacts[TargetMihomoGateway] = hostile
	np.certFacts[TargetMihomoGateway] = CertificateFacts{
		Target:    TargetMihomoGateway,
		Present:   true,
		DNSNames:  []string{canarySAN, "*." + canaryHost},
		NotBefore: fixedNow.Add(-time.Hour),
		NotAfter:  fixedNow.Add(-time.Minute),
		Trusted:   false,
	}
	np.dnsErrs[TargetNativeGateway] = errors.New(canaryErrText)
	np.certErrs[TargetNativeGateway] = errors.New(canaryErrText)

	res := runNet(t, "gateway", np)
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	out := string(blob)
	for _, tok := range probeCanaries {
		if strings.Contains(out, tok) {
			t.Errorf("result JSON leaks probe token %q: %s", tok, out)
		}
	}
	// Every fmt rendering is clean too.
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		rendered := fmt.Sprintf(verb, res)
		for _, tok := range probeCanaries {
			if strings.Contains(rendered, tok) {
				t.Errorf("result %s leaks probe token %q", verb, tok)
			}
		}
	}
	if res.OK {
		t.Error("result OK despite hostile evidence")
	}
}

// TestNoRealNetworkAPIsInPreflightSources is a source-level guard: this
// package must not reach for a real DNS resolver, an HTTP/TLS client or
// an ACME endpoint. The evidence boundary stays synthetic in this slice,
// and a future real probe must be added deliberately, not by accident.
func TestNoRealNetworkAPIsInPreflightSources(t *testing.T) {
	banned := []string{
		"net.Lookup", "net.Resolver", "net.Dial", "net.DialTimeout",
		"tls.Dial", "tls.Client", "http.Get", "http.Post",
		"http.Client", "net/http", "acme", "x509.Certificate",
		"LookupHost", "LookupIP", "LookupCNAME", "LookupTXT", "LookupAddr",
	}
	entries, err := goSourceFiles(".")
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range entries {
		for i, line := range strings.Split(src, "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			for _, b := range banned {
				if strings.Contains(code, b) {
					t.Errorf("%s:%d uses a real network API %q: %s", name, i+1, b, line)
				}
			}
		}
	}
}
