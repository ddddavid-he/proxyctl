package render

import (
	"os"
	"strings"
	"testing"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

func TestBundlePhaseQuotesSecrets(t *testing.T) {
	// A secret containing quote, backslash, colon AND hash must land in
	// the output as ONE double-quoted scalar, escapes intact.
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	src := fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": `CANARY-VALUE "q" \b c:d #e`,
	}}
	out, err := substituteCredentials(tmpl, src)
	if err != nil {
		t.Fatalf("substituteCredentials: %v", err)
	}
	want := `password: "CANARY-VALUE \"q\" \\b c:d #e"` + "\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
	// The raw (unescaped) secret bytes must not appear verbatim.
	if strings.Contains(out, `"q" \b`) {
		t.Errorf("output contains unescaped secret bytes: %q", out)
	}
}

func TestBundlePhaseComposesHysteriaUserpass(t *testing.T) {
	doc, err := config.Parse("schema: private-proxy/v1\nrole: gateway\ngateway-egress-user: gateway-node-01\ngateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}\n", config.RoleGateway) // secret-scan:allow-line synthetic placeholder-only config
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	out, err := substituteCredentials("password: ${GATEWAY_EGRESS_AUTH}\n", fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": "CANARY-VALUE",
	}}, doc)
	if err != nil {
		t.Fatalf("substituteCredentials: %v", err)
	}
	if out != "password: \"gateway-node-01:CANARY-VALUE\"\n" {
		t.Errorf("derived userpass output = %q", out)
	}
}

func TestBundlePhaseRejectsAmbiguousHysteriaUser(t *testing.T) {
	doc, err := config.Parse("schema: private-proxy/v1\nrole: gateway\ngateway-egress-user: bad:user\ngateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}\n", config.RoleGateway) // secret-scan:allow-line synthetic placeholder-only rejection config
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	_, err = substituteCredentials("password: ${GATEWAY_EGRESS_AUTH}\n", fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": "CANARY-VALUE",
	}}, doc)
	requireCode(t, err, safex.CodeConfigRejected)
	requireNoCanary(t, err)
}

func TestBundlePhaseRejectsNewlineValue(t *testing.T) {
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	for _, v := range []string{
		"CANARY-VALUE\ninjected: line",
		"CANARY-VALUE\r\nnext: 1",
		"CANARY-VALUE\r",
	} {
		_, err := substituteCredentials(tmpl, fakeBundle{scalars: map[string]string{
			"GATEWAY_EGRESS_PASSWORD_1": v,
		}})
		requireCode(t, err, safex.CodeConfigRejected)
		requireNoCanary(t, err)
	}
}

func TestBundlePhaseRejectsControlValue(t *testing.T) {
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	for _, v := range []string{
		"CANARY-VALUE\x00nul",
		"CANARY-VALUE\x1b[31mesc",
		"CANARY-VALUE\t" + "tab",
		"CANARY-VALUE\x7f",
		"CANARY-VALUE\u2028",
	} {
		_, err := substituteCredentials(tmpl, fakeBundle{scalars: map[string]string{
			"GATEWAY_EGRESS_PASSWORD_1": v,
		}})
		requireCode(t, err, safex.CodeConfigRejected)
		requireNoCanary(t, err)
	}
}

func TestBundlePhaseRejectsPlaceholderShapedValue(t *testing.T) {
	// A credential value that itself looks like a placeholder must be
	// rejected: substituting it would smuggle a nested ${...} into the
	// output (and potentially re-enter substitution).
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	for _, v := range []string{
		"${NESTED}",
		"prefix${NESTED}suffix",
		"CANARY-VALUE${GATEWAY_EGRESS_PASSWORD_1}",
	} {
		_, err := substituteCredentials(tmpl, fakeBundle{scalars: map[string]string{
			"GATEWAY_EGRESS_PASSWORD_1": v,
		}})
		requireCode(t, err, safex.CodeConfigRejected)
		requireNoCanary(t, err)
	}
}

// TestBundlePhaseRejectsEmptyValue pins the defense-in-depth guard: a
// bundle that resolves a placeholder to the empty string must fail the
// render, not publish an empty (unauthenticated) credential.
func TestBundlePhaseRejectsEmptyValue(t *testing.T) {
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line placeholder-only template literal, no secret value
	out, err := substituteCredentials(tmpl, fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": "",
	}})
	requireCode(t, err, safex.CodeConfigRejected)
	requireNoCanary(t, err)
	if out != "" {
		t.Errorf("output produced despite an empty credential: %q", out)
	}
}

func TestBundlePhaseRejectsUnknownPlaceholder(t *testing.T) {
	tmpl := "value: ${TOTALLY_UNKNOWN}\n"
	_, err := substituteCredentials(tmpl, fakeBundle{})
	requireCode(t, err, safex.CodeTemplateRejected)
	requireNoCanary(t, err)
	// The diagnostic must NOT echo the attacker-controlled name.
	if strings.Contains(err.Error(), "TOTALLY_UNKNOWN") {
		t.Errorf("error echoed an attacker-controlled placeholder name: %q", err.Error())
	}
}

func TestBundlePhaseRejectsMissingCredential(t *testing.T) {
	// Schema-declared but not resolvable from the bundle: NOT_FOUND,
	// named by placeholder only.
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	_, err := substituteCredentials(tmpl, fakeBundle{})
	requireCode(t, err, safex.CodeNotFound)
	requireNoCanary(t, err)
}

func TestBundlePhaseRejectsDanglingPlaceholder(t *testing.T) {
	// "${" without a closing "}" is invisible to the variable
	// extractor; the dangling post-check must still fail the render.
	src := fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": "CANARY-VALUE",
	}}
	tmpl := "password: ${GATEWAY_EGRESS_PASSWORD_1}\nnote: ${\n"
	_, err := substituteCredentials(tmpl, src)
	requireCode(t, err, safex.CodeTemplateRejected)
	requireNoCanary(t, err)
}

func TestBundlePhaseRejectsNestedPlaceholderInTemplate(t *testing.T) {
	// ${OUTER_${INNER}} extracts as "OUTER_${INNER", which is not a
	// declared schema name: nested placeholders in template text are
	// rejected as unknown.
	src := fakeBundle{scalars: map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": "CANARY-VALUE",
	}}
	tmpl := "password: ${OUTER_${INNER}}\n"
	_, err := substituteCredentials(tmpl, src)
	requireCode(t, err, safex.CodeTemplateRejected)
	requireNoCanary(t, err)
}

// TestNoSentinelBundleInProductionCode is a source-level guard: the
// non-test sources of this package must not define a bundle that
// resolves secret placeholders to fixed sentinel text. Such a stub
// would, if it ever reached a real render, publish a config whose
// credentials are non-secrets — a silently broken and insecure
// deployment instead of a fail-closed refusal.
func TestNoSentinelBundleInProductionCode(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"validationBundle", "validation-only-placeholder"} {
			for _, line := range strings.Split(string(src), "\n") {
				code := line
				if i := strings.Index(code, "//"); i >= 0 {
					code = code[:i]
				}
				if strings.Contains(code, banned) {
					t.Errorf("%s must not define a sentinel credential bundle (%q): %s", name, banned, line)
				}
			}
		}
	}
}

// TestEveryCredentialPlaceholderIsCoveredByTheBundleContract proves the
// schema's secret placeholders are exactly the names a bundle must be
// able to resolve, so a template can never carry a secret placeholder
// no bundle knows about.
func TestEveryCredentialPlaceholderIsCoveredByTheBundleContract(t *testing.T) {
	names := schemaNames(kindSecret)
	if len(names) == 0 {
		t.Fatal("schema declares no credential placeholders")
	}
	b := synthGateway()
	// The gateway bundle resolves every gateway placeholder; the egress-only alias
	// resolves through the fixed alias to the same shared credential.
	for _, name := range names {
		if name == "GATEWAY_EGRESS_AUTH" {
			continue // derived from gateway-egress-user plus GATEWAY_EGRESS_PASSWORD_1
		}
		v, ok := b.Scalar(name)
		if !ok {
			// GATEWAY_NODE_USER-style egress names are not gateway credentials; only
			// the fixed secret names must resolve for the role that
			// uses them. Assert the alias specifically.
			if name == "GATEWAY_NODE_PASSWORD_1" {
				t.Errorf("the fixed alias ${%s} must resolve", name)
			}
			continue
		}
		if err := rejectUnsafeValue(v); err != nil {
			t.Errorf("synthetic ${%s} violates the insertion contract: %v", name, err)
		}
	}
	// The alias and its canonical name are the SAME credential.
	alias, aok := b.Scalar("GATEWAY_NODE_PASSWORD_1")
	canon, cok := b.Scalar("GATEWAY_EGRESS_PASSWORD_1")
	if !aok || !cok || alias != canon {
		t.Errorf("alias resolution differs: %v/%v", aok, cok)
	}
	// A non-secret placeholder is never a bundle credential.
	if v, ok := b.Scalar("MIXED_PORT"); ok {
		t.Errorf("bundle resolved a non-secret placeholder: %q", v)
	}
}
