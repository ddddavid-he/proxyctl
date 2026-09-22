package render

import (
	"strings"
	"testing"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

func TestQuoteYAMLEscapesQuoteAndBackslash(t *testing.T) {
	cases := map[string]string{
		`plain`:       `"plain"`,
		`he said "x"`: `"he said \"x\""`,
		`back\slash`:  `"back\\slash"`,
		`both \" mix`: `"both \\\" mix"`,
		"":            `""`,
	}
	for in, want := range cases {
		if got := quoteYAML(in); got != want {
			t.Errorf("quoteYAML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoteYAMLColonHashAreLiteralInsideQuotes(t *testing.T) {
	// ':' and '#' are the YAML structure/comment characters; inside a
	// double-quoted scalar they must pass through literally (still
	// quoted), never escaped, never breaking the scalar.
	in := `key: value # comment`
	got := quoteYAML(in)
	if got != `"key: value # comment"` {
		t.Errorf("quoteYAML(%q) = %q", in, got)
	}
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("output not double-quoted: %q", got)
	}
}

func TestQuoteYAMLEscapesNewlineAndControl(t *testing.T) {
	// quoteYAML is defense-in-depth (the bundle phase rejects these
	// values outright); when asked, it must escape, never emit literal.
	cases := map[string]string{
		"a\nb":   `"a\nb"`,
		"a\rb":   `"a\rb"`,
		"a\tb":   `"a\tb"`,
		"a\x00b": `"a\x00b"`,
		"a\x1fb": `"a\x1fb"`,
		"a\x7fb": `"a\x7fb"`,
		// Unicode line/paragraph separators must be ESCAPED, never
		// emitted literally.
		"a\u2028b": `"a\u2028b"`,
		"a\u2029b": `"a\u2029b"`,
	}
	for in, want := range cases {
		got := quoteYAML(in)
		if got != want {
			t.Errorf("quoteYAML(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(got, "\r\n") || strings.IndexFunc(got, isYAMLControl) >= 0 {
			t.Errorf("quoteYAML(%q) emitted a literal control: %q", in, got)
		}
	}
}

func TestConfigPhaseLeavesCredentialPlaceholders(t *testing.T) {
	doc := mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: 7890
bind-address: 127.0.0.1
controller-listen: 127.0.0.1:9090
gateway-egress-user: gateway-node-01
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	tmpl := "mixed-port: ${MIXED_PORT}\ngateway-egress-user: ${GATEWAY_EGRESS_USER}\ngateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic placeholder-only template
	out, err := substituteConfig(tmpl, doc)
	if err != nil {
		t.Fatalf("substituteConfig: %v", err)
	}
	// Number raw, string double-quoted, credential untouched.
	want := "mixed-port: 7890\ngateway-egress-user: \"gateway-node-01\"\ngateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}\n" // secret-scan:allow-line synthetic expected placeholder output
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestConfigPhaseQuotesColonHashValues(t *testing.T) {
	doc := mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: 7890
bind-address: 127.0.0.1
controller-listen: 127.0.0.1:9090
gateway-egress-user: "user: with # marks"
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	tmpl := "gateway-egress-user: ${GATEWAY_EGRESS_USER}\n"
	out, err := substituteConfig(tmpl, doc)
	if err != nil {
		t.Fatalf("substituteConfig: %v", err)
	}
	if out != "gateway-egress-user: \"user: with # marks\"\n" {
		t.Errorf("output = %q", out)
	}
}

func TestConfigPhaseEmitsOnlySchemaMarkedNumbersRaw(t *testing.T) {
	doc := mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: 7890
bind-address: 127.0.0.1
controller-listen: 127.0.0.1:9090
gateway-egress-user: gateway-node-01
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	// A kindNumber placeholder rejects a non-number config value.
	bad := mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: "7890; rm -rf /"
bind-address: 127.0.0.1
controller-listen: 127.0.0.1:9090
gateway-egress-user: gateway-node-01
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	if _, err := substituteConfig("mixed-port: ${MIXED_PORT}\n", doc); err != nil {
		t.Fatalf("valid number rejected: %v", err)
	}
	_, err := substituteConfig("mixed-port: ${MIXED_PORT}\n", bad)
	requireCode(t, err, safex.CodeConfigRejected)
	requireNoCanary(t, err)
}

func TestConfigPhaseValidatesRawAddresses(t *testing.T) {
	// Keep mixed-port off 7890 so the bind-address posture coupling in
	// the config validator does not interfere with these cases.
	mk := func(addr string) *config.Document {
		return mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: 7891
bind-address: `+addr+`
controller-listen: 127.0.0.1:9090
gateway-egress-user: gateway-node-01
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	}
	tmpl := "bind-address: ${BIND_ADDRESS}\n"
	for _, ok := range []string{"127.0.0.1", "::1", "0.0.0.0", "[::1]:9090", "127.0.0.1:8080", "localhost"} {
		if _, err := substituteConfig(tmpl, mk(ok)); err != nil {
			t.Errorf("valid address %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"999.1.1.1", "not a host", `quo"te`, "a:b:c", "-bad-.x"} {
		if isValidAddress(bad) {
			t.Errorf("isValidAddress(%q) = true, want false", bad)
		}
		_, err := substituteConfig(tmpl, mk(`"`+bad+`"`))
		requireCode(t, err, safex.CodeConfigRejected)
		requireNoCanary(t, err)
	}
	// Out-of-range ports in a host:port form are invalid raw addresses.
	// isValidAddress is pure; test it directly (a controller-listen
	// fixture would trip unrelated posture checks in config.Parse).
	for _, bad := range []string{"127.0.0.1:0", "127.0.0.1:65536", "[::1]:99999", "127.0.0.1:notaport"} {
		if isValidAddress(bad) {
			t.Errorf("isValidAddress(%q) = true, want false", bad)
		}
	}
}

func TestAddressEmissionIsAlwaysQuoted(t *testing.T) {
	for _, value := range []string{
		"null", "true", "yes", "on", "off",
		"127.0.0.1", "::1", "127.0.0.1:8080", "[::1]:9090", "proxy.example",
	} {
		got, err := emit("BIND_ADDRESS", kindAddress, value)
		if err != nil {
			t.Errorf("emit address %q: %v", value, err)
			continue
		}
		want := quoteYAML(value)
		if got != want {
			t.Errorf("emit address %q = %q, want quoted %q", value, got, want)
		}
	}
}

func TestConfigPhaseRejectsUnknownAndUnresolved(t *testing.T) {
	doc := mustParseConfig(t, config.RoleGateway, `
schema: private-proxy/v1
role: gateway
mixed-port: 7890
bind-address: 127.0.0.1
controller-listen: 127.0.0.1:9090
gateway-egress-user: gateway-node-01
gateway-egress-password: ${GATEWAY_EGRESS_PASSWORD_1}
`)
	// Unknown (not schema-declared) placeholder name.
	_, err := substituteConfig("x: ${NO_SUCH_NAME}\n", doc)
	requireCode(t, err, safex.CodeTemplateRejected)
	requireNoCanary(t, err)
	// Schema-declared non-secret placeholder with no config value.
	_, err = substituteConfig("port: ${PORT}\n", doc)
	requireCode(t, err, safex.CodeConfigRejected)
	requireNoCanary(t, err)
}

func TestValidateTemplateUsesSchema(t *testing.T) {
	if err := validateTemplate("ok: ${MIXED_PORT}\ncred: ${GATEWAY_EGRESS_PASSWORD_1}\n"); err != nil {
		t.Fatalf("schema-declared placeholders rejected: %v", err)
	}
	err := validateTemplate("bad: ${USERNAME_9}\n")
	requireCode(t, err, safex.CodeTemplateRejected)
	requireNoCanary(t, err)
}
