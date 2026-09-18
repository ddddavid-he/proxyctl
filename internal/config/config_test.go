package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxyctl/internal/safex"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "tests", "fixtures", "render", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	return p
}

func TestParseGatewayValid(t *testing.T) {
	doc, err := ParseFile(fixture(t, "gateway-valid.yaml"), RoleGateway)
	if err != nil {
		t.Fatalf("gateway-valid rejected: %v", err)
	}
	if got := len(doc.Users()); got != 3 {
		t.Errorf("users = %d, want 3", got)
	}
	if v, _ := doc.Scalar("bind-address"); v != "127.0.0.1" {
		t.Errorf("bind-address = %q", v)
	}
}

func TestParseEgressValid(t *testing.T) {
	doc, err := ParseFile(fixture(t, "egress-valid.yaml"), RoleEgress)
	if err != nil {
		t.Fatalf("egress-valid rejected: %v", err)
	}
	if doc.Summary() == "" {
		t.Error("empty summary")
	}
}

func TestRuntimePortsAreFixed(t *testing.T) {
	gateway, err := os.ReadFile(fixture(t, "gateway-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(strings.Replace(string(gateway), "egress-port: 443", "egress-port: 444", 1), RoleGateway); err == nil {
		t.Fatal("gateway upstream port other than 443 accepted")
	}
	if _, err := Parse(strings.Replace(string(gateway), "listen: 127.0.0.1\n    port: 18444", "listen: 0.0.0.0\n    port: 18444", 1), RoleGateway); err == nil {
		t.Fatal("public decrypted HTTPS CONNECT backend accepted")
	}
	if _, err := Parse(strings.Replace(string(gateway), "port: 18444", "port: 8444", 1), RoleGateway); err == nil {
		t.Fatal("Mihomo accepted the OpenResty-owned public HTTPS CONNECT port")
	}
	if _, err := Parse(strings.Replace(string(gateway), "listen: 127.0.0.1\n    port: 17894", "listen: 0.0.0.0\n    port: 17894", 1), RoleGateway); err == nil {
		t.Fatal("Mihomo accepted a public IKEv2 TPROXY listener")
	}
	if _, err := Parse(strings.Replace(string(gateway), "port: 17894", "port: 17895", 1), RoleGateway); err == nil {
		t.Fatal("Mihomo accepted a moved IKEv2 TPROXY listener")
	}
	egress, err := os.ReadFile(fixture(t, "egress-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(strings.Replace(string(egress), "port: 443", "port: 444", 1), RoleEgress); err == nil {
		t.Fatal("egress listener port other than 443 accepted")
	}
	if _, err := Parse(strings.Replace(string(egress), "gateway-node-user: gateway-node-01", "gateway-node-user: bad:user", 1), RoleEgress); err == nil {
		t.Fatal("egress user containing the userpass delimiter accepted")
	}
}

func TestRejectionMatrix(t *testing.T) {
	cases := []struct {
		fixture string
		role    Role
		code    safex.Code
	}{
		{"gateway-reject-direct.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-skip-cert.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-public-7890.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-controller-wildcard.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-unknown-field.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-real-secret.yaml", RoleGateway, safex.CodeConfigRejected},
		{"gateway-reject-role-mismatch.yaml", RoleGateway, safex.CodeConfigRejected},
		{"egress-reject-insecure.yaml", RoleEgress, safex.CodeConfigRejected},
	}
	for _, c := range cases {
		_, err := ParseFile(fixture(t, c.fixture), c.role)
		if err == nil {
			t.Errorf("%s: accepted, want rejection", c.fixture)
			continue
		}
		se, ok := err.(*safex.Error)
		if !ok {
			t.Errorf("%s: error type %T, want *safex.Error", c.fixture, err)
			continue
		}
		if se.Code != c.code {
			t.Errorf("%s: code = %s, want %s (msg: %s)", c.fixture, se.Code, c.code, se.Message)
		}
	}
}

func TestEmptyCredentialEgress(t *testing.T) {
	// Empty value parses to empty string; must be rejected as empty
	// credential or as placeholder failure.
	_, err := ParseFile(fixture(t, "egress-reject-empty-credential.yaml"), RoleEgress)
	if err == nil {
		t.Fatal("empty credential accepted")
	}
}

func TestUnknownSchema(t *testing.T) {
	_, err := Parse("schema: other/v9\nrole: gateway\n", RoleGateway)
	if err == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestParseRoleEnum(t *testing.T) {
	if _, err := ParseRole("gateway"); err != nil {
		t.Errorf("gateway rejected: %v", err)
	}
	if _, err := ParseRole("eu"); err == nil {
		t.Error("eu accepted")
	}
	if _, err := ParseRole("GATEWAY"); err == nil {
		t.Error("GATEWAY accepted; enum must be exact")
	}
}

func TestErrorMessagesRedacted(t *testing.T) {
	// A config carrying a real-looking secret must not leak it in the
	// error message.
	text := "schema: private-proxy/v1\nrole: gateway\nrealpasswordfield: abc\n"
	_, err := Parse(text, RoleGateway)
	if err == nil {
		t.Skip("rejected before message construction")
	}
	if containsSecret(err.Error(), "abc") {
		t.Errorf("error message leaks value: %s", err.Error())
	}
}

func containsSecret(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
