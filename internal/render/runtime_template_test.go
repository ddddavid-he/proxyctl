package render

import (
	"strings"
	"testing"
)

func TestRuntimeTemplatesEmitUpstreamConfiguration(t *testing.T) {
	tests := []struct {
		role, templateDir, fixture string
		bundle                     Bundle
		required, forbidden        []string
	}{
		{
			role: "gateway", templateDir: "mihomo", fixture: "gateway-valid.yaml", bundle: synthGateway(),
			required:  []string{"proxies:\n", "type: hysteria2", "password: \"gateway-node-01:", "proxy-groups:\n", "listeners:\n", "certificate: /run/private-proxy/gateway.crt", "name: gateway-https-in\n    type: http\n", "listen: 127.0.0.1\n    port: 18444", "name: gateway-ikev2-tproxy\n    type: tproxy\n", "listen: 127.0.0.1\n    port: 17894\n    udp: true"},
			forbidden: []string{"schema: private-proxy/v1", "role: gateway", "skip-cert-verify", "DIRECT", "name: gateway-https-in\n    type: http\n    listen: 0.0.0.0"},
		},
		{
			role: "egress", templateDir: "hysteria", fixture: "egress-valid.yaml", bundle: synthEgress(),
			required:  []string{"listen: \"0.0.0.0:443\"", "tls:\n", "sniGuard: strict", "auth:\n", "type: userpass"},
			forbidden: []string{"schema: private-proxy/v1", "role: egress", "insecure:"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.role, func(t *testing.T) {
			f := newRenderFixture(t, tc.role, tc.templateDir, tc.fixture, tc.bundle)
			result, err := Run(f.opts)
			if err != nil {
				t.Fatalf("render runtime template: %v", err)
			}
			text := f.content(result.Files[0])
			for _, required := range tc.required {
				if !strings.Contains(text, required) {
					t.Errorf("rendered config is missing required upstream field %q", required)
				}
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(text, forbidden) {
					t.Errorf("rendered config contains forbidden/non-runtime field %q", forbidden)
				}
			}
		})
	}
}
