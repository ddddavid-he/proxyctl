package credential

import (
	"strings"
	"testing"

	"proxyctl/internal/safex"
)

// Canary values: distinctive byte strings planted in fixtures. Every
// error path asserts they never appear in returned errors.
const (
	gatewayEgressCanary = "cw-cnus-shared-9f2c"
	trojanUC            = "cw-trojan-user-41ad"
	trojanPC            = "cw-trojan-pass-b820"
	httpsUC             = "cw-https-user-77e0"
	httpsPC             = "cw-https-pass-13b5"
	httpsUC2            = "cw-https-user2-77e0"
	httpsPC2            = "cw-https-pass2-13b5"
	certGatewayCanary   = "cw-gateway-crt-pem-0d4a"
	keyGatewayCanary    = "cw-gateway-key-pem-6e91"
	certEgressCanary    = "cw-egress-crt-pem-25c7"
	keyEgressCanary     = "cw-egress-key-pem-8c33"
	optGatewayClientCr  = "cw-gateway-client-crt-59ff"
	optGatewayCA        = "cw-gateway-client-ca-30de"
)

// canaries lists every planted secret byte string. These are the ONLY
// strings assertNoLeak checks: fixed error messages (which legitimately
// contain words like "credentials") are safe and must not trip it.
var canaries = []string{
	gatewayEgressCanary, trojanUC, trojanPC, httpsUC, httpsPC, httpsUC2, httpsPC2,
	certGatewayCanary, keyGatewayCanary, certEgressCanary, keyEgressCanary,
	optGatewayClientCr, optGatewayCA,
}

// assertNoLeak fails if any planted canary appears in the error.
func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	got := err.Error()
	for _, b := range canaries {
		if strings.Contains(got, b) {
			t.Errorf("error message leaks canary %q: %q", b, got)
		}
	}
}

func assertCode(t *testing.T, err error, want safex.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	se, ok := err.(*safex.Error)
	if !ok {
		t.Fatalf("error is not *safex.Error: %T %v", err, err)
	}
	if se.Code != want {
		t.Fatalf("error code = %s, want %s (message %q)", se.Code, want, se.Message)
	}
}

// --- fake source (portable, no filesystem) ---------------------------

// fakeSource maps each name to a canned result. It exercises load()'s
// allowlist/validation/optional handling deterministically WITHOUT any
// filesystem access, so these tests run on every platform (including
// Darwin development hosts where the real descriptor source fails
// closed by design).
type fakeSource struct {
	files map[string][]byte
	errs  map[string]error
}

func (f fakeSource) open() error            { return nil }
func (f fakeSource) close()                 {}
func (f fakeSource) checkDuplicates() error { return nil }

func (f fakeSource) read(name string) ([]byte, error) {
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	if data, ok := f.files[name]; ok {
		return data, nil
	}
	return nil, errNotFound
}

func cnFakeFiles() map[string][]byte {
	return map[string][]byte{
		"GATEWAY_EGRESS_PASSWORD_1": []byte(gatewayEgressCanary),
		"TROJAN_USER_1":             []byte(trojanUC),
		"TROJAN_PASSWORD_1":         []byte(trojanPC),
		"HTTPS_USER_1":              []byte(httpsUC),
		"HTTPS_PASSWORD_1":          []byte(httpsPC),
		"HTTPS_USER_2":              []byte(httpsUC2),
		"HTTPS_PASSWORD_2":          []byte(httpsPC2),
		"gateway.crt":               []byte(certGatewayCanary),
		"gateway.key":               []byte(keyGatewayCanary),
	}
}

func usFakeFiles() map[string][]byte {
	return map[string][]byte{
		"GATEWAY_EGRESS_PASSWORD_1": []byte(gatewayEgressCanary),
		"egress.crt":                []byte(certEgressCanary),
		"egress.key":                []byte(keyEgressCanary),
	}
}
