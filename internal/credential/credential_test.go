package credential

import (
	"strings"
	"testing"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// Loader/validation/optional tests via the fake source, plus pure
// helper tests. Filesystem-backed tests live in
// credential_linux_test.go; the non-Linux fail-closed contract lives
// in platform_other_test.go.

// --- scalar content validation ----------------------------------------

func TestMultilineScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte("first\nsecond")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestCRLFScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte("value\r\n")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestNULScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte("ab\x00cd")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestInvalidUTF8ScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte("ab\xffcd")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestControlCharScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte("ab\x1b[0m")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestEmptyRequiredCredential(t *testing.T) {
	f := cnFakeFiles()
	f["HTTPS_PASSWORD_1"] = []byte("")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestNewlineOnlyRequiredCredential(t *testing.T) {
	f := cnFakeFiles()
	f["HTTPS_PASSWORD_1"] = []byte("\n")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestOversizeScalarRejected(t *testing.T) {
	f := cnFakeFiles()
	f["TROJAN_USER_1"] = []byte(strings.Repeat("x", maxScalarBytes+1))
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestOversizeAssetRejected(t *testing.T) {
	f := cnFakeFiles()
	f["gateway.crt"] = []byte(strings.Repeat("x", maxAssetBytes+1))
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestMissingRequiredCredential(t *testing.T) {
	f := cnFakeFiles()
	delete(f, "TROJAN_PASSWORD_1")
	_, err := load("gateway", fakeSource{files: f})
	assertCode(t, err, safex.CodeNotFound)
	assertNoLeak(t, err)
}

// --- optional credentials (fake source; stable not-found only) ---------

func TestOptionalAbsentIgnoredFake(t *testing.T) {
	b, err := load("egress", fakeSource{files: usFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(b.OptionalLoaded()); n != 0 {
		t.Errorf("optional = %d, want 0", n)
	}
}

func TestOptionalPresentLoadedFake(t *testing.T) {
	f := cnFakeFiles()
	f["gateway-client.crt"] = []byte(optGatewayClientCr)
	b, err := load("gateway", fakeSource{files: f})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	opt := b.OptionalLoaded()
	if len(opt) != 1 || opt[0] != "gateway-client.crt" {
		t.Errorf("optional = %v", opt)
	}
	found := false
	for _, a := range b.Materialize() {
		if a.Dest == "gateway-client.crt" && string(a.Data) == optGatewayClientCr {
			found = true
		}
	}
	if !found {
		t.Errorf("optional asset not materialized")
	}
}

func TestOptionalEmptyFailsFake(t *testing.T) {
	f := usFakeFiles()
	f["gateway-client-ca.crt"] = []byte("")
	_, err := load("egress", fakeSource{files: f})
	assertCode(t, err, safex.CodeConfigRejected)
}

func TestOptionalPermissionErrorFailsFake(t *testing.T) {
	src := fakeSource{
		files: usFakeFiles(),
		errs: map[string]error{
			"gateway-client-ca.crt": safex.New(safex.CodePermission, "credential access denied"),
		},
	}
	_, err := load("egress", src)
	assertCode(t, err, safex.CodePermission)
}

func TestOptionalSymlinkErrorFailsFake(t *testing.T) {
	src := fakeSource{
		files: usFakeFiles(),
		errs: map[string]error{
			"gateway-client-ca.crt": safex.New(safex.RenderUnsafe, "credential must not be a symlink"),
		},
	}
	_, err := load("egress", src)
	assertCode(t, err, safex.RenderUnsafe)
}

func TestOptionalIOErrorFailsFake(t *testing.T) {
	src := fakeSource{
		files: usFakeFiles(),
		errs: map[string]error{
			"gateway-client-ca.crt": safex.New(safex.CodeIO, "credential cannot be read"),
		},
	}
	_, err := load("egress", src)
	assertCode(t, err, safex.CodeIO)
}

func TestRequiredPermissionErrorFailsFake(t *testing.T) {
	src := fakeSource{
		files: usFakeFiles(),
		errs: map[string]error{
			"GATEWAY_EGRESS_PASSWORD_1": safex.New(safex.CodePermission, "credential access denied"),
		},
	}
	_, err := load("egress", src)
	assertCode(t, err, safex.CodePermission)
}

// --- role handling ----------------------------------------------------

func TestLoadUnknownRoleFailsClosed(t *testing.T) {
	// Defense in depth: load() itself must reject an unrecognized role
	// fail-closed, never silently degrade to an empty allowlist.
	for _, role := range []config.Role{"", "bogus", "GATEWAY", "all"} {
		_, err := load(role, fakeSource{files: cnFakeFiles()})
		if err == nil {
			t.Errorf("load(%q) = nil error, want INVALID_ENUM", role)
		} else {
			assertCode(t, err, safex.CodeInvalidEnum)
			assertNoLeak(t, err)
		}
	}
}

// --- production API surface ---------------------------------------------

func TestLoadSystemdInvalidRoleFailsClosed(t *testing.T) {
	// Must fail on role parsing before ever touching the environment.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	for _, role := range []string{"", "bogus", "GATEWAY"} {
		if _, err := LoadSystemd(role); err == nil {
			t.Errorf("LoadSystemd(%q) = nil error, want failure", role)
		} else {
			assertCode(t, err, safex.CodeInvalidEnum)
		}
	}
}

// --- pure helpers ------------------------------------------------------

func TestHasTraversal(t *testing.T) {
	bad := []string{"a/../b", "../x", "/a/../../b", "a/b/.."}
	for _, p := range bad {
		if !hasTraversal(p) {
			t.Errorf("hasTraversal(%q) = false", p)
		}
	}
	good := []string{"/run/credentials/unit", "a..b/c", "/a/b"}
	for _, p := range good {
		if hasTraversal(p) {
			t.Errorf("hasTraversal(%q) = true", p)
		}
	}
}

func TestASCIILower(t *testing.T) {
	if got := asciiLower("AbC_XyZ"); got != "abc_xyz" {
		t.Errorf("asciiLower = %q", got)
	}
	// Non-ASCII bytes pass through unchanged (no Unicode folding).
	if got := asciiLower("A\xc3\x84Z"); got != "a\xc3\x84z" {
		t.Errorf("asciiLower folded non-ASCII: %q", got)
	}
}

func TestCheckNameCollisions(t *testing.T) {
	if err := checkNameCollisions([]string{"a", "b", "C"}); err != nil {
		t.Errorf("clean names rejected: %v", err)
	}
	if err := checkNameCollisions([]string{"GATEWAY_EGRESS_PASSWORD_1", "gateway_egress_password_1"}); err == nil {
		t.Errorf("ASCII case collision accepted")
	} else {
		assertCode(t, err, safex.RenderUnsafe)
	}
}
