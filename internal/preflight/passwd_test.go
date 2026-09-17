package preflight

import (
	"strings"
	"testing"
)

// Compile-time guards: the platform probes and the stub must all
// satisfy the Probe boundary.
var (
	_ Probe = stubProbe{}
	_ Probe = defaultProbe()
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
privateproxy:x:996:994:private proxy service:/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
`

func TestParsePasswdUIDGIDExactAccount(t *testing.T) {
	uid, gid, err := parsePasswdUIDGID(passwdFixture, "privateproxy")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if uid != 996 || gid != 994 {
		t.Errorf("uid,gid = %d,%d; want 996,994", uid, gid)
	}
}

// TestParsePasswdUIDGIDExactNameOnly proves prefix/substring/suffixed
// names never match the fixed account.
func TestParsePasswdUIDGIDExactNameOnly(t *testing.T) {
	data := "privateproxy2:x:5000:5000::/n:/n\n" +
		"notprivateproxy:x:5001:5001::/n:/n\n" +
		passwdFixture
	for _, name := range []string{"privateproxy2", "notprivateproxy", "private", "proxy"} {
		if _, _, err := parsePasswdUIDGID(data, name); err == nil {
			// names that exist in the fixture legitimately resolve; only
			// non-fixture names are asserted here
			if name != "privateproxy2" && name != "notprivateproxy" {
				t.Errorf("name %q unexpectedly resolved", name)
			}
		}
	}
	uid, gid, err := parsePasswdUIDGID(data, "privateproxy")
	if err != nil || uid != 996 || gid != 994 {
		t.Errorf("exact lookup = %d,%d,%v; want 996,994,nil", uid, gid, err)
	}
}

// TestParsePasswdUIDGIDFailures covers malformed matching lines,
// duplicates, missing accounts and out-of-bounds content. No error
// detail may leak canary text from the data.
func TestParsePasswdUIDGIDFailures(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"account missing", passwdFixture},
		{"uid not numeric", "privateproxy:x:canary-uid:994::/n:/n\n"},
		{"gid not numeric", "privateproxy:x:996:canary-gid::/n:/n\n"},
		{"uid negative", "privateproxy:x:-1:994::/n:/n\n"},
		{"gid negative", "privateproxy:x:996:-1::/n:/n\n"},
		{"duplicate account", passwdFixture + "privateproxy:x:5002:5003::/n:/n\n"},
		{"overlong line", "privateproxy:x:996:994:" + strings.Repeat("c", 4096) + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "privateproxy"
			if tc.name == "account missing" {
				name = "canary-absent"
			}
			_, _, err := parsePasswdUIDGID(tc.data, name)
			if err == nil {
				t.Fatal("malformed data resolved successfully")
			}
			for _, tok := range []string{"canary"} {
				if strings.Contains(err.Error(), tok) {
					t.Errorf("canary leaked into error: %q", err.Error())
				}
			}
		})
	}
}

// TestParsePasswdUIDGIDBounds proves an oversized database is rejected.
func TestParsePasswdUIDGIDBounds(t *testing.T) {
	data := strings.Repeat("nobody:x:65534:65534::/n:/n\n", maxPasswdLines+1)
	if _, _, err := parsePasswdUIDGID(data, "privateproxy"); err == nil {
		t.Fatal("oversized account database accepted")
	}
}

// TestPasswdSizeBoundary documents the pure size boundary enforced by
// readPasswd (Lstat size check before ReadFile): exactly maxPasswdSize
// is admissible, one byte over is not. The Lstat/read side is
// Linux-only; this test pins the constant contract on any host.
func TestPasswdSizeBoundary(t *testing.T) {
	if maxPasswdSize != 1<<20 {
		t.Errorf("maxPasswdSize = %d; want 1 MiB", maxPasswdSize)
	}
	// Within-size content parses normally.
	ok := strings.Repeat("nobody:x:65534:65534::/n:/n\n", 10) +
		"privateproxy:x:996:994::/n:/n\n"
	if len(ok) > maxPasswdSize {
		t.Fatal("test content exceeds the size bound")
	}
	if _, _, err := parsePasswdUIDGID(ok, "privateproxy"); err != nil {
		t.Fatalf("within-size database rejected: %v", err)
	}
}
