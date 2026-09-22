package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxyctl/internal/safex"
)

// fakeProbe records per-method invocation counts and returns
// configurable typed facts and errors.
type fakeProbe struct {
	envCalls       int
	diskCalls      int
	identityCalls  int
	listenersCalls int

	envErr       error
	avail        uint64
	diskErr      error
	identity     IdentityFacts
	identityErr  error
	listeners    []Listener
	listenersErr error
}

func (p *fakeProbe) Environment() error {
	p.envCalls++
	return p.envErr
}

func (p *fakeProbe) AvailableBytes() (uint64, error) {
	p.diskCalls++
	return p.avail, p.diskErr
}

func (p *fakeProbe) Identity() (IdentityFacts, error) {
	p.identityCalls++
	return p.identity, p.identityErr
}

func (p *fakeProbe) Listeners() ([]Listener, error) {
	p.listenersCalls++
	return p.listeners, p.listenersErr
}

func (p *fakeProbe) totalCalls() int {
	return p.envCalls + p.diskCalls + p.identityCalls + p.listenersCalls
}

// goodIdentity returns the intended non-root identity facts with
// host-assigned numeric IDs (never hardcoded by preflight).
func goodIdentity() IdentityFacts {
	return IdentityFacts{
		Name: expectedServiceAccount, UID: 996, GID: 994,
		DirMode: 0o700, DirUID: 996, DirGID: 994,
	}
}

// goodOnlineProbe returns a fake with all facts satisfying the checks.
func goodOnlineProbe() *fakeProbe {
	return &fakeProbe{avail: minFreeBytes, identity: goodIdentity()}
}

func findCheck(res *Result, name string) *Check {
	for i := range res.Checks {
		if res.Checks[i].Name == name {
			return &res.Checks[i]
		}
	}
	return nil
}

func runOnline(t *testing.T, role string, p Probe) *Result {
	t.Helper()
	res, err := Run(Options{Role: role, Offline: false, Probe: p})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return res
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "render", name))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestPreflightGateway(t *testing.T) {
	res, err := Run(Options{Role: "gateway", Offline: true, arch: "arm64"})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !res.OK {
		for _, c := range res.Checks {
			if c.Status == "fail" {
				t.Errorf("check %s failed: %s", c.Name, c.Detail)
			}
		}
	}
	if res.Offline != true {
		t.Error("offline not recorded")
	}
}

func TestPreflightOfflineNoNetworkMarkers(t *testing.T) {
	res, _ := Run(Options{Role: "egress", Offline: true})
	found := false
	for _, c := range res.Checks {
		if c.Name == "offline-mode" {
			found = true
		}
	}
	if !found {
		t.Error("offline-mode marker missing")
	}
}

// TestPreflightOfflineInvokesNoProbeMethods proves that offline mode
// never touches any method of the injected probe, even when a probe is
// supplied.
func TestPreflightOfflineInvokesNoProbeMethods(t *testing.T) {
	probe := &fakeProbe{envErr: errors.New("boom")}
	res, err := Run(Options{Role: "gateway", Offline: true, Probe: probe, arch: "arm64"})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if probe.totalCalls() != 0 {
		t.Errorf("offline mode invoked probe %d times; want 0 (env=%d disk=%d identity=%d listeners=%d)",
			probe.totalCalls(), probe.envCalls, probe.diskCalls, probe.identityCalls, probe.listenersCalls)
	}
	for _, name := range []string{"environment", "disk", "runtime-identity"} {
		if c := findCheck(res, name); c != nil {
			t.Errorf("offline run must not emit a %s check, got %+v", name, *c)
		}
	}
	if c := findCheck(res, "ports"); c == nil || c.Status != "pass" {
		t.Errorf("offline ports check missing or not pass: %+v", c)
	}
	if !res.OK {
		t.Error("offline run not OK")
	}
}

// TestPreflightOnlineUsesInjectedProbe proves that online mode invokes
// every injected probe method and records passes when facts are good.
func TestPreflightOnlineUsesInjectedProbe(t *testing.T) {
	probe := goodOnlineProbe()
	res := runOnline(t, "egress", probe)
	if probe.envCalls != 1 || probe.diskCalls != 1 || probe.identityCalls != 1 || probe.listenersCalls != 1 {
		t.Fatalf("online mode calls: env=%d disk=%d identity=%d listeners=%d; want 1 each",
			probe.envCalls, probe.diskCalls, probe.identityCalls, probe.listenersCalls)
	}
	for _, name := range []string{"environment", "disk", "runtime-identity", "ports"} {
		c := findCheck(res, name)
		if c == nil {
			t.Errorf("online run missing %s check", name)
			continue
		}
		if c.Status != "pass" {
			t.Errorf("%s check = %q (%s); want pass", name, c.Status, c.Detail)
		}
	}
}

// TestPreflightOnlineProbeFailureIsStable proves a probe failure
// surfaces as a failed check whose Detail does not leak the probe's
// error text.
func TestPreflightOnlineProbeFailureIsStable(t *testing.T) {
	probe := goodOnlineProbe()
	probe.envErr = errors.New("dial 10.0.0.9:443: connection refused by upstream secret-box")
	res := runOnline(t, "egress", probe)
	if probe.envCalls != 1 {
		t.Fatalf("online mode invoked environment probe %d times; want 1", probe.envCalls)
	}
	if res.OK {
		t.Error("result marked OK despite failed probe")
	}
	c := findCheck(res, "environment")
	if c == nil {
		t.Fatal("online run missing environment check")
	}
	if c.Status != "fail" {
		t.Errorf("environment check = %q; want fail", c.Status)
	}
	for _, tok := range []string{"10.0.0.9", "secret-box", "dial", "refused"} {
		if strings.Contains(c.Detail, tok) {
			t.Errorf("probe error text %q leaked into detail: %q", tok, c.Detail)
		}
	}
}

// TestPreflightDiskBoundaries covers the documented minimum free-space
// constant at its exact boundary and just below.
func TestPreflightDiskBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		avail uint64
		want  string
	}{
		{"way above minimum", minFreeBytes * 4, "pass"},
		{"exact minimum passes", minFreeBytes, "pass"},
		{"one byte below minimum fails", minFreeBytes - 1, "fail"},
		{"zero fails", 0, "fail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := goodOnlineProbe()
			probe.avail = tc.avail
			res := runOnline(t, "gateway", probe)
			c := findCheck(res, "disk")
			if c == nil {
				t.Fatal("disk check missing")
			}
			if c.Status != tc.want {
				t.Errorf("avail=%d: disk = %q; want %q", tc.avail, c.Status, tc.want)
			}
		})
	}
}

// TestPreflightDiskProbeErrorNoLeak proves a disk probe error is a
// stable failure without the canary text.
func TestPreflightDiskProbeErrorNoLeak(t *testing.T) {
	probe := goodOnlineProbe()
	probe.diskErr = errors.New("statfs /run/private-proxy on canary-disk-9: i/o error")
	res := runOnline(t, "gateway", probe)
	c := findCheck(res, "disk")
	if c == nil || c.Status != "fail" {
		t.Fatalf("disk check = %+v; want fail", c)
	}
	for _, tok := range []string{"canary-disk-9", "statfs", "i/o error", "/run/private-proxy"} {
		if strings.Contains(c.Detail, tok) {
			t.Errorf("disk error token %q leaked into detail: %q", tok, c.Detail)
		}
	}
}

// TestPreflightRuntimeIdentity covers the intended non-root service
// account (by stable name, host-assigned numeric IDs), restrictive
// runtime directory mode and ownership matching the probed UID/GID.
func TestPreflightRuntimeIdentity(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*IdentityFacts)
		want    string
		leakTok []string
	}{
		{"good identity passes", func(*IdentityFacts) {}, "pass", nil},
		{"different host-assigned numeric ids pass", func(f *IdentityFacts) {
			f.UID, f.GID = 105, 111
			f.DirUID, f.DirGID = 105, 111
		}, "pass", nil},
		{"wrong account name fails", func(f *IdentityFacts) { f.Name = "canary-svc" }, "fail", []string{"canary-svc"}},
		{"root uid fails", func(f *IdentityFacts) { f.UID = 0; f.DirUID = 0 }, "fail", nil},
		{"root gid fails", func(f *IdentityFacts) { f.GID = 0; f.DirGID = 0 }, "fail", nil},
		{"permissive dir mode fails", func(f *IdentityFacts) { f.DirMode = 0o755 }, "fail", []string{"755"}},
		{"missing dir fails", func(f *IdentityFacts) { f.DirMissing = true }, "fail", nil},
		{"dir owned by other uid fails", func(f *IdentityFacts) { f.DirUID = f.UID + 1 }, "fail", nil},
		{"dir owned by other gid fails", func(f *IdentityFacts) { f.DirGID = f.GID + 1 }, "fail", nil},
		{"dir owned by root fails", func(f *IdentityFacts) { f.DirUID, f.DirGID = 0, 0 }, "fail", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := goodOnlineProbe()
			tc.mutate(&probe.identity)
			res := runOnline(t, "egress", probe)
			c := findCheck(res, "runtime-identity")
			if c == nil {
				t.Fatal("runtime-identity check missing")
			}
			if c.Status != tc.want {
				t.Errorf("runtime-identity = %q (%s); want %q", c.Status, c.Detail, tc.want)
			}
			for _, tok := range tc.leakTok {
				if strings.Contains(c.Detail, tok) {
					t.Errorf("untrusted fact %q leaked into detail: %q", tok, c.Detail)
				}
			}
		})
	}
}

// TestPreflightIdentityProbeErrorNoLeak proves an identity probe error
// is a stable failure without the canary text.
func TestPreflightIdentityProbeErrorNoLeak(t *testing.T) {
	probe := goodOnlineProbe()
	probe.identityErr = errors.New("lookup account on canary-idmap-7: no such user")
	res := runOnline(t, "gateway", probe)
	c := findCheck(res, "runtime-identity")
	if c == nil || c.Status != "fail" {
		t.Fatalf("runtime-identity check = %+v; want fail", c)
	}
	for _, tok := range []string{"canary-idmap-7", "lookup", "no such user"} {
		if strings.Contains(c.Detail, tok) {
			t.Errorf("identity error token %q leaked into detail: %q", tok, c.Detail)
		}
	}
}

func TestPreflightInvalidRoleRejected(t *testing.T) {
	_, err := Run(Options{Role: "eu", Offline: true})
	if err == nil {
		t.Fatal("invalid role accepted by preflight")
	}
	se, ok := err.(*safex.Error)
	if !ok || se.Code != safex.CodeInvalidEnum {
		t.Fatalf("want INVALID_ENUM, got %v", err)
	}
	_, err = Run(Options{Role: "", Offline: true})
	if err == nil {
		t.Fatal("empty role accepted by preflight")
	}
}

// TestPreflightIntermediateTraversalRejected proves an intermediate
// ".." in the RAW config path is flagged even though filepath.Clean
// would collapse it to an existing, readable file. All directories on
// both sides of the ".." really exist, so the failure is the traversal
// check, not ENOENT.
func TestPreflightIntermediateTraversalRejected(t *testing.T) {
	root := t.TempDir()
	cfg, err := os.ReadFile(fixture(t, "gateway-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gateway-valid.yaml"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sanity: the target file exists at the collapsed location.
	if _, err := os.Stat(filepath.Join(root, "gateway-valid.yaml")); err != nil {
		t.Fatal(err)
	}
	// Raw string with an intermediate ".." that Clean collapses to
	// root/gateway-valid.yaml (an existing file).
	sep := string(filepath.Separator)
	raw := root + sep + "sub" + sep + ".." + sep + "gateway-valid.yaml"
	// "sub" must exist so the traversal is real, not a missing dir.
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Run(Options{Role: "gateway", Offline: true, ConfigPath: raw})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	failed := false
	for _, c := range res.Checks {
		if c.Name == "credentials" && c.Status == "fail" &&
			strings.Contains(c.Detail, "traversal") {
			failed = true
		}
	}
	if !failed {
		t.Errorf("intermediate '..' in config path not flagged; checks: %+v", res.Checks)
	}
}

// TestPreflightLegalDottyFilenameNotTraversal: a file literally named
// with ".." inside its name (a..b.yaml) must not be flagged.
func TestPreflightLegalDottyFilenameNotTraversal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a..b.yaml")
	if err := os.WriteFile(p, []byte("schema: private-proxy/v1\nrole: gateway\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Role: "gateway", Offline: true, ConfigPath: p})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	for _, c := range res.Checks {
		if c.Name == "credentials" && c.Status == "fail" && strings.Contains(c.Detail, "traversal") {
			t.Errorf("legal 'a..b.yaml' filename falsely flagged as traversal")
		}
	}
}

// TestPreflightConfigSymlinkEscapeRejected proves a config path whose
// final component is a symlink to an external VALID config file is
// flagged, not passed via ENOENT.
func TestPreflightConfigSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(root, "external")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(fixture(t, "gateway-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	extFile := filepath.Join(external, "gateway-valid.yaml")
	if err := os.WriteFile(extFile, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "links")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "gateway-config.yaml")
	if err := os.Symlink(extFile, link); err != nil {
		t.Skip("symlink not supported")
	}
	// Sanity: the symlink resolves to a readable valid config.
	if _, err := os.Stat(link); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Role: "gateway", Offline: true, ConfigPath: link})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	flagged := false
	for _, c := range res.Checks {
		if c.Name == "credentials" && c.Status == "fail" &&
			strings.Contains(c.Detail, "symlink") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("config symlink escape not flagged; checks: %+v", res.Checks)
	}
}

func TestPreflightConfigRejectsRealSecret(t *testing.T) {
	res, err := Run(Options{
		Role: "gateway", Offline: true,
		ConfigPath: fixture(t, "gateway-reject-real-secret.yaml"),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	failed := false
	for _, c := range res.Checks {
		if c.Name == "credentials" && c.Status == "fail" {
			failed = true
		}
	}
	if !failed {
		t.Error("real secret in config not flagged by preflight")
	}
	if res.OK {
		t.Error("result marked OK despite failed check")
	}
}
