package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectBasic(t *testing.T) {
	rep, err := Collect(Options{})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if rep.Version == "" || rep.Commit == "" || rep.BuildTime == "" {
		t.Error("version metadata incomplete")
	}
	if !rep.Restricted || len(rep.Restrictions) == 0 {
		t.Error("restricted state missing")
	}
}

func TestLastVerifySummary(t *testing.T) {
	dir := t.TempDir()
	sum := VerifySum{Profile: "canary", OK: true, Duration: "1ms"}
	b, _ := json.Marshal(sum)
	if err := os.WriteFile(filepath.Join(dir, stateFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Collect(Options{StateDir: dir})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if rep.LastVerify == nil || rep.LastVerify.Profile != "canary" {
		t.Errorf("last verify summary missing: %+v", rep.LastVerify)
	}
}

func TestLastVerifySymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, stateFileName)
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Skip("symlink not supported")
	}
	_, err := Collect(Options{StateDir: dir})
	if err == nil {
		t.Fatal("symlinked state file accepted")
	}
}

// TestStateDirSymlinkRejected proves a caller-supplied state dir that is
// a symlink to an external directory holding a VALID summary file is
// refused (not merely absent), and that raw ".." traversal in the state
// dir is rejected too.
func TestStateDirSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(root, "external")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := VerifySum{Profile: "canary", OK: true, Duration: "1ms"}
	b, _ := json.Marshal(sum)
	if err := os.WriteFile(filepath.Join(external, stateFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state-link")
	if err := os.Symlink(external, link); err != nil {
		t.Skip("symlink not supported")
	}
	// Sanity: the symlink resolves to a readable valid summary.
	if _, err := os.Stat(filepath.Join(link, stateFileName)); err != nil {
		t.Fatal(err)
	}
	_, err := Collect(Options{StateDir: link})
	if err == nil {
		t.Fatal("symlinked state dir accepted")
	}
	// Raw traversal in the state dir must be rejected.
	sep := string(filepath.Separator)
	traversal := root + sep + "sub" + sep + ".." + sep + "external"
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(Options{StateDir: traversal}); err == nil {
		t.Fatal("state dir with intermediate '..' accepted")
	}
}

func TestNoSecretsInReport(t *testing.T) {
	rep, _ := Collect(Options{})
	b, _ := json.Marshal(rep)
	s := string(b)
	for _, banned := range []string{"password", "Authorization", "token"} {
		if len(banned) > 4 && contains(s, banned) {
			t.Errorf("status report contains %q", banned)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
