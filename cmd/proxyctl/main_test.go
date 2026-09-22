package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "proxyctl")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run failed: %v", err)
		}
	}
	return code, string(out)
}

func TestCLIPreflightHappyPath(t *testing.T) {
	bin := buildBinary(t)
	role := "egress"
	if runtime.GOARCH == "arm64" {
		role = "gateway"
	}
	code, out := runCLI(t, bin, "preflight", "--role", role, "--offline")
	if code != 0 {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	var res struct {
		Role    string `json:"role"`
		Offline bool   `json:"offline"`
		OK      bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out)
	}
	if res.Role != role || !res.Offline || !res.OK {
		t.Errorf("unexpected result: %+v", res)
	}
}

func repoAbs(t *testing.T, rel ...string) string {
	t.Helper()
	parts := append([]string{"..", ".."}, rel...)
	abs, err := filepath.Abs(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// newCLIOutDir creates the 0700 caller-isolated output directory the
// render publication transaction requires.
func newCLIOutDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return dir
}

// TestCLIRenderWithoutCredentialsFailsClosed is the CLI-level contract
// of the runtime credential wiring: render loads the role's systemd
// credential bundle from the FIXED /run/credentials root, so in a test
// environment (no credentials provisioned) it must fail closed with a
// stable code and publish NOTHING — never fall back to a sentinel, an
// environment variable secret or an empty credential.
func TestCLIRenderWithoutCredentialsFailsClosed(t *testing.T) {
	bin := buildBinary(t)
	out := newCLIOutDir(t)
	code, output := runCLI(t, bin,
		"render", "--role", "gateway",
		"--template-dir", repoAbs(t, "templates", "mihomo"),
		"--config", repoAbs(t, "tests", "fixtures", "render", "gateway-valid.yaml"),
		"--out-dir", out)
	if code == 0 {
		t.Fatalf("render succeeded without provisioned credentials: %s", output)
	}
	// The failure is a stable, machine-readable code, not a crash or a
	// free-form message.
	if !strings.Contains(output, "NOT_FOUND") && !strings.Contains(output, "INTERNAL") &&
		!strings.Contains(output, "PERMISSION") {
		t.Errorf("output missing a stable fail-closed code: %s", output)
	}
	// Nothing may be published: not the config, not an asset, not a
	// staging directory.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("render published %v despite failing closed", names)
	}
}

// TestCLIRenderRejectsCredentialFlags proves the CLI exposes NO way to
// supply a credential root, directory, file name, environment variable
// name or secret value: every such flag is an unknown flag.
func TestCLIRenderRejectsCredentialFlags(t *testing.T) {
	bin := buildBinary(t)
	base := []string{
		"render", "--role", "gateway",
		"--template-dir", repoAbs(t, "templates", "mihomo"),
		"--config", repoAbs(t, "tests", "fixtures", "render", "gateway-valid.yaml"),
	}
	for _, flag := range []string{
		"--credentials-dir=/tmp/creds",
		"--credential-root=/tmp/creds",
		"--credentials-directory=/tmp/creds",
		"--credential-file=/tmp/creds/GATEWAY_EGRESS_PASSWORD_1",
		"--secret=SYNTHETIC-CLI-CANARY-9f",   // secret-scan:allow-line synthetic rejected-flag value, never a real credential
		"--password=SYNTHETIC-CLI-CANARY-9f", // secret-scan:allow-line synthetic rejected-flag value, never a real credential
		"--credential-env=GATEWAY_EGRESS_PASSWORD_1",
		"--secrets-from-stdin",
		"--credential-url=https://example.invalid/secret",
	} {
		out := newCLIOutDir(t)
		args := append(append([]string{}, base...), "--out-dir", out, flag)
		code, output := runCLI(t, bin, args...)
		if code != 4 {
			t.Errorf("%s: code = %d, want 4 (UNKNOWN_FLAG); out = %s", flag, code, output)
		}
		if !strings.Contains(output, "UNKNOWN_FLAG") {
			t.Errorf("%s: output missing UNKNOWN_FLAG: %s", flag, output)
		}
		// The rejection must not echo a supplied secret value.
		if strings.Contains(output, "SYNTHETIC-CLI-CANARY-9f") {
			t.Errorf("%s: CLI echoed a supplied secret value: %s", flag, output)
		}
		if entries, err := os.ReadDir(out); err == nil && len(entries) != 0 {
			t.Errorf("%s: files were published despite flag rejection", flag)
		}
	}
}

func TestCLIRenderRejectsDirectFixture(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin,
		"render", "--role", "gateway",
		"--template-dir", repoAbs(t, "templates", "mihomo"),
		"--config", repoAbs(t, "tests", "fixtures", "render", "gateway-reject-direct.yaml"),
		"--out-dir", t.TempDir())
	if code == 0 {
		t.Fatalf("DIRECT fixture accepted, out = %s", out)
	}
	if !strings.Contains(out, "CONFIG_REJECTED") {
		t.Errorf("error output missing stable code: %s", out)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "deploy")
	if code != 3 {
		t.Errorf("unknown command code = %d, want 3 (out: %s)", code, out)
	}
	if !strings.Contains(out, "UNKNOWN_COMMAND") {
		t.Errorf("output missing UNKNOWN_COMMAND: %s", out)
	}
}

func TestCLIUnknownFlag(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "preflight", "--role", "gateway", "--bogus")
	if code != 4 {
		t.Errorf("unknown flag code = %d, want 4 (out: %s)", code, out)
	}
	if !strings.Contains(out, "UNKNOWN_FLAG") {
		t.Errorf("output missing UNKNOWN_FLAG: %s", out)
	}
}

func TestCLIInvalidEnum(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "preflight", "--role", "eu")
	if code != 5 {
		t.Errorf("invalid enum code = %d, want 5 (out: %s)", code, out)
	}
	if !strings.Contains(out, "INVALID_ENUM") {
		t.Errorf("output missing INVALID_ENUM: %s", out)
	}
	code, _ = runCLI(t, bin, "verify", "--profile", "full")
	if code != 5 {
		t.Errorf("invalid profile code = %d, want 5", code)
	}
}

func TestCLIMissingRole(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "preflight")
	if code != 2 {
		t.Errorf("missing role code = %d, want 2 (out: %s)", code, out)
	}
}

func TestCLIVerifyJSONStable(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "verify", "--profile", "loopback")
	if code != 0 {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res["profile"] != "loopback" || res["ok"] != true {
		t.Errorf("unexpected: %v", res)
	}
}

func TestCLIStatusJSON(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "status", "--json")
	if code != 0 {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep["version"] == nil || rep["restricted"] != true {
		t.Errorf("unexpected: %v", rep)
	}
}

func TestCLIStatusText(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "status")
	if code != 0 {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	if !strings.Contains(out, "proxyctl") {
		t.Errorf("status text missing banner: %s", out)
	}
}

func TestCLIVersion(t *testing.T) {
	bin := buildBinary(t)
	code, out := runCLI(t, bin, "version")
	if code != 0 || !strings.Contains(out, "proxyctl") {
		t.Errorf("code = %d, out = %s", code, out)
	}
}

func TestCLIErrorOutputIsJSON(t *testing.T) {
	bin := buildBinary(t)
	_, out := runCLI(t, bin, "nope")
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		t.Fatalf("error output not JSON: %v\n%s", err, out)
	}
	if e.Error.Code != "UNKNOWN_COMMAND" {
		t.Errorf("code = %s", e.Error.Code)
	}
}
