package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxyctl/internal/safex"
)

const repoRoot = "../../"

func tmplDir(t *testing.T, sub string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(repoRoot, "templates", sub))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(repoRoot, "tests", "fixtures", "render", name))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// newRealOutDir creates the 0700 caller-isolated output directory the
// production writer requires.
func newRealOutDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return dir
}

// cnOpts / usOpts build a production-path render request (real writer)
// with an injected synthetic bundle.
func cnOpts(t *testing.T, out string, b Bundle) Options {
	t.Helper()
	return Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out,
		Loader: &synthLoader{bundle: b},
	}
}

func usOpts(t *testing.T, out string, b Bundle) Options {
	t.Helper()
	return Options{
		Role: "egress", TemplateDir: tmplDir(t, "hysteria"),
		ConfigPath: fixturePath(t, "egress-valid.yaml"), OutDir: out,
		Loader: &synthLoader{bundle: b},
	}
}

func TestRenderGatewayPositive(t *testing.T) {
	skipUnlessSupported(t)
	out := newRealOutDir(t)
	res, err := Run(cnOpts(t, out, synthGateway()))
	if err != nil {
		t.Fatalf("render gateway failed: %v", err)
	}
	// The rendered config AND both gateway assets are published together.
	if !res.OK || len(res.Files) != 3 {
		t.Fatalf("unexpected result: %+v", res)
	}
	for _, name := range []string{"gateway-rendered.yaml", "gateway.crt", "gateway.key"} {
		p := filepath.Join(out, name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("output %s missing: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o, want 600", name, fi.Mode().Perm())
		}
	}
	data, _ := os.ReadFile(filepath.Join(out, "gateway-rendered.yaml"))
	s := string(data)
	if s == "" {
		t.Error("rendered output empty")
	}
	for _, banned := range []string{"DIRECT", "skip-cert-verify", "insecure: true"} {
		if contains(s, banned) {
			t.Errorf("rendered output contains %q", banned)
		}
	}
	// The real secrets ARE in the rendered config (that is the point),
	// quoted; the ASSET bytes must never be inlined into the config.
	if !contains(s, synthGatewayEgressPassword) {
		t.Error("rendered config does not contain the substituted credential")
	}
	for _, assetBody := range []string{synthGatewayCrt, synthGatewayKey} {
		if contains(s, assetBody) {
			t.Errorf("asset bytes were inlined into the rendered config")
		}
	}
	// Assets land verbatim under their fixed destination names.
	crt, _ := os.ReadFile(filepath.Join(out, "gateway.crt"))
	if string(crt) != synthGatewayCrt {
		t.Errorf("gateway.crt content = %d bytes, want the materialized asset", len(crt))
	}
	key, _ := os.ReadFile(filepath.Join(out, "gateway.key"))
	if string(key) != synthGatewayKey {
		t.Errorf("gateway.key content = %d bytes, want the materialized asset", len(key))
	}
}

func TestRenderEgressPositive(t *testing.T) {
	skipUnlessSupported(t)
	out := newRealOutDir(t)
	res, err := Run(usOpts(t, out, synthEgress()))
	if err != nil {
		t.Fatalf("render egress failed: %v", err)
	}
	if !res.OK || len(res.Files) != 3 {
		t.Fatalf("unexpected result: %+v", res)
	}
	for _, name := range []string{"egress-rendered.yaml", "egress.crt", "egress.key"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("output %s missing: %v", name, err)
		}
	}
}

func TestRenderRefusesOverwrite(t *testing.T) {
	skipUnlessSupported(t)
	out := newRealOutDir(t)
	if _, err := Run(cnOpts(t, out, synthGateway())); err != nil {
		t.Fatalf("first render failed: %v", err)
	}
	// A fresh bundle: Close made the first one fail closed, which is
	// the production lifecycle too.
	_, err := Run(cnOpts(t, out, synthGateway()))
	if err == nil {
		t.Fatal("second render overwrote existing output")
	}
	se, ok := err.(*safex.Error)
	if !ok || se.Code != safex.RenderUnsafe {
		t.Fatalf("want RENDER_UNSAFE, got %v", err)
	}
}

func TestRenderRefusesSymlinkOutput(t *testing.T) {
	skipUnlessSupported(t)
	target := newRealOutDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink not supported")
	}
	_, err := Run(cnOpts(t, link, synthGateway()))
	if err == nil {
		t.Fatal("render accepted symlinked output dir")
	}
	// Nothing may be written through the symlink into the real target.
	entries, rerr := os.ReadDir(target)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("render wrote through the symlinked dir: %v", entries)
	}
}

func TestRenderRefusesSymlinkFile(t *testing.T) {
	skipUnlessSupported(t)
	out := newRealOutDir(t)
	// Pre-create a symlink where the output file would land.
	linkPath := filepath.Join(out, "gateway-rendered.yaml")
	if err := os.Symlink("/etc/passwd", linkPath); err != nil {
		t.Skip("symlink not supported")
	}
	_, err := Run(cnOpts(t, out, synthGateway()))
	if err == nil {
		t.Fatal("render wrote through a symlink")
	}
	if se, ok := err.(*safex.Error); !ok || se.Code != safex.RenderUnsafe {
		t.Fatalf("want RENDER_UNSAFE, got %v", err)
	}
	// The symlink must be intact (not clobbered).
	fi, err := os.Lstat(linkPath)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was clobbered by render")
	}
	// No asset may have been published either: the refusal happens
	// before any file is created.
	for _, name := range []string{"gateway.crt", "gateway.key"} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Errorf("%s was published despite the symlink refusal", name)
		}
	}
}

func TestRenderPathTraversalRejected(t *testing.T) {
	out := t.TempDir()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: "../../templates/mihomo/../../..",
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out,
	})
	if err == nil {
		t.Fatal("traversal template dir accepted")
	}
	_, err2 := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		// Build the raw path without filepath.Join, which would clean the
		// traversal components before Run can validate them.
		ConfigPath: fixturePath(t, "gateway-valid.yaml"),
		OutDir:     out + string(filepath.Separator) + ".." + string(filepath.Separator) + "..",
	})
	if err2 == nil {
		t.Fatal("traversal out dir accepted")
	}
}

// TestRenderConfigSymlinkEscapeRejected proves a caller-supplied config
// path whose final component is a symlink to an external VALID config
// file is refused by the read root, not by ENOENT.
func TestRenderConfigSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	// A real, valid gateway config outside the "intended" directory.
	external := filepath.Join(root, "external")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(fixturePath(t, "gateway-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	extFile := filepath.Join(external, "gateway-valid.yaml")
	if err := os.WriteFile(extFile, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	// The "caller-supplied" dir contains only a symlink to it.
	linkDir := filepath.Join(root, "links")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "gateway-config.yaml")
	if err := os.Symlink(extFile, link); err != nil {
		t.Skip("symlink not supported")
	}
	// Sanity: the symlink target is a readable valid config.
	if _, err := os.Stat(link); err != nil {
		t.Fatal(err)
	}
	_, err = Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: link, OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("config symlink escape accepted")
	}
	se, ok := err.(*safex.Error)
	if !ok || se.Code != safex.CodeConfigRejected {
		t.Fatalf("want CONFIG_REJECTED, got %v", err)
	}
}

// TestRenderTemplateDirSymlinkRejected proves a caller-supplied
// template dir that is itself a symlink to an external directory
// containing a byte-identical template is still refused.
func TestRenderTemplateDirSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(root, "external")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(tmplDir(t, "mihomo"), "mihomo-gateway.yaml.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(external, "mihomo-gateway.yaml.tmpl"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "tmpl-link")
	if err := os.Symlink(external, link); err != nil {
		t.Skip("symlink not supported")
	}
	// Sanity: the linked dir contains a valid template.
	if _, err := os.Stat(filepath.Join(link, "mihomo-gateway.yaml.tmpl")); err != nil {
		t.Fatal(err)
	}
	_, err = Run(Options{
		Role: "gateway", TemplateDir: link,
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("symlinked template dir accepted")
	}
	se, ok := err.(*safex.Error)
	if !ok || se.Code != safex.RenderUnsafe {
		t.Fatalf("want RENDER_UNSAFE, got %v", err)
	}
}

// TestRenderTemplateIdentity verifies the template name+SHA-256 double
// allowlist: the repository templates pass, and a same-named file with
// arbitrary or tampered content is rejected without any output file
// being created.
func TestRenderTemplateIdentity(t *testing.T) {
	skipUnlessSupported(t)
	out := newRealOutDir(t)
	// Official gateway template passes the identity check end to end.
	if _, err := Run(cnOpts(t, out, synthGateway())); err != nil {
		t.Fatalf("official gateway template rejected: %v", err)
	}
	// Official egress template passes too.
	if _, err := Run(usOpts(t, newRealOutDir(t), synthEgress())); err != nil {
		t.Fatalf("official egress template rejected: %v", err)
	}

	// Attacker dir: same file name, arbitrary benign-looking content.
	evil := t.TempDir()
	evilTmpl := "schema: private-proxy/v1\nrole: gateway\nvalue: whatever\n"
	if err := os.WriteFile(filepath.Join(evil, "mihomo-gateway.yaml.tmpl"), []byte(evilTmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	out3 := t.TempDir()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: evil,
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out3,
	})
	if err == nil {
		t.Fatal("arbitrary same-named template accepted")
	}
	se, ok := err.(*safex.Error)
	if !ok || se.Code != safex.CodeTemplateRejected {
		t.Fatalf("want TEMPLATE_REJECTED, got %v", err)
	}
	if strings.Contains(se.Message, evilTmpl) {
		t.Errorf("error leaks template content: %s", se.Message)
	}
	// No output file may be created on rejection.
	if _, err := os.Stat(filepath.Join(out3, "gateway-rendered.yaml")); !os.IsNotExist(err) {
		t.Error("output file created despite template rejection")
	}

	// Tampered official template: one byte changed.
	official, err := os.ReadFile(filepath.Join(tmplDir(t, "mihomo"), "mihomo-gateway.yaml.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	tamperedDir := t.TempDir()
	tampered := strings.Replace(string(official), "role: gateway", "role: gateway ", 1)
	if err := os.WriteFile(filepath.Join(tamperedDir, "mihomo-gateway.yaml.tmpl"), []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	out4 := t.TempDir()
	if _, err := Run(Options{
		Role: "gateway", TemplateDir: tamperedDir,
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out4,
	}); err == nil {
		t.Fatal("tampered template accepted")
	}
	if _, err := os.Stat(filepath.Join(out4, "gateway-rendered.yaml")); !os.IsNotExist(err) {
		t.Error("output file created despite tampered template rejection")
	}
}

// TestRenderIntermediateTraversalRejected proves that an intermediate
// ".." component in a RAW path string is rejected even though
// filepath.Clean/Join would collapse it into an existing, readable
// target. The directories on both sides of the ".." really exist, so
// the rejection can only come from the traversal check, not ENOENT.
func TestRenderIntermediateTraversalRejected(t *testing.T) {
	root := t.TempDir()
	// Real template dir and config, all components on disk.
	tmpl := filepath.Join(root, "templates")
	if err := os.MkdirAll(tmpl, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(tmplDir(t, "mihomo"), "mihomo-gateway.yaml.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpl, "mihomo-gateway.yaml.tmpl"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(fixturePath(t, "gateway-valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(root, "configs")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "gateway-valid.yaml"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()

	// Raw strings with an intermediate ".." that Clean would collapse:
	// root/templates/../templates  -> root/templates (exists, readable)
	// root/configs/../configs      -> root/configs   (exists, readable)
	// Both must still be rejected as traversal.
	sep := string(filepath.Separator)
	rawTmpl := root + sep + "templates" + sep + ".." + sep + "templates"
	rawCfg := root + sep + "configs" + sep + ".." + sep + "configs"

	// Sanity: the collapsed forms exist (proves no ENOENT shortcut).
	if _, err := os.Stat(filepath.Join(root, "templates", "mihomo-gateway.yaml.tmpl")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "configs", "gateway-valid.yaml")); err != nil {
		t.Fatal(err)
	}

	if _, err := Run(Options{Role: "gateway", TemplateDir: rawTmpl, ConfigPath: rawCfg, OutDir: out}); err == nil {
		t.Fatal("intermediate '..' in template dir accepted despite Clean collapsing it to a real path")
	} else {
		se, ok := err.(*safex.Error)
		if !ok || se.Code != safex.RenderUnsafe {
			t.Fatalf("want RENDER_UNSAFE, got %v", err)
		}
	}
	if _, err := Run(Options{Role: "gateway", TemplateDir: tmpl, ConfigPath: rawCfg, OutDir: out}); err == nil {
		t.Fatal("intermediate '..' in config path accepted")
	}
	// The same traversal via the output dir must be rejected too, even
	// though it collapses to an existing directory.
	rawOut := out + sep + ".." + sep + filepath.Base(out)
	if _, err := Run(Options{Role: "gateway", TemplateDir: tmpl, ConfigPath: filepath.Join(cfgDir, "gateway-valid.yaml"), OutDir: rawOut}); err == nil {
		t.Fatal("intermediate '..' in out dir accepted")
	}

	// "a..b" is a legal filename: a directory literally named "a..b"
	// must NOT be rejected (component-exact check, not substring).
	dotty := filepath.Join(root, "a..b")
	if err := os.MkdirAll(filepath.Join(dotty, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{
		Role: "gateway", TemplateDir: dotty,
		ConfigPath: filepath.Join(cfgDir, "gateway-valid.yaml"), OutDir: t.TempDir(),
	})
	if err == nil && res != nil {
		// Expected: template file missing inside a..b, NOT traversal.
		t.Fatalf("unexpected success: %+v", res)
	}
	if err != nil {
		se, ok := err.(*safex.Error)
		if !ok {
			t.Fatalf("unexpected error type: %T", err)
		}
		if se.Code == safex.RenderUnsafe && strings.Contains(se.Message, "traversal") {
			t.Fatalf("legal 'a..b' directory name falsely rejected as traversal: %v", se.Message)
		}
	}
}

func TestRenderUnknownTemplateVarRejected(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "mihomo-gateway.yaml.tmpl")
	bad := "schema: private-proxy/v1\nvalue: ${NOT_IN_SCHEMA}\n"
	if err := os.WriteFile(tmpl, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: dir,
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out,
	})
	if err == nil {
		t.Fatal("unknown template variable accepted")
	}
}

func TestRenderWrongTemplateForRoleRejected(t *testing.T) {
	out := t.TempDir()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "hysteria"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: out,
	})
	if err == nil {
		t.Fatal("gateway role accepted egress template dir")
	}
}

func TestRenderNegativeFixtures(t *testing.T) {
	cases := []struct{ fixture, role, tmpl string }{
		{"gateway-reject-direct.yaml", "gateway", "mihomo"},
		{"gateway-reject-skip-cert.yaml", "gateway", "mihomo"},
		{"gateway-reject-public-7890.yaml", "gateway", "mihomo"},
		{"gateway-reject-controller-wildcard.yaml", "gateway", "mihomo"},
		{"gateway-reject-unknown-field.yaml", "gateway", "mihomo"},
		{"gateway-reject-real-secret.yaml", "gateway", "mihomo"},
		{"gateway-reject-role-mismatch.yaml", "gateway", "mihomo"},
		{"egress-reject-insecure.yaml", "egress", "hysteria"},
		{"egress-reject-empty-credential.yaml", "egress", "hysteria"},
	}
	for _, c := range cases {
		_, err := Run(Options{
			Role: c.role, TemplateDir: tmplDir(t, c.tmpl),
			ConfigPath: fixturePath(t, c.fixture), OutDir: t.TempDir(),
		})
		if err == nil {
			t.Errorf("%s: render accepted a rejected fixture", c.fixture)
		}
	}
}

func TestRenderMissingOutDirRejected(t *testing.T) {
	_, err := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: "",
	})
	if err == nil {
		t.Fatal("empty out dir accepted")
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
