// Package render validates templates and renders role configuration
// files, together with the role's allowlisted certificate/key assets,
// into an explicit output directory.
//
// Ordering is validation-before-write, without exception: the config
// document, the template identity (name + pinned SHA-256), the
// placeholder schema and the whole credential bundle are validated and
// fully substituted in memory FIRST; only then does one publication
// transaction touch the filesystem. A rejection therefore never leaves
// a partial artifact.
//
// Output files are created with 0600 permissions inside a 0700
// caller-isolated directory, are published per file atomically without
// ever replacing an existing entry, never follow a symlink at any path
// depth, and reject path traversal. See writer.go for the exact
// publication guarantees, including the documented partial-bundle
// ("bundle state undefined") behavior.
//
// Credentials are never caller-supplied: they are loaded through the
// Loader seam, whose production implementation is
// credential.LoadSystemd with its fixed /run/credentials root and
// fixed per-role name allowlist. No credential root, file name,
// environment variable, stdin stream, URL or arbitrary path is
// accepted from the CLI, and no secret value, source path or
// credential content ever appears in a Result or an error.
package render

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// Options controls a render run.
type Options struct {
	Role        string
	TemplateDir string
	ConfigPath  string
	// OutDir is the caller-isolated output directory. It must be an
	// explicitly passed, non-empty path, must already exist and must
	// have mode 0700 (the publication transaction enforces this on the
	// descriptor it holds, never on a re-resolved path).
	OutDir string

	// Loader is the credential-bundle boundary. A nil Loader selects
	// the production SystemdLoader, i.e. credential.LoadSystemd with
	// its fixed /run/credentials root and fixed per-role name
	// allowlist. Options carries NO credential root, directory, file
	// name, environment variable name or secret value, and the CLI
	// exposes no flag that could supply one.
	Loader Loader

	// writer optionally overrides the publication backend. It is
	// UNEXPORTED on purpose: only tests inside this package can set
	// it, so the CLI and every other package always get the production
	// descriptor-relative backend and can never weaken the writer.
	writer *backend
}

// Result is the stable JSON shape of a render run. Files lists the
// fixed published output names (rendered config plus the role's
// allowlisted certificate/key assets) in publication order. Every name
// is hardcoded; no secret value, source path or credential content is
// ever included.
type Result struct {
	Role        string   `json:"role"`
	OK          bool     `json:"ok"`
	Files       []string `json:"files"`
	TemplateDir string   `json:"template_dir"`
}

// roleAssetNames is the fixed per-role allowlist of asset destination
// names render may publish. It mirrors the credential package's
// required+optional asset allowlists and is enforced independently:
// even a bundle that somehow offered another role's material (or an
// unexpected name) cannot get it written, and a gateway render can never
// publish egress.crt/egress.key.
var roleAssetNames = map[string]map[string]struct{}{
	"gateway": {
		"gateway.crt":        {},
		"gateway.key":        {},
		"gateway-client.crt": {},
		"gateway-client.key": {},
	},
	"egress": {
		"egress.crt":            {},
		"egress.key":            {},
		"gateway-client-ca.crt": {},
	},
}

// renderedName is the fixed output file name of the rendered config for
// a role. It is derived from the validated role only, never from
// caller text.
func renderedName(role config.Role) string { return string(role) + "-rendered.yaml" }

// allowedTemplates maps role -> the exact allowed template file name
// and the SHA-256 digest of the repository-controlled template bytes.
// This is a double allowlist (name + content identity): a file with
// the right name but arbitrary or tampered content is rejected. When a
// template is changed on purpose, its digest here must be updated in
// the same reviewed change.
var allowedTemplates = map[string]struct{ name, sha256 string }{
	"gateway": {"mihomo-gateway.yaml.tmpl",
		"b0797657c50ed13d21200174bf270ef1ed050edb61ebde6a7f9be7cd17b01880"},
	"egress": {"hysteria-egress.yaml.tmpl",
		"7164721b0c1e3204b70937c6bf1e994f7c2d0587a05c1db6cb08376bb90b2e5e"},
}

// Run performs validation and rendering.
func Run(opts Options) (*Result, error) {
	role, err := config.ParseRole(opts.Role)
	if err != nil {
		return nil, err
	}
	if opts.TemplateDir == "" {
		return nil, safex.New(safex.CodeUsage, "template dir is required")
	}
	if opts.ConfigPath == "" {
		return nil, safex.New(safex.CodeUsage, "config path is required")
	}
	if err := checkNoTraversal(opts.ConfigPath); err != nil {
		return nil, err
	}
	if opts.OutDir == "" {
		return nil, safex.New(safex.CodeUsage, "output dir is required (explicit caller-isolated path)")
	}
	// Raw option strings are checked for traversal components before
	// any cleaning/joining, so ".." in user input can never vanish into
	// a cleaned path.
	for _, raw := range []string{opts.TemplateDir, opts.ConfigPath, opts.OutDir} {
		if err := checkNoTraversal(raw); err != nil {
			return nil, err
		}
	}

	// 1. Load and validate the config document against the allowlist.
	doc, err := config.ParseFile(opts.ConfigPath, role)
	if err != nil {
		return nil, err
	}

	// 2. Template must be exactly the allowlisted file (name + content
	// digest) for the role.
	allowed, ok := allowedTemplates[string(role)]
	if !ok {
		return nil, safex.New(safex.CodeInternal, "no template registered for role %s", role)
	}
	tmplName := allowed.name
	// The template dir itself must be a real directory, not a symlink:
	// a caller-supplied symlinked template dir would redirect template
	// reads outside the intended root.
	tmplDirFi, err := os.Lstat(opts.TemplateDir)
	if err != nil {
		return nil, safex.New(safex.CodeNotFound, "template dir not found").Wrap(err)
	}
	if tmplDirFi.Mode()&os.ModeSymlink != 0 {
		return nil, safex.New(safex.RenderUnsafe, "template dir must not be a symlink")
	}
	if !tmplDirFi.IsDir() {
		return nil, safex.New(safex.CodeUsage, "template dir is not a directory")
	}
	tmplPath := filepath.Join(opts.TemplateDir, tmplName)
	if err := checkNoTraversal(tmplPath); err != nil {
		return nil, err
	}
	if err := checkNoTraversal(opts.TemplateDir); err != nil {
		return nil, err
	}
	tmplData, err := readFileNoSymlink(tmplPath)
	if err != nil {
		return nil, safex.New(safex.CodeNotFound, "template %s not found or unsafe", tmplName).Wrap(err)
	}
	// Template identity: constant comparison of the SHA-256 digest
	// against the pinned allowlist entry. Any mismatch is rejected
	// without echoing template content.
	actualDigest := fmt.Sprintf("%x", sha256.Sum256(tmplData))
	if actualDigest != allowed.sha256 {
		return nil, safex.New(safex.CodeTemplateRejected,
			"template %s does not match the pinned SHA-256 allowlist entry", tmplName)
	}
	// Template must be confined to the (resolved) template dir.
	if err := checkConfined(opts.TemplateDir, tmplPath); err != nil {
		return nil, err
	}

	// 3. Validate template: only schema-declared placeholders, no
	// includes, no arbitrary template directives.
	if err := validateTemplate(string(tmplData)); err != nil {
		return nil, err
	}

	// 4. Output directory: the raw path is traversal-checked here, and
	// the real contract (exists, is a directory, mode 0700, no symlink
	// at ANY depth) is enforced by the publication transaction on the
	// descriptor it opens and holds — not on a re-resolved path, so
	// there is no check-then-use window.
	if err := checkNoTraversal(filepath.Clean(opts.OutDir)); err != nil {
		return nil, err
	}

	// 5. Credentials: load the role's bundle through the fixed
	// loader BEFORE any substitution, so a missing or malformed
	// credential fails closed with nothing written. Close is deferred
	// immediately to minimize secret lifetime (asset bytes are
	// zeroized in place on return, whether this render succeeds or
	// fails).
	loader := opts.Loader
	if loader == nil {
		loader = SystemdLoader{}
	}
	bundle, err := loader.Load(string(role))
	if err != nil {
		return nil, err
	}
	// A TYPED-NIL bundle is a non-nil interface wrapping a nil pointer,
	// so `bundle == nil` is false and the ordinary nil branch would be
	// skipped. Its methods have pointer receivers that read fields
	// directly (Role reads b.role, Scalar reads b.closed), so the first
	// call would dereference nil and PANIC — a crash with a stack trace
	// instead of a stable redacted refusal. Refuse it explicitly, from
	// ANY loader, before any method call.
	if isNilBundle(bundle) {
		return nil, safex.New(safex.CodeInternal, "credential bundle unavailable")
	}
	defer bundle.Close()
	// A bundle for the OTHER role must never be rendered: its secrets
	// and assets belong to a different host. The check is on the
	// bundle's own fixed role identity, not on anything caller-supplied.
	if got := bundle.Role(); got != string(role) {
		return nil, safex.New(safex.CodeConfigRejected,
			"credential bundle role does not match the requested role")
	}

	// 6. Config phase: non-secret schema placeholders resolve from the
	// config document (numbers raw after validation, strings and
	// validated addresses YAML double-quoted); the fixed credential
	// placeholders pass through untouched for the bundle phase.
	rendered, err := substituteConfig(string(tmplData), doc)
	if err != nil {
		return nil, err
	}
	// 7. Bundle phase: the fixed credential placeholders resolve from
	// the loaded bundle. Every value is validated (single line, no
	// control characters, never placeholder-shaped) and emitted as a
	// YAML double-quoted scalar. Any unresolvable placeholder fails the
	// render here, BEFORE anything is written.
	rendered, err = substituteCredentials(rendered, bundle, doc)
	if err != nil {
		return nil, err
	}

	// 8. Collect the publication set: the rendered config plus every
	// allowlisted materialized asset for THIS role, under their fixed
	// destination names. An asset name outside the role allowlist fails
	// closed rather than being written or silently dropped.
	//
	// OWNERSHIP AND SECRET LIFETIME (see also the backend contract in
	// writer.go). From here until Run returns, this map OWNS every byte
	// slice it holds, and those slices hold live secret material:
	//
	//   - files[renderedName] holds the rendered config, which contains
	//     every substituted scalar secret;
	//   - files[asset.Dest] holds the deep copies Materialize produced,
	//     i.e. live certificate/key bytes;
	//   - Bundle.Close() only zeroes the BUNDLE's own originals, never
	//     these copies, so closing the bundle is not sufficient.
	//
	// TWO deferred cleanups therefore run on EVERY path out of Run —
	// writer success, writer failure, and every early return alike:
	// one over this map, and one over the whole batch Materialize
	// returned (registered the moment that batch exists, so a validation
	// that rejects an asset cannot skip it). Together they leave no copy
	// of the material alive when Run returns; they deliberately overlap,
	// and zeroing twice is idempotent.
	//
	// That cleanup is safe only because the backend contract requires
	// each write to consume the bytes SYNCHRONOUSLY and retain nothing:
	// a backend that kept a reference and wrote later would observe
	// zeroed data. The production backend writes through the held
	// descriptor inside the call and keeps no reference.
	//
	// Documented limit: the rendered config also exists as an immutable
	// Go string (`rendered`) and the scalar secrets as bundle strings.
	// Those cannot be zeroed without unsafe aliasing of memory render
	// does not own, so they are left to the collector; only the byte
	// slices render owns are deterministically wiped.
	files := map[string][]byte{renderedName(role): []byte(rendered)}
	defer func() {
		for name, data := range files {
			for i := range data {
				data[i] = 0
			}
			delete(files, name)
		}
	}()

	// Materialize returns the WHOLE batch of deep copies in one call, so
	// it is captured in a local slice and its cleanup is registered
	// IMMEDIATELY — before any validation that can return early.
	//
	// Registering per-asset cleanup as assets are inserted into files
	// would not be enough: the allowlist, empty and duplicate checks
	// below all return BEFORE the insertion, so the offending asset and
	// every asset after it would never be reached by a files-only wipe,
	// leaving live certificate/key bytes behind on exactly the paths
	// that reject hostile material.
	//
	// This defer covers the entire batch unconditionally. It overlaps
	// with the files wipe above for the assets that did get inserted;
	// zeroing an already-zeroed slice is idempotent, and double coverage
	// is the point — neither cleanup depends on how far the loop got.
	assets := bundle.Materialize()
	defer func() {
		for i := range assets {
			for j := range assets[i].Data {
				assets[i].Data[j] = 0
			}
		}
	}()

	allowedAssets := roleAssetNames[string(role)]
	for _, a := range assets {
		if _, ok := allowedAssets[a.Dest]; !ok {
			// Fixed message: the rejected name is not echoed.
			return nil, safex.New(safex.RenderUnsafe,
				"credential bundle offered an asset outside the role allowlist")
		}
		if len(a.Data) == 0 {
			return nil, safex.New(safex.CodeConfigRejected,
				"credential asset is empty")
		}
		if _, dup := files[a.Dest]; dup {
			return nil, safex.New(safex.RenderUnsafe,
				"credential bundle offered a duplicate asset name")
		}
		files[a.Dest] = a.Data
	}

	// 9. Validate the publication set BEFORE the first write.
	// validation-before-write is without exception: no name may reach
	// the filesystem before it has been checked against the fixed
	// allowlist. (writeTransaction re-validates defensively, but that
	// is a second line of defence, not the one Run relies on.)
	published, err := validateOutputNames(files)
	if err != nil {
		return nil, err
	}

	// 10. Publish config and assets in ONE safe transaction. Every
	// validation has already completed, so this is the first and only
	// step that touches the output directory. The transaction keeps
	// every documented guarantee (descriptor-relative whole-path
	// verification, 0700 dir, 0600 files, per-file atomic no-replace
	// publish, fsync before and after cleanup, published files never
	// deleted).
	w := defaultBackend()
	if opts.writer != nil {
		w = *opts.writer
	}
	if err := writeTransactionWithBackend(opts.OutDir, files, w); err != nil {
		return nil, err
	}

	return &Result{
		Role:        string(role),
		OK:          true,
		Files:       published,
		TemplateDir: opts.TemplateDir,
	}, nil
}

// placeholderValues returns the config-phase substitution map from the
// document: ONLY the schema-declared non-secret top-level fields a
// config document may provide (numbers, addresses, identity strings).
// Credential fields (gateway-egress-password, gateway-node-password) and users-section
// secrets are deliberately NOT mapped: their placeholders are resolved
// exclusively by the bundle phase from a loaded credential bundle.
func placeholderValues(doc *config.Document) map[string]string {
	m := map[string]string{}
	for _, k := range []string{"mixed-port", "bind-address", "controller-listen",
		"gateway-egress-user", "egress-server", "egress-port", "egress-sni", "listen-address", "port", "sni",
		"gateway-node-user", "max-users"} {
		if v, ok := doc.Scalar(k); ok {
			m[strings.ToUpper(strings.ReplaceAll(k, "-", "_"))] = v
		}
	}
	if address, ok := doc.Scalar("listen-address"); ok {
		if port, portOK := doc.Scalar("port"); portOK {
			m["LISTEN"] = net.JoinHostPort(strings.Trim(address, "[]"), port)
		}
	}
	return m
}

// validateTemplate rejects template constructs and placeholders that
// are not declared in the explicit placeholder schema.
func validateTemplate(tmpl string) error {
	// No template engine features: reject include/extends/backticks.
	for _, banned := range []string{"{{", "}}", "{%"} {
		if strings.Contains(tmpl, banned) {
			return safex.New(safex.CodeTemplateRejected,
				"template contains forbidden directive syntax %q (no template engine allowed)", banned)
		}
	}
	if strings.Contains(tmpl, "skip-cert-verify") || strings.Contains(tmpl, "insecure: true") {
		return safex.New(safex.CodeTemplateRejected,
			"template contains forbidden insecure TLS option")
	}
	// A DIRECT outbound fallback is forbidden anywhere in the template
	// source. Validation runs before substitution, so credential values
	// cannot affect this check.
	if strings.Contains(tmpl, "DIRECT") {
		return safex.New(safex.CodeTemplateRejected,
			"template contains forbidden DIRECT fallback")
	}
	// A dangling "${" with no closing "}" is rejected up front: the
	// variable extractor silently drops such fragments, so they must be
	// caught before any output is produced. Fixed message only.
	if containsDanglingPlaceholder(tmpl) {
		return safex.New(safex.CodeTemplateRejected,
			"template contains an unterminated placeholder")
	}
	// Every ${VAR} must be declared in the placeholder schema. Unknown
	// names are attacker-controlled template text; the diagnostic is a
	// fixed message that never echoes the extracted name.
	for _, m := range templateVars(tmpl) {
		if _, ok := placeholderSchema[m]; !ok {
			return safex.New(safex.CodeTemplateRejected,
				"template references an unknown placeholder (not in schema allowlist)")
		}
	}
	return nil
}

// templateVars extracts ${VAR} names.
func templateVars(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return out
		}
		rest := s[i+2:]
		j := strings.Index(rest, "}")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		s = rest[j+1:]
	}
}

// checkNoTraversal rejects paths with ".." path components, splitting
// the RAW path on separators without any prior Clean: an intermediate
// ".." (as in "a/../b") must be rejected, not silently collapsed by
// filepath.Clean. Component-exact, not substring: "a..b" is a legal
// filename; the empty leading component of an absolute path ("/a") is
// allowed. Symlink escapes are handled separately: template paths are
// Lstat'ed (final component must not be a symlink) and output
// directories are Lstat'ed and never created or walked above by
// proxyctl.
func checkNoTraversal(p string) error {
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return safex.New(safex.RenderUnsafe, "path traversal rejected (component '..') in %s", p)
		}
	}
	return nil
}

// checkConfined verifies that path (after resolving symlinks) stays
// inside root (after resolving symlinks). Both must exist.
func checkConfined(root, path string) error {
	rr, err := filepath.EvalSymlinks(root)
	if err != nil {
		return safex.New(safex.CodeNotFound, "cannot resolve root for confinement check")
	}
	pp, err := filepath.EvalSymlinks(path)
	if err != nil {
		return safex.New(safex.CodeNotFound, "cannot resolve path for confinement check")
	}
	if pp != rr && !strings.HasPrefix(pp+string(filepath.Separator), rr+string(filepath.Separator)) {
		return safex.New(safex.RenderUnsafe, "path escapes its allowed root (symlink?)")
	}
	return nil
}

// readFileNoSymlink reads a file, refusing to follow a symlink at the
// final path component.
func readFileNoSymlink(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink at template path")
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("template path is a directory")
	}
	return os.ReadFile(path)
}

// NOTE: render deliberately has NO second, weaker file writer. Every
// output byte goes through writeTransaction / writeTransactionWithBackend
// (writer.go), which owns the descriptor-relative whole-path
// verification, the 0700 directory contract, 0600 files, the per-file
// atomic no-replace publish and the fsync ordering. A local
// "write one file safely" helper next to it would be a second,
// unaudited path to the filesystem, so it is not provided.
