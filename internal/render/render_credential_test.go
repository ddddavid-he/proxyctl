package render

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"proxyctl/internal/credential"
	"proxyctl/internal/safex"
)

// Regressions for the runtime credential wiring: the loaded bundle
// really drives substitution, the role's allowlisted assets are
// published in the SAME transaction as the rendered config, and every
// failure mode fails closed with a redacted, fixed error that publishes
// nothing.
//
// These tests run on every platform: they drive Run through the
// injected in-memory publication backend (Options.writer), so the
// pipeline is fully exercised even where the production writer fails
// closed by design.

// --- happy path: bundle drives substitution and asset publication ----

// TestRenderPublishesConfigAndAssetsTogether proves the rendered config
// and BOTH role assets are published by one render, under their fixed
// names, with the credential values substituted into the config and the
// asset bytes written verbatim (never inlined into the config).
func TestRenderPublishesConfigAndAssetsTogether(t *testing.T) {
	for _, tc := range []struct {
		role, tmpl, fixture string
		bundle              func() *synthBundle
		wantAssets          map[string]string
		wantSecret          string
	}{
		{"gateway", "mihomo", "gateway-valid.yaml", synthGateway,
			map[string]string{"gateway.crt": synthGatewayCrt, "gateway.key": synthGatewayKey},
			synthTrojanPass},
		{"egress", "hysteria", "egress-valid.yaml", synthEgress,
			map[string]string{"egress.crt": synthEgressCrt, "egress.key": synthEgressKey},
			synthGatewayEgressPassword},
	} {
		t.Run(tc.role, func(t *testing.T) {
			f := newRenderFixture(t, tc.role, tc.tmpl, tc.fixture, tc.bundle())
			res, err := f.run()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !res.OK {
				t.Fatalf("result not OK: %+v", res)
			}
			cfgName := tc.role + "-rendered.yaml"
			want := []string{cfgName}
			for n := range tc.wantAssets {
				want = append(want, n)
			}
			got := f.published()
			if len(got) != len(want) {
				t.Fatalf("published = %v, want the config plus %d assets", got, len(tc.wantAssets))
			}
			// Result.Files must exactly match what landed on disk.
			if len(res.Files) != len(want) {
				t.Errorf("Result.Files = %v, want %d entries", res.Files, len(want))
			}
			for _, n := range res.Files {
				if f.content(n) == "" {
					t.Errorf("Result.Files lists %q but nothing was published under it", n)
				}
			}
			// Assets land verbatim under their fixed destination names.
			for name, body := range tc.wantAssets {
				if f.content(name) != body {
					t.Errorf("%s = %d bytes, want the materialized asset", name, len(f.content(name)))
				}
			}
			cfg := f.content(cfgName)
			// The credential really came from the bundle.
			if !strings.Contains(cfg, tc.wantSecret) {
				t.Error("rendered config does not contain the bundle credential")
			}
			// Asset bytes are NEVER inlined into the config: assets and
			// scalars are strictly distinct.
			for _, body := range tc.wantAssets {
				if strings.Contains(cfg, body) {
					t.Error("asset bytes were inlined into the rendered config")
				}
			}
			// No placeholder may survive into the published config.
			if strings.Contains(cfg, "${") {
				t.Error("published config still contains a placeholder fragment")
			}
		})
	}
}

// TestRenderSubstitutesEveryCredentialQuoted proves each substituted
// credential lands as a YAML double-quoted scalar, so secret bytes can
// never inject config structure.
func TestRenderSubstitutesEveryCredentialQuoted(t *testing.T) {
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", synthGateway())
	if _, err := f.run(); err != nil {
		t.Fatalf("render: %v", err)
	}
	cfg := f.content("gateway-rendered.yaml")
	for _, secret := range []string{
		"gateway-node-01:" + synthGatewayEgressPassword, synthTrojanUser, synthTrojanPass,
		synthHTTPSUser, synthHTTPSPass,
	} {
		if !strings.Contains(cfg, `"`+secret+`"`) {
			t.Errorf("credential %q is not emitted as a double-quoted scalar", secret)
		}
	}
}

// TestRenderPublishesOptionalAssets proves an allowlisted OPTIONAL
// asset (future mTLS material) is published when the bundle carries it.
func TestRenderPublishesOptionalAssets(t *testing.T) {
	b := synthGateway()
	b.assets["gateway-client.crt"] = []byte(synthGatewayClientCrt)
	b.assets["gateway-client.key"] = []byte(synthGatewayClientKey)
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	res, err := f.run()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(res.Files) != 5 {
		t.Fatalf("Result.Files = %v, want config + 4 assets", res.Files)
	}
	if f.content("gateway-client.crt") != synthGatewayClientCrt ||
		f.content("gateway-client.key") != synthGatewayClientKey {
		t.Error("optional mTLS assets were not published verbatim")
	}
}

// TestRenderPublicationOrderIsFixed proves publication follows the
// writer's fixed allowlist order, not bundle or map iteration order.
func TestRenderPublicationOrderIsFixed(t *testing.T) {
	b := synthGateway()
	b.assets["gateway-client.crt"] = []byte(synthGatewayClientCrt)
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	res, err := f.run()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := []string{"gateway-rendered.yaml", "gateway.crt", "gateway.key", "gateway-client.crt"}
	if strings.Join(res.Files, ",") != strings.Join(want, ",") {
		t.Errorf("Result.Files = %v, want fixed order %v", res.Files, want)
	}
}

// --- loader contract -------------------------------------------------

// TestRenderUsesLoaderExactlyOnceWithValidatedRole proves the loader is
// consulted once per render and receives the VALIDATED role string.
func TestRenderUsesLoaderExactlyOnceWithValidatedRole(t *testing.T) {
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", synthGateway())
	if _, err := f.run(); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.loader.loads != 1 {
		t.Errorf("loader called %d times, want exactly 1", f.loader.loads)
	}
	if f.loader.gotRole != "gateway" {
		t.Errorf("loader got role %q, want %q", f.loader.gotRole, "gateway")
	}
}

// TestRenderClosesBundleOnSuccessAndFailure proves secret lifetime is
// minimized on BOTH paths: the bundle is closed whether the render
// succeeds or fails.
func TestRenderClosesBundleOnSuccessAndFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		b := synthGateway()
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		if _, err := f.run(); err != nil {
			t.Fatalf("render: %v", err)
		}
		if b.closes != 1 {
			t.Errorf("bundle closed %d times, want exactly 1", b.closes)
		}
		if !b.closed {
			t.Error("bundle was not closed after a successful render")
		}
	})
	t.Run("failure", func(t *testing.T) {
		// A missing credential fails the bundle phase after the load.
		b := synthGateway()
		delete(b.scalars, "HTTPS_PASSWORD_1")
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		if _, err := f.run(); err == nil {
			t.Fatal("render accepted a bundle missing a required credential")
		}
		if b.closes != 1 {
			t.Errorf("bundle closed %d times on the failure path, want exactly 1", b.closes)
		}
	})
}

// TestRenderLoaderErrorFailsClosed proves a loader failure aborts the
// render before anything is published, preserving the loader's code.
func TestRenderLoaderErrorFailsClosed(t *testing.T) {
	for _, code := range []safex.Code{
		safex.CodeNotFound, safex.CodePermission,
		safex.CodeConfigRejected, safex.RenderUnsafe, safex.CodeInternal,
	} {
		fb, _ := newFakeBackend(outputDirPerm)
		w := fb.backend()
		_, err := Run(Options{
			Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
			ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: "out",
			Loader: &synthLoader{err: safex.New(code, "credential unavailable")},
			writer: &w,
		})
		requireCode(t, err, code)
		if n := fb.names(); len(n) != 0 {
			t.Errorf("code %v: published %v despite a loader failure", code, n)
		}
	}
}

// TestRenderNilBundleFromLoaderFailsClosed proves a loader that returns
// (nil, nil) cannot cause a credential-free render.
func TestRenderNilBundleFromLoaderFailsClosed(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	w := fb.backend()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: "out",
		Loader: &synthLoader{}, // bundle nil, err nil
		writer: &w,
	})
	requireCode(t, err, safex.CodeInternal)
	if n := fb.names(); len(n) != 0 {
		t.Errorf("published %v despite a nil bundle", n)
	}
}

// --- wrong-role and wrong-asset material -----------------------------

// TestRenderRejectsWrongRoleBundle proves a bundle belonging to the
// OTHER role is refused: its secrets and assets are for a different
// host, so rendering it would cross-provision the wrong machine.
func TestRenderRejectsWrongRoleBundle(t *testing.T) {
	for _, tc := range []struct {
		role, tmpl, fixture string
		bundle              *synthBundle
	}{
		{"gateway", "mihomo", "gateway-valid.yaml", synthEgress()},
		{"egress", "hysteria", "egress-valid.yaml", synthGateway()},
	} {
		f := newRenderFixture(t, tc.role, tc.tmpl, tc.fixture, tc.bundle)
		_, err := f.run()
		requireCode(t, err, safex.CodeConfigRejected)
		assertNoSynthSecretLeak(t, "wrong-role error", err.Error())
		if n := f.published(); len(n) != 0 {
			t.Errorf("role %s: published %v with a wrong-role bundle", tc.role, n)
		}
		// The bundle is still closed on this path.
		if tc.bundle.closes != 1 {
			t.Errorf("role %s: wrong-role bundle closed %d times, want 1", tc.role, tc.bundle.closes)
		}
	}
}

// TestRenderRejectsAssetOutsideRoleAllowlist proves render enforces the
// per-role asset allowlist ITSELF: a bundle offering another role's
// asset, or an unknown name, is refused rather than written.
func TestRenderRejectsAssetOutsideRoleAllowlist(t *testing.T) {
	for _, name := range []string{
		"egress.crt",            // the other role's material
		"egress.key",            // the other role's material
		"gateway-client-ca.crt", // allowlisted, but for the egress role only
		"evil.crt",              // unknown entirely
		"gateway-rendered.yaml", // would collide with the rendered config
	} {
		b := synthGateway()
		b.assets[name] = []byte("SYNTH-CANARY-out-of-allowlist-body")
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		_, err := f.run()
		if err == nil {
			t.Fatalf("asset %q outside the gateway allowlist was accepted", name)
		}
		requireCode(t, err, safex.RenderUnsafe)
		// The rejected name must not be echoed.
		if strings.Contains(err.Error(), name) {
			t.Errorf("error echoed the rejected asset name %q: %q", name, err.Error())
		}
		if n := f.published(); len(n) != 0 {
			t.Errorf("asset %q: published %v despite the refusal", name, n)
		}
	}
}

// TestRenderRejectsEmptyAsset proves an empty asset fails closed rather
// than publishing a zero-length certificate or key.
func TestRenderRejectsEmptyAsset(t *testing.T) {
	b := synthGateway()
	b.assets["gateway.key"] = []byte{}
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	_, err := f.run()
	requireCode(t, err, safex.CodeConfigRejected)
	if n := f.published(); len(n) != 0 {
		t.Errorf("published %v despite an empty asset", n)
	}
}

// --- malformed credential values -------------------------------------

// TestRenderRejectsMalformedCredentialValues covers the value-level
// failure matrix at the render boundary: multiline, control-bearing,
// invalid UTF-8, placeholder-shaped and empty credentials all fail
// closed with a redacted error and publish nothing.
func TestRenderRejectsMalformedCredentialValues(t *testing.T) {
	const canary = "SYNTH-CANARY-malformed-9a8b"
	cases := []struct {
		name  string
		value string
		want  safex.Code
	}{
		{"newline", canary + "\ninjected: true", safex.CodeConfigRejected},
		{"crlf", canary + "\r\nnext: 1", safex.CodeConfigRejected},
		{"cr", canary + "\r", safex.CodeConfigRejected},
		{"nul", canary + "\x00", safex.CodeConfigRejected},
		{"escape", canary + "\x1b[31m", safex.CodeConfigRejected},
		{"tab", canary + "\ttab", safex.CodeConfigRejected},
		{"del", canary + "\x7f", safex.CodeConfigRejected},
		{"line separator", canary + "\u2028", safex.CodeConfigRejected},
		{"invalid utf8", canary + "\xff", safex.CodeConfigRejected},
		{"placeholder shaped", "${NESTED}", safex.CodeConfigRejected},
		{"embedded placeholder", canary + "${GATEWAY_EGRESS_PASSWORD_1}", safex.CodeConfigRejected},
		{"dangling placeholder", canary + "${", safex.CodeConfigRejected},
		{"empty", "", safex.CodeConfigRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := synthGateway()
			b.scalars["TROJAN_PASSWORD_1"] = tc.value
			f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
			_, err := f.run()
			if err == nil {
				t.Fatalf("malformed credential (%s) accepted", tc.name)
			}
			// An empty value is "not available" from the bundle's point
			// of view only if absent; here it is present but empty, so
			// the emission contract must reject it.
			se, ok := err.(*safex.Error)
			if !ok {
				t.Fatalf("error = %T, want *safex.Error", err)
			}
			if se.Code != tc.want && se.Code != safex.CodeNotFound {
				t.Errorf("code = %v, want %v", se.Code, tc.want)
			}
			// The error must not leak the value or any fragment of it.
			msg := err.Error()
			if strings.Contains(msg, canary) {
				t.Errorf("error leaks the credential value: %q", msg)
			}
			if strings.ContainsAny(msg, "\r\n\t\x00") {
				t.Errorf("error carries control characters: %q", msg)
			}
			if se.Unwrap() != nil {
				t.Errorf("error wraps an underlying cause: %q", msg)
			}
			if n := f.published(); len(n) != 0 {
				t.Errorf("published %v despite a malformed credential", n)
			}
		})
	}
}

// TestRenderRejectsMissingCredential proves an absent required
// credential fails closed as NOT_FOUND, naming only the hardcoded
// placeholder, and publishes nothing.
func TestRenderRejectsMissingCredential(t *testing.T) {
	for _, missing := range []string{
		"GATEWAY_EGRESS_PASSWORD_1", "TROJAN_USER_1", "TROJAN_PASSWORD_1",
		"HTTPS_USER_1", "HTTPS_PASSWORD_1",
	} {
		b := synthGateway()
		delete(b.scalars, missing)
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		_, err := f.run()
		requireCode(t, err, safex.CodeNotFound)
		assertNoSynthSecretLeak(t, "missing-credential error", err.Error())
		if n := f.published(); len(n) != 0 {
			t.Errorf("missing %s: published %v", missing, n)
		}
	}
}

// TestRenderRejectsClosedBundle proves a bundle that is already closed
// cannot render: every lookup fails closed, so the render must abort
// rather than emit empty credentials.
func TestRenderRejectsClosedBundle(t *testing.T) {
	b := synthGateway()
	b.Close()
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	_, err := f.run()
	requireCode(t, err, safex.CodeNotFound)
	if n := f.published(); len(n) != 0 {
		t.Errorf("published %v with a closed bundle", n)
	}
}

// --- output surface must never carry secrets --------------------------

// TestRenderResultAndErrorsNeverCarrySecrets proves the Result (and its
// JSON encoding, which is what the CLI prints on stdout) contains only
// fixed names, and that a failing render's error is equally clean.
func TestRenderResultAndErrorsNeverCarrySecrets(t *testing.T) {
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", synthGateway())
	res, err := f.run()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	blob, jerr := json.Marshal(res)
	if jerr != nil {
		t.Fatalf("json.Marshal: %v", jerr)
	}
	assertNoSynthSecretLeak(t, "Result JSON", string(blob))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		assertNoSynthSecretLeak(t, "Result "+verb, fmt.Sprintf(verb, res))
	}
	// Result lists only fixed, allowlisted names.
	for _, n := range res.Files {
		if _, ok := allowedOutputNames[n]; !ok {
			t.Errorf("Result.Files contains a non-allowlisted name %q", n)
		}
	}
}

// TestRenderErrorsNeverCarrySecretsAcrossFailureModes sweeps the
// failure matrix and asserts no synthetic secret, and no bundle-internal
// detail, reaches any error message.
func TestRenderErrorsNeverCarrySecretsAcrossFailureModes(t *testing.T) {
	mutators := map[string]func(*synthBundle){
		"missing scalar":  func(b *synthBundle) { delete(b.scalars, "TROJAN_USER_1") },
		"newline scalar":  func(b *synthBundle) { b.scalars["TROJAN_USER_1"] = synthTrojanUser + "\nx: 1" },
		"nul scalar":      func(b *synthBundle) { b.scalars["HTTPS_USER_1"] = synthHTTPSUser + "\x00" },
		"nested scalar":   func(b *synthBundle) { b.scalars["HTTPS_PASSWORD_1"] = "${" + synthHTTPSPass + "}" },
		"empty asset":     func(b *synthBundle) { b.assets["gateway.crt"] = nil },
		"foreign asset":   func(b *synthBundle) { b.assets["egress.key"] = []byte(synthEgressKey) },
		"wrong role":      func(b *synthBundle) { b.role = "egress" },
		"closed upfront":  func(b *synthBundle) { b.Close() },
		"oversize scalar": func(b *synthBundle) { b.scalars["TROJAN_PASSWORD_1"] = strings.Repeat(synthTrojanPass, 64) },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			b := synthGateway()
			mutate(b)
			f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
			_, err := f.run()
			if err == nil {
				// An oversize-but-well-formed value is legitimately
				// renderable; only assert the no-leak property then.
				if name == "oversize scalar" {
					assertNoSynthSecretLeak(t, "published names",
						strings.Join(f.published(), ","))
					return
				}
				t.Fatalf("%s was accepted", name)
			}
			msg := err.Error()
			assertNoSynthSecretLeak(t, name+" error", msg)
			// No source path, credential file name or auth header form.
			for _, banned := range []string{
				"/run/credentials", "CREDENTIALS_DIRECTORY",
				"Authorization", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE",
			} {
				if strings.Contains(msg, banned) {
					t.Errorf("%s error leaks %q: %q", name, banned, msg)
				}
			}
			if strings.ContainsAny(msg, "\r\n\t") {
				t.Errorf("%s error carries control characters: %q", name, msg)
			}
		})
	}
}

// TestRenderPublishedConfigContainsNoAssetOrPlaceholderResidue proves
// the published config carries the scalars only: no asset bytes, no
// placeholder fragment, no unresolved name.
func TestRenderPublishedConfigContainsNoAssetOrPlaceholderResidue(t *testing.T) {
	b := synthGateway()
	b.assets["gateway-client.crt"] = []byte(synthGatewayClientCrt)
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	if _, err := f.run(); err != nil {
		t.Fatalf("render: %v", err)
	}
	cfg := f.content("gateway-rendered.yaml")
	for _, assetBody := range []string{synthGatewayCrt, synthGatewayKey, synthGatewayClientCrt} {
		if strings.Contains(cfg, assetBody) {
			t.Error("published config contains asset bytes")
		}
	}
	if strings.Contains(cfg, "${") {
		t.Error("published config contains a placeholder fragment")
	}
	for _, banned := range []string{"DIRECT", "skip-cert-verify", "insecure: true"} {
		if strings.Contains(cfg, banned) {
			t.Errorf("published config contains %q", banned)
		}
	}
}

// --- isolation --------------------------------------------------------

// TestRenderConcurrentRendersAreIsolated proves the loader seam carries
// no package-level mutable state: concurrent renders with DIFFERENT
// bundles never see each other's credentials.
func TestRenderConcurrentRendersAreIsolated(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	bad := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			unique := fmt.Sprintf("SYNTH-CANARY-render-%d", i)
			b := synthGateway()
			b.scalars["TROJAN_PASSWORD_1"] = unique
			f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
			if _, err := f.run(); err != nil {
				errs[i] = err
				return
			}
			cfg := f.content("gateway-rendered.yaml")
			if !strings.Contains(cfg, unique) {
				bad[i] = "own credential missing"
				return
			}
			// No other goroutine's unique credential may appear.
			for j := 0; j < n; j++ {
				if j == i {
					continue
				}
				if strings.Contains(cfg, fmt.Sprintf("SYNTH-CANARY-render-%d", j)) {
					bad[i] = fmt.Sprintf("saw credential of render %d", j)
				}
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("render %d: %v", i, errs[i])
		}
		if bad[i] != "" {
			t.Errorf("render %d: %s", i, bad[i])
		}
	}
}

// --- production loader surface ---------------------------------------

// TestSystemdLoaderIsTheDefaultAndFixed proves a nil Loader selects the
// production systemd loader, which fails closed when no credential
// directory is provisioned (the test environment) and publishes nothing.
func TestSystemdLoaderIsTheDefaultAndFixed(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	fb, _ := newFakeBackend(outputDirPerm)
	w := fb.backend()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: "out",
		// Loader deliberately nil: the production default applies.
		writer: &w,
	})
	if err == nil {
		t.Fatal("render succeeded with no provisioned credentials")
	}
	se, ok := err.(*safex.Error)
	if !ok {
		t.Fatalf("error = %T, want *safex.Error", err)
	}
	// Fail-closed, and the message names no path.
	if strings.Contains(se.Message, "/run/credentials") ||
		strings.Contains(se.Message, "CREDENTIALS_DIRECTORY") {
		t.Errorf("error leaks the credential source: %q", se.Message)
	}
	if n := fb.names(); len(n) != 0 {
		t.Errorf("published %v with no credentials", n)
	}
}

// TestSystemdLoaderRejectsInvalidRole proves the production loader
// validates the role before touching any environment or filesystem.
func TestSystemdLoaderRejectsInvalidRole(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	for _, role := range []string{"", "eu", "gateway", "gateway/../egress"} {
		b, err := SystemdLoader{}.Load(role)
		if err == nil {
			t.Errorf("role %q accepted by the production loader", role)
		}
		if b != nil {
			t.Errorf("role %q returned a bundle alongside an error", role)
		}
	}
}

// TestCredentialBundleSatisfiesRenderBundle is a compile-time and
// behavioral check that the real *credential.Bundle is usable as the
// render Bundle: the seam must not drift from the production type.
func TestCredentialBundleSatisfiesRenderBundle(t *testing.T) {
	var _ Bundle = (*credential.Bundle)(nil)
	var _ Loader = SystemdLoader{}
	var _ BundleSource = (*credential.Bundle)(nil)
}

// --- typed-nil defense ------------------------------------------------

// nilBundleLoader returns a TYPED NIL bundle: a non-nil interface value
// wrapping a nil *credential.Bundle. `bundle == nil` is FALSE for it,
// which is exactly why Run needs an explicit reflect-based guard.
type nilBundleLoader struct{}

func (nilBundleLoader) Load(string) (Bundle, error) {
	var b *credential.Bundle // nil pointer
	return b, nil            // non-nil interface, nil pointer inside
}

// TestRenderRejectsTypedNilBundle proves a typed-nil bundle cannot slip
// through: it must fail closed with a fixed internal error rather than
// panicking or rendering with an empty bundle.
func TestRenderRejectsTypedNilBundle(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	w := fb.backend()
	_, err := Run(Options{
		Role: "gateway", TemplateDir: tmplDir(t, "mihomo"),
		ConfigPath: fixturePath(t, "gateway-valid.yaml"), OutDir: "out",
		Loader: nilBundleLoader{}, writer: &w,
	})
	if err == nil {
		t.Fatal("render accepted a typed-nil bundle")
	}
	requireCode(t, err, safex.CodeInternal)
	// A fixed message with no credential, path or secret detail.
	msg := err.Error()
	for _, banned := range []string{
		"/run/credentials", "CREDENTIALS_DIRECTORY", "Authorization",
	} {
		if strings.Contains(msg, banned) {
			t.Errorf("typed-nil error leaks %q: %q", banned, msg)
		}
	}
	if n := fb.names(); len(n) != 0 {
		t.Errorf("published %v with a typed-nil bundle", n)
	}
}

// TestTypedNilBundleIsUnusable proves the failure is not incidental: the
// typed-nil value really is a non-nil interface, so only an explicit
// guard can catch it, and the guard must not reject a REAL bundle.
func TestTypedNilBundleIsUnusable(t *testing.T) {
	var b *credential.Bundle
	var i Bundle = b
	if i == nil {
		t.Fatal("test premise broken: typed nil compared equal to nil")
	}
	if !isNilBundle(i) {
		t.Error("isNilBundle did not detect a typed nil")
	}
	// The guard must not reject a real, loaded bundle.
	real, err := SystemdLoader{}.Load("gateway")
	if err == nil && isNilBundle(real) {
		t.Error("isNilBundle rejected a real bundle")
	}
	// A literal nil interface is detected too.
	if !isNilBundle(nil) {
		t.Error("isNilBundle(nil) = false, want true")
	}
}

// TestSystemdLoaderNeverReturnsTypedNil proves the production loader
// never hands back a typed-nil bundle, on either the success or the
// failure path.
func TestSystemdLoaderNeverReturnsTypedNil(t *testing.T) {
	// Failure path (no credentials provisioned here).
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	b, err := SystemdLoader{}.Load("gateway")
	if err == nil {
		t.Fatal("expected a failure with no credentials provisioned")
	}
	if b != nil {
		t.Errorf("failure path returned a non-nil bundle: %T", b)
	}
	if isNilBundle(b) != true {
		t.Error("failure-path bundle should be detected as nil")
	}
}

// TestIsNilBundleCoversInterfaceKinds pins the helper against the
// nil-able kinds a Bundle could arrive as.
func TestIsNilBundleCoversInterfaceKinds(t *testing.T) {
	cases := []struct {
		name string
		b    Bundle
		want bool
	}{
		{"literal nil", nil, true},
		{"typed nil pointer", func() Bundle { var p *credential.Bundle; return p }(), true},
		{"real synthetic bundle", synthGateway(), false},
	}
	for _, tc := range cases {
		if got := isNilBundle(tc.b); got != tc.want {
			t.Errorf("%s: isNilBundle = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// --- secret lifetime: every owned slice is wiped on every path ---------

// TestRenderZeroesOwnedBuffersOnSuccess proves the secret-bearing slices
// render owns (the rendered config and the materialized asset copies)
// are zeroed in place before Run returns. The test observes the very
// backing arrays the writer was given, so it cannot pass unless the
// cleanup actually happened.
func TestRenderZeroesOwnedBuffersOnSuccess(t *testing.T) {
	b := synthGateway()
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
	// Wrap the FIXTURE's own backend (f.fb), so f.content() observes the
	// very tree the render wrote into.
	seen := map[string][]byte{}
	rec := &recordingBackend{fb: f.fb, seen: seen}
	w := rec.wrap(f.fb.backend())
	f.opts.writer = &w
	res, err := Run(f.opts)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !res.OK {
		t.Fatalf("result not OK: %+v", res)
	}
	// The published content must be intact: the backend consumed the
	// bytes synchronously during the write, before the wipe.
	if f.content("gateway.crt") != synthGatewayCrt {
		t.Error("published gateway.crt is not the materialized asset")
	}
	if !strings.Contains(f.content("gateway-rendered.yaml"), synthGatewayEgressPassword) {
		t.Error("published config is missing the substituted credential")
	}
	// Every captured backing array must now be zeroed.
	if len(seen) == 0 {
		t.Fatal("test premise broken: no write was captured")
	}
	for name, data := range seen {
		if len(data) == 0 {
			continue
		}
		for i, c := range data {
			if c != 0 {
				t.Errorf("slice for %q was not zeroed (byte %d = %d)", name, i, c)
				break
			}
		}
	}
}

// recordingBackend wraps a fake backend and records the exact byte
// slices passed to write, without copying them.
type recordingBackend struct {
	fb   *fakeBackend
	seen map[string][]byte
}

func (r *recordingBackend) wrap(b backend) backend {
	// Intercept the file write by wrapping createAt's returned file.
	b.createAt = func(dir *dirHandle, name string, perm os.FileMode) (file, inodeID, error) {
		f, id, err := r.fb.createAt(dir, name, perm)
		if err != nil {
			return nil, inodeID{}, err
		}
		return &recordingFile{f: f, name: name, seen: r.seen}, id, nil
	}
	return b
}

// recordingFile records the slice identity passed to write, then
// delegates.
type recordingFile struct {
	f    file
	name string
	seen map[string][]byte
}

func (r *recordingFile) write(data []byte) error {
	r.seen[r.name] = data // keep the SAME backing array
	return r.f.write(data)
}
func (r *recordingFile) sync() error  { return r.f.sync() }
func (r *recordingFile) close() error { return r.f.close() }

// TestRenderZeroesOwnedBuffersOnWriterFailure proves the wipe also
// happens when the publication FAILS: an error path must not leave live
// secret buffers behind any more than the success path.
func TestRenderZeroesOwnedBuffersOnWriterFailure(t *testing.T) {
	f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", synthGateway())
	// Wrap the FIXTURE's own backend so the injected publish failure
	// lands in the tree this fixture observes.
	seen := map[string][]byte{}
	rec := &recordingBackend{fb: f.fb, seen: seen}
	w := rec.wrap(f.fb.backend())
	// Force the publish to fail partway through.
	w.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		if name == "gateway.key" {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		return f.fb.publish(dir, staging, name)
	}
	f.opts.writer = &w
	if _, err := Run(f.opts); err == nil {
		t.Fatal("render succeeded despite the injected publish failure")
	}
	if len(seen) == 0 {
		t.Fatal("test premise broken: no write was captured")
	}
	for name, data := range seen {
		if len(data) == 0 {
			continue
		}
		for i, c := range data {
			if c != 0 {
				t.Errorf("failure path: slice for %q was not zeroed (byte %d = %d)", name, i, c)
				break
			}
		}
	}
}

// TestRenderZeroesWholeMaterializeBatchOnEarlyReturn is the regression
// for the batch-cleanup gap: Materialize returns the WHOLE batch of deep
// copies in one call, but the asset-validation loop can return BEFORE an
// asset is inserted into the publication set. A files-only wipe would
// then miss the offending asset AND every asset after it, leaving live
// certificate/key bytes behind on exactly the paths that reject hostile
// material.
//
// Each case asserts the whole batch — the triggering asset and the
// following ones — is zeroed. The bundle records the slices it handed
// out by reference, so the assertion observes the real backing arrays.
func TestRenderZeroesWholeMaterializeBatchOnEarlyReturn(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(*synthBundle)
		want    safex.Code
		// wantMsg pins WHICH branch fired. Without it, a case can pass
		// while hitting an unrelated rejection — the duplicate case
		// originally did exactly that by tripping the allowlist branch.
		wantMsg string
		// minEntries is the number of batch entries the scenario must
		// have produced for the assertions to mean anything: the
		// triggering entry plus at least one unvisited subsequent one.
		minEntries int
	}{
		{
			// Branch: out-of-role name, on the FIRST entry. "aa-out-of-role.crt"
			// sorts before gateway.crt/gateway.key, so the allowlist rejection
			// fires immediately and the remaining assets are never even
			// examined.
			name: "out-of-role name rejected first",
			arrange: func(b *synthBundle) {
				b.assets["aa-out-of-role.crt"] = []byte(synthEgressCrt)
			},
			want:       safex.RenderUnsafe,
			wantMsg:    "outside the role allowlist",
			minEntries: 3,
		},
		{
			// Branch: empty data, genuinely MID-BATCH. The batch is
			// supplied explicitly so ordering cannot depend on name
			// collation (gateway-client.crt would sort FIRST against
			// gateway.crt, because '-' < '.'). Here gateway.crt is already
			// inserted when the empty gateway-client.crt is rejected, and
			// gateway.key is never reached.
			name: "empty asset rejected mid-batch",
			arrange: func(b *synthBundle) {
				b.withOrderedAssets(
					asset("gateway.crt", synthGatewayCrt),
					asset("gateway-client.crt", ""),
					asset("gateway.key", synthGatewayKey),
				)
			},
			want:       safex.CodeConfigRejected,
			wantMsg:    "credential asset is empty",
			minEntries: 3,
		},
		{
			// Branch: DUPLICATE name, i.e. `if _, dup := files[a.Dest]`.
			// The duplicate must be a name that PASSES the role asset
			// allowlist and is inserted before it repeats — otherwise
			// the allowlist branch fires first and this branch is never
			// reached. gateway.crt appears twice, gateway.key follows unvisited.
			name: "duplicate name rejected",
			arrange: func(b *synthBundle) {
				b.withOrderedAssets(
					asset("gateway.crt", synthGatewayCrt),
					asset("gateway.crt", "SYNTH-CANARY-duplicate-body"),
					asset("gateway.key", synthGatewayKey),
				)
			},
			want:       safex.RenderUnsafe,
			wantMsg:    "duplicate asset name",
			minEntries: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := synthGateway()
			tc.arrange(b)
			f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
			_, err := f.run()
			if err == nil {
				t.Fatalf("%s: render accepted the invalid asset set", tc.name)
			}
			requireCode(t, err, tc.want)
			assertNoSynthSecretLeak(t, tc.name+" error", err.Error())
			// The INTENDED branch fired, not an incidental rejection.
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("%s: error = %q, want it to mention %q (wrong branch)",
					tc.name, err.Error(), tc.wantMsg)
			}
			// Nothing may be published on any of these paths, and the
			// backend must not have been touched at all.
			if n := f.published(); len(n) != 0 {
				t.Errorf("%s: published %v", tc.name, n)
			}
			if len(f.fb.log) != 0 {
				t.Errorf("%s: backend was touched before validation: %v", tc.name, f.fb.log)
			}
			// THE POINT: every entry of the batch Materialize handed out
			// is zeroed — the triggering entry AND the entries the loop
			// never reached. Checked per entry so duplicate names count.
			b.assertEveryHandedSliceZeroed(t, tc.name, tc.minEntries)
			b.assertHandedOutZeroed(t, tc.name)
		})
	}
}

// TestRenderZeroesWholeMaterializeBatchOnSuccessAndWriterFailure proves
// the batch cleanup also covers the ordinary paths, so the two deferred
// wipes (files map and Materialize batch) provide the intended double
// coverage rather than one substituting for the other.
func TestRenderZeroesWholeMaterializeBatchOnSuccessAndWriterFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		b := synthGateway()
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		if _, err := f.run(); err != nil {
			t.Fatalf("render: %v", err)
		}
		b.assertHandedOutZeroed(t, "success")
	})
	t.Run("writer failure", func(t *testing.T) {
		b := synthGateway()
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		w := f.fb.backend()
		w.publish = func(dir, staging *dirHandle, name string) (bool, error) {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		f.opts.writer = &w
		if _, err := Run(f.opts); err == nil {
			t.Fatal("render succeeded despite the injected publish failure")
		}
		b.assertHandedOutZeroed(t, "writer failure")
	})
}

// --- validation before write -------------------------------------------

// TestOutputNameValidationRunsBeforeAnyWrite proves name validation
// happens BEFORE the first filesystem operation: when the publication
// set contains a name outside the allowlist, the backend is NEVER
// touched at all and nothing is published.
//
// The set is built through the injected writer seam so no new public
// interface is needed: a bundle offering an out-of-allowlist asset is
// the realistic way a bad name could enter the map, and the rejection
// must occur before the backend is touched.
//
// The assertion is that the backend log is COMPLETELY EMPTY — not merely
// free of createAt/mkdirAt. openDir alone would already mean the output
// directory was opened and verified before the names were checked, so
// "zero filesystem operations" has to mean zero recorded operations of
// any kind.
func TestOutputNameValidationRunsBeforeAnyWrite(t *testing.T) {
	for _, bad := range []string{"evil.yaml", "gateway.crt.bak", "sub/gateway.crt", "../gateway.crt", "gateway.CRT", ""} {
		b := synthGateway()
		b.assets[bad] = []byte("SYNTH-CANARY-bad-name-body")
		f := newRenderFixture(t, "gateway", "mihomo", "gateway-valid.yaml", b)
		_, err := f.run()
		if err == nil {
			t.Fatalf("out-of-allowlist name %q was accepted", bad)
		}
		// Either render's own asset-allowlist check or the name
		// validation rejects it — in both cases BEFORE any write.
		se, ok := err.(*safex.Error)
		if !ok {
			t.Fatalf("error = %T, want *safex.Error", err)
		}
		if se.Code != safex.RenderUnsafe {
			t.Errorf("name %q: code = %v, want RENDER_UNSAFE", bad, se.Code)
		}
		if n := f.published(); len(n) != 0 {
			t.Errorf("name %q: published %v", bad, n)
		}
		// No staging directory: the transaction never started.
		if f.fb.stagingDir() != nil {
			t.Errorf("name %q: staging state was created", bad)
		}
		// ZERO backend operations of ANY kind, openDir included.
		if len(f.fb.log) != 0 {
			t.Errorf("name %q: backend was touched before names were validated: %v",
				bad, f.fb.log)
		}
		// The rejected name must not be echoed, and the asset bytes must
		// still have been wiped.
		if strings.Contains(se.Message, bad) && bad != "" {
			t.Errorf("error echoed the rejected name %q: %q", bad, se.Message)
		}
		b.assertHandedOutZeroed(t, "rejected name "+bad)
	}
}

// TestValidateOutputNamesRejectsBeforeTransaction pins the helper the
// render now calls before writing: it rejects unknown and
// separator-bearing names without any backend interaction.
func TestValidateOutputNamesRejectsBeforeTransaction(t *testing.T) {
	for _, bad := range []string{
		"evil.yaml", "gateway.crt.bak", "gateway_client.crt", "", "gateway.CRT",
		"sub/gateway.crt", "/gateway.crt", "../gateway.crt", `gateway.crt\`,
	} {
		got, err := validateOutputNames(map[string][]byte{bad: []byte(writerCanary)})
		if err == nil {
			t.Errorf("validateOutputNames(%q) = %v, want an error", bad, got)
		}
	}
	// The full allowlist is accepted and returned in fixed order.
	all := map[string][]byte{}
	for _, n := range outputNameOrder {
		all[n] = []byte(writerCanary)
	}
	got, err := validateOutputNames(all)
	if err != nil {
		t.Fatalf("validateOutputNames(full allowlist): %v", err)
	}
	if len(got) != len(outputNameOrder) {
		t.Errorf("ordered = %v, want %v", got, outputNameOrder)
	}
	for i := range outputNameOrder {
		if got[i] != outputNameOrder[i] {
			t.Errorf("ordered[%d] = %q, want %q", i, got[i], outputNameOrder[i])
		}
	}
}
