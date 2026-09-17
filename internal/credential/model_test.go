package credential

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Model/opacity/allowlist tests: happy paths via the fake source,
// placeholder alias resolution, unknown-placeholder rejection and the
// fmt/JSON opacity contract (canary-free on %v/%+v/%#v/%s and JSON,
// for both *Bundle and dereferenced Bundle values, and for
// MaterializedAsset).

func TestLoadGatewayHappy(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for placeholder, want := range map[string]string{
		"GATEWAY_EGRESS_PASSWORD_1": gatewayEgressCanary,
		"TROJAN_USER_1":             trojanUC,
		"TROJAN_PASSWORD_1":         trojanPC,
		"HTTPS_USER_1":              httpsUC,
		"HTTPS_PASSWORD_1":          httpsPC,
	} {
		got, ok := b.Scalar(placeholder)
		if !ok || got != want {
			t.Errorf("Scalar(%q) = %q,%v want %q", placeholder, got, ok, want)
		}
	}
	assets := b.Materialize()
	if len(assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(assets))
	}
	got := map[string]string{}
	for _, a := range assets {
		got[a.Dest] = string(a.Data)
	}
	if got["gateway.crt"] != certGatewayCanary || got["gateway.key"] != keyGatewayCanary {
		t.Errorf("assets = %v", got)
	}
	if n := len(b.OptionalLoaded()); n != 0 {
		t.Errorf("optional loaded = %d, want 0", n)
	}
}

func TestLoadEgressHappy(t *testing.T) {
	b, err := load("egress", fakeSource{files: usFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, ok := b.Scalar("GATEWAY_EGRESS_PASSWORD_1")
	if !ok || got != gatewayEgressCanary {
		t.Errorf("Scalar(GATEWAY_EGRESS_PASSWORD_1) = %q,%v", got, ok)
	}
	assets := b.Materialize()
	if len(assets) != 2 || assets[0].Dest != "egress.crt" || assets[1].Dest != "egress.key" {
		t.Errorf("assets = %+v", assets)
	}
}

func TestAliasGatewayNodePasswordResolvesToSameCredential(t *testing.T) {
	b, err := load("egress", fakeSource{files: usFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	viaAlias, okAlias := b.Scalar("GATEWAY_NODE_PASSWORD_1")
	viaCanon, okCanon := b.Scalar("GATEWAY_EGRESS_PASSWORD_1")
	if !okAlias || !okCanon || viaAlias != viaCanon || viaAlias != gatewayEgressCanary {
		t.Errorf("alias resolution = %q,%v vs %q,%v", viaAlias, okAlias, viaCanon, okCanon)
	}
	// The alias is a lookup alias, never a second credential: the egress
	// allowlist reads exactly one scalar file (GATEWAY_EGRESS_PASSWORD_1).
}

func TestUnknownPlaceholderRejected(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range []string{"EVIL", "gateway.crt", "TROJAN_USER_2", "gateway_egress_password_1"} {
		if v, ok := b.Scalar(name); ok {
			t.Errorf("Scalar(%q) = %q, want not-ok", name, v)
		}
	}
}

func TestScalarToleratesSingleTrailingLF(t *testing.T) {
	f := usFakeFiles()
	f["GATEWAY_EGRESS_PASSWORD_1"] = []byte(gatewayEgressCanary + "\n")
	b, err := load("egress", fakeSource{files: f})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, _ := b.Scalar("GATEWAY_EGRESS_PASSWORD_1")
	if got != gatewayEgressCanary {
		t.Errorf("scalar = %q, want %q (trailing LF stripped)", got, gatewayEgressCanary)
	}
}

func TestBundleOpaqueFmtAndJSON(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	outputs := map[string]string{
		"%v":  fmt.Sprintf("%v", b),
		"%+v": fmt.Sprintf("%+v", b),
		"%#v": fmt.Sprintf("%#v", b),
		"%s":  fmt.Sprintf("%s", b),
	}
	jb, jerr := json.Marshal(b)
	if jerr != nil {
		t.Fatalf("json.Marshal: %v", jerr)
	}
	outputs["json"] = string(jb)
	for mode, out := range outputs {
		for _, c := range canaries {
			if strings.Contains(out, c) {
				t.Errorf("%s output leaks canary %q: %q", mode, c, out)
			}
		}
		if strings.Contains(out, "map[") {
			t.Errorf("%s output exposes internal map: %q", mode, out)
		}
	}
}

func TestBundleValueFormatting(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := *b // dereferenced VALUE
	outputs := map[string]string{
		"value-%v":  fmt.Sprintf("%v", v),
		"value-%#v": fmt.Sprintf("%#v", v),
		"value-%s":  fmt.Sprintf("%s", v),
	}
	jb, jerr := json.Marshal(v)
	if jerr != nil {
		t.Fatalf("json.Marshal(value): %v", jerr)
	}
	outputs["value-json"] = string(jb)
	for mode, out := range outputs {
		for _, c := range canaries {
			if strings.Contains(out, c) {
				t.Errorf("%s leaks canary %q: %q", mode, c, out)
			}
		}
	}
}

// TestMaterializeDeepCopy proves the isolation contract: mutating a
// returned asset slice (from the same or an earlier Materialize call)
// must never alter the Bundle. A caller that corrupts or trims its copy
// cannot corrupt the credential material other callers receive.
func TestMaterializeDeepCopy(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	first := b.Materialize()
	if len(first) != 2 {
		t.Fatalf("assets = %d, want 2", len(first))
	}
	// Scribble over every byte of every returned asset.
	for i := range first {
		for j := range first[i].Data {
			first[i].Data[j] = 'X'
		}
	}
	// A second call must still return the pristine originals. Failure
	// messages carry only the fixed destination name and the expected
	// length: asset bytes are secret material and must never appear in
	// test output even on failure.
	second := b.Materialize()
	for _, a := range second {
		switch a.Dest {
		case "gateway.crt":
			if string(a.Data) != certGatewayCanary {
				t.Errorf("gateway.crt corrupted via returned slice (got %d bytes)", len(a.Data))
			}
		case "gateway.key":
			if string(a.Data) != keyGatewayCanary {
				t.Errorf("gateway.key corrupted via returned slice (got %d bytes)", len(a.Data))
			}
		default:
			t.Errorf("unexpected asset %q", a.Dest)
		}
		// The two calls must not share backing arrays.
		for _, f := range first {
			if f.Dest == a.Dest && len(f.Data) > 0 && len(a.Data) > 0 && &f.Data[0] == &a.Data[0] {
				t.Errorf("asset %q shares backing array across Materialize calls", a.Dest)
			}
		}
	}
	// Scalars are unaffected by asset mutation.
	if got, _ := b.Scalar("TROJAN_PASSWORD_1"); got != trojanPC {
		t.Errorf("scalar changed after asset mutation: %q", got)
	}
}

func TestMaterializedAssetOpaque(t *testing.T) {
	a := MaterializedAsset{Dest: "gateway.crt", Data: []byte(certGatewayCanary)}
	outputs := map[string]string{
		"%v":  fmt.Sprintf("%v", a),
		"%+v": fmt.Sprintf("%+v", a),
		"%#v": fmt.Sprintf("%#v", a),
	}
	jb, jerr := json.Marshal(a)
	if jerr != nil {
		t.Fatalf("json.Marshal: %v", jerr)
	}
	outputs["json"] = string(jb)
	for mode, out := range outputs {
		if strings.Contains(out, certGatewayCanary) {
			t.Errorf("%s leaks asset bytes: %q", mode, out)
		}
		if !strings.Contains(out, "gateway.crt") {
			t.Errorf("%s lacks fixed dest name: %q", mode, out)
		}
	}
}

// TestBundleRoleIsFixedIdentity proves Role reports the loaded role as
// a secret-free identity, which is what a consumer uses to refuse a
// bundle belonging to the other role.
func TestBundleRoleIsFixedIdentity(t *testing.T) {
	gateway, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load gateway: %v", err)
	}
	if got := gateway.Role(); got != "gateway" {
		t.Errorf("gateway bundle Role() = %q, want %q", got, "gateway")
	}
	egress, err := load("egress", fakeSource{files: usFakeFiles()})
	if err != nil {
		t.Fatalf("load egress: %v", err)
	}
	if got := egress.Role(); got != "egress" {
		t.Errorf("egress bundle Role() = %q, want %q", got, "egress")
	}
	for _, c := range canaries {
		if strings.Contains(gateway.Role()+egress.Role(), c) {
			t.Errorf("Role() leaks canary %q", c)
		}
	}
}

// TestBundleCloseZeroizesAssetsAndFailsClosed pins the lifecycle
// contract: Close overwrites the asset bytes in place, and every later
// lookup fails closed instead of returning stale material.
func TestBundleCloseZeroizesAssetsAndFailsClosed(t *testing.T) {
	b, err := load("gateway", fakeSource{files: cnFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Keep a reference to the bundle's OWN backing array (not a copy)
	// so the in-place wipe can be observed directly.
	backing := b.assets["gateway.crt"]
	if len(backing) == 0 || string(backing) != certGatewayCanary {
		t.Fatalf("unexpected pre-close asset state (%d bytes)", len(backing))
	}
	// A copy taken before Close must survive it untouched: Materialize
	// deep-copies, so zeroization must not reach into caller material.
	before := b.Materialize()
	if len(before) != 2 {
		t.Fatalf("assets = %d, want 2", len(before))
	}
	preCopy := map[string]string{}
	for _, a := range before {
		preCopy[a.Dest] = string(a.Data)
	}

	b.Close()

	for i, c := range backing {
		if c != 0 {
			t.Fatalf("asset byte %d was not zeroized after Close", i)
		}
	}
	if got, ok := b.Scalar("GATEWAY_EGRESS_PASSWORD_1"); ok {
		t.Errorf("Scalar after Close = %q, ok=true; want fail-closed", got)
	}
	if n := len(b.Materialize()); n != 0 {
		t.Errorf("Materialize after Close returned %d assets, want 0", n)
	}
	if n := len(b.OptionalLoaded()); n != 0 {
		t.Errorf("OptionalLoaded after Close = %d, want 0", n)
	}
	// The pre-close copies are intact (no unsafe aliasing).
	if preCopy["gateway.crt"] != certGatewayCanary || preCopy["gateway.key"] != keyGatewayCanary {
		t.Error("Close corrupted material a caller had already copied")
	}
	// Summary stays secret-free and states the closed state.
	sum := b.Summary()
	if !strings.Contains(sum, "closed") {
		t.Errorf("Summary after Close = %q, want it to state closed", sum)
	}
	for _, c := range canaries {
		if strings.Contains(sum, c) {
			t.Errorf("Summary after Close leaks canary %q: %q", c, sum)
		}
	}
}

// TestBundleCloseIsIdempotent proves repeated Close (and Close on a nil
// bundle) is safe, so callers can defer it unconditionally.
func TestBundleCloseIsIdempotent(t *testing.T) {
	b, err := load("egress", fakeSource{files: usFakeFiles()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b.Close()
	b.Close()
	b.Close()
	if _, ok := b.Scalar("GATEWAY_EGRESS_PASSWORD_1"); ok {
		t.Error("Scalar resolved after repeated Close")
	}
	var nilBundle *Bundle
	nilBundle.Close() // must not panic
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 5: "5", 12345: "12345"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestQuoteASCII(t *testing.T) {
	if got := quoteASCII("gateway.crt"); got != `"gateway.crt"` {
		t.Errorf("quoteASCII = %q", got)
	}
	if got := quoteASCII(`a"b`); got != `"a\"b"` {
		t.Errorf("quoteASCII escape = %q", got)
	}
}
