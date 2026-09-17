package render

import (
	"strings"
	"testing"

	"proxyctl/internal/credential"
)

// Synthetic credential material for render tests. These are SYNTHETIC
// canaries, never real secrets: every value is a distinctive string so
// a test can prove it does NOT appear in stdout, stderr, JSON or any
// error message.
const (
	synthGatewayEgressPassword = "SYNTH-CANARY-cnus-pass-1a2b"
	synthTrojanUser            = "SYNTH-CANARY-trojan-user-3c4d"
	synthTrojanPass            = "SYNTH-CANARY-trojan-pass-5e6f"
	synthHTTPSUser             = "SYNTH-CANARY-https-user-7a8b"
	synthHTTPSPass             = "SYNTH-CANARY-https-pass-9c0d"
	synthGatewayCrt            = "SYNTH-CANARY-gateway-crt-body-e1f2"
	synthGatewayKey            = "SYNTH-CANARY-gateway-key-body-a3b4"
	synthEgressCrt             = "SYNTH-CANARY-egress-crt-body-c5d6"
	synthEgressKey             = "SYNTH-CANARY-egress-key-body-e7f8"
	synthGatewayClientCrt      = "SYNTH-CANARY-gateway-client-crt-1122"
	synthGatewayClientKey      = "SYNTH-CANARY-gateway-client-key-3344"
	synthGatewayClientCA       = "SYNTH-CANARY-gateway-client-ca-5566"
)

// synthSecrets lists every synthetic secret byte string. A render's
// output, JSON and errors are checked against this list.
var synthSecrets = []string{
	synthGatewayEgressPassword, synthTrojanUser, synthTrojanPass,
	synthHTTPSUser, synthHTTPSPass,
	synthGatewayCrt, synthGatewayKey, synthEgressCrt, synthEgressKey,
	synthGatewayClientCrt, synthGatewayClientKey, synthGatewayClientCA,
}

// synthBundle is a pure in-memory Bundle: no filesystem, no
// environment, no network. It mirrors the production bundle's contract
// closely enough to be a faithful stand-in, including the fixed
// GATEWAY_NODE_PASSWORD_1 -> GATEWAY_EGRESS_PASSWORD_1 alias and fail-closed
// behavior after Close.
type synthBundle struct {
	role    string
	scalars map[string]string
	assets  map[string][]byte
	// closed records Close; closes counts the calls so a test can
	// prove Close ran exactly once per render and is idempotent.
	closed bool
	closes int
	// handedOut keeps, by reference, every slice Materialize returned,
	// so a test can assert render zeroed the whole batch. Keyed by
	// destination name.
	handedOut map[string][]byte
	// handedSlices records the same slices PER ENTRY, in batch order. A
	// duplicate-name batch carries two distinct slices under one name,
	// and both must be observable.
	handedSlices []handedSlice
	// handOutOrdered, when set, is returned verbatim by Materialize in
	// the given order (see Materialize).
	handOutOrdered []credential.MaterializedAsset
}

// handedSlice is one slice Materialize handed out, in batch order.
type handedSlice struct {
	name string
	data []byte
}

// Scalar resolves an allowlisted placeholder, applying the fixed legacy
// alias, and fails closed after Close.
func (b *synthBundle) Scalar(placeholder string) (string, bool) {
	if b.closed {
		return "", false
	}
	if placeholder == "GATEWAY_NODE_PASSWORD_1" {
		placeholder = "GATEWAY_EGRESS_PASSWORD_1"
	}
	v, ok := b.scalars[placeholder]
	return v, ok
}

// Materialize returns deep copies in deterministic name order, and
// nothing after Close (mirroring the production contract).
//
// Every slice handed out is also recorded in handedOut, keyed by
// destination name and KEPT BY REFERENCE (never copied), so a test can
// observe whether render zeroed the very batch it received — including
// the assets an early return never inserted into the publication set.
func (b *synthBundle) Materialize() []credential.MaterializedAsset {
	if b.closed {
		return nil
	}
	if b.handOutOrdered != nil {
		// Explicit, caller-controlled batch. Used by tests that must hit
		// a SPECIFIC branch of the asset-validation loop in a SPECIFIC
		// position (the map-based path below is sorted by name, which
		// cannot express "a duplicate of an already-inserted name").
		// Entries are returned as supplied; handedOut still records the
		// slices by reference so zeroing stays observable.
		if b.handedOut == nil {
			b.handedOut = map[string][]byte{}
		}
		b.handedSlices = b.handedSlices[:0]
		for i := range b.handOutOrdered {
			d := b.handOutOrdered[i]
			b.handedOut[d.Dest] = d.Data
			// Recorded per ENTRY, not per name: a duplicate-name batch
			// has two distinct slices under one name, and both must be
			// observable to prove both were zeroed.
			b.handedSlices = append(b.handedSlices, handedSlice{name: d.Dest, data: d.Data})
		}
		return b.handOutOrdered
	}
	names := make([]string, 0, len(b.assets))
	for n := range b.assets {
		names = append(names, n)
	}
	// Insertion sort: deterministic order without pulling in sort.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	if b.handedOut == nil {
		b.handedOut = map[string][]byte{}
	}
	out := make([]credential.MaterializedAsset, 0, len(names))
	b.handedSlices = b.handedSlices[:0]
	for _, n := range names {
		data := append([]byte(nil), b.assets[n]...)
		b.handedOut[n] = data // same backing array, by reference
		b.handedSlices = append(b.handedSlices, handedSlice{name: n, data: data})
		out = append(out, credential.MaterializedAsset{Dest: n, Data: data})
	}
	return out
}

// withOrderedAssets makes Materialize return exactly the given batch, in
// the given order, instead of the name-sorted map contents. Duplicated
// destination names are therefore expressible, which is what the
// duplicate-asset branch needs.
func (b *synthBundle) withOrderedAssets(assets ...credential.MaterializedAsset) *synthBundle {
	b.handOutOrdered = assets
	return b
}

// asset is a shorthand for building a MaterializedAsset in a test.
func asset(dest, data string) credential.MaterializedAsset {
	return credential.MaterializedAsset{Dest: dest, Data: []byte(data)}
}

// assertHandedOutZeroed fails unless every slice Materialize handed out
// has been fully zeroed. It reports only the destination name and the
// offending index — never the bytes, which are (synthetic) secrets.
func (b *synthBundle) assertHandedOutZeroed(t *testing.T, what string) {
	t.Helper()
	if len(b.handedOut) == 0 {
		t.Fatalf("%s: test premise broken: Materialize handed out nothing", what)
	}
	for name, data := range b.handedOut {
		for i, c := range data {
			if c != 0 {
				t.Errorf("%s: asset %q was not zeroed (byte %d of %d non-zero)",
					what, name, i, len(data))
				break
			}
		}
	}
}

// assertEveryHandedSliceZeroed is the per-ENTRY form: it walks the batch
// in order and checks every slice individually, so a duplicate-name batch
// (two distinct slices under one name) is fully covered — the map-based
// assertHandedOutZeroed would only see the last slice per name.
//
// minEntries guards against a vacuous pass: the caller declares how many
// entries the batch must have contained for the scenario to mean
// anything (the triggering entry plus at least one unvisited
// subsequent entry).
func (b *synthBundle) assertEveryHandedSliceZeroed(t *testing.T, what string, minEntries int) {
	t.Helper()
	if len(b.handedSlices) < minEntries {
		t.Fatalf("%s: test premise broken: batch has %d entries, want at least %d",
			what, len(b.handedSlices), minEntries)
	}
	for k, h := range b.handedSlices {
		for i, c := range h.data {
			if c != 0 {
				t.Errorf("%s: batch entry %d (%q) was not zeroed (byte %d of %d non-zero)",
					what, k, h.name, i, len(h.data))
				break
			}
		}
	}
}

func (b *synthBundle) Role() string { return b.role }

func (b *synthBundle) Close() {
	b.closes++
	b.closed = true
}

// synthGateway returns a complete, well-formed gateway bundle.
func synthGateway() *synthBundle {
	return &synthBundle{
		role: "gateway",
		scalars: map[string]string{
			"GATEWAY_EGRESS_PASSWORD_1": synthGatewayEgressPassword,
			"TROJAN_USER_1":             synthTrojanUser,
			"TROJAN_PASSWORD_1":         synthTrojanPass,
			"HTTPS_USER_1":              synthHTTPSUser,
			"HTTPS_PASSWORD_1":          synthHTTPSPass,
		},
		assets: map[string][]byte{
			"gateway.crt": []byte(synthGatewayCrt),
			"gateway.key": []byte(synthGatewayKey),
		},
	}
}

// synthEgress returns a complete, well-formed egress bundle.
func synthEgress() *synthBundle {
	return &synthBundle{
		role: "egress",
		scalars: map[string]string{
			"GATEWAY_EGRESS_PASSWORD_1": synthGatewayEgressPassword,
		},
		assets: map[string][]byte{
			"egress.crt": []byte(synthEgressCrt),
			"egress.key": []byte(synthEgressKey),
		},
	}
}

// synthLoader is an injectable Loader returning a fixed bundle or a
// fixed error. loads counts invocations.
type synthLoader struct {
	bundle Bundle
	err    error
	loads  int
	// gotRole records the role the loader was asked for, so a test can
	// prove render passes the VALIDATED role through unchanged.
	gotRole string
}

func (l *synthLoader) Load(role string) (Bundle, error) {
	l.loads++
	l.gotRole = role
	if l.err != nil {
		return nil, l.err
	}
	return l.bundle, nil
}

// renderFixture wires a complete synthetic render: the real repository
// template and config fixture, an injected bundle, and the in-memory
// publication backend so the FULL pipeline runs on every platform
// (the production backend fails closed off Linux by design).
type renderFixture struct {
	opts   Options
	loader *synthLoader
	fb     *fakeBackend
}

// newRenderFixture builds a fixture for role with the given bundle.
func newRenderFixture(t *testing.T, role, tmplSub, configFixture string, b Bundle) *renderFixture {
	t.Helper()
	fb, _ := newFakeBackend(outputDirPerm)
	backendCopy := fb.backend()
	loader := &synthLoader{bundle: b}
	return &renderFixture{
		loader: loader,
		fb:     fb,
		opts: Options{
			Role:        role,
			TemplateDir: tmplDir(t, tmplSub),
			ConfigPath:  fixturePath(t, configFixture),
			OutDir:      "out",
			Loader:      loader,
			writer:      &backendCopy,
		},
	}
}

// run executes the render.
func (f *renderFixture) run() (*Result, error) { return Run(f.opts) }

// published returns the published output names in sorted order.
func (f *renderFixture) published() []string { return f.fb.names() }

// content returns the published bytes of one output name.
func (f *renderFixture) content(name string) string { return f.fb.content(name) }

// assertNoSynthSecretLeak fails when any synthetic secret appears in s.
func assertNoSynthSecretLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, secret := range synthSecrets {
		if strings.Contains(s, secret) {
			t.Errorf("%s leaks synthetic secret %q", what, secret)
		}
	}
}
