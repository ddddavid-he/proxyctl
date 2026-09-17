//go:build linux

package credential

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Deterministic TOCTOU regression for the single-held-descriptor
// design. The afterOpen test hook (export_test.go, test binary only)
// swaps the unit directory's on-disk PATH after the descriptor has
// been opened and verified but before any credential is read; every
// read is descriptor-relative, so the held descriptor — never the
// swapped path — governs what is read. Helpers (writeCred, ...) live
// in credential_linux_test.go.

// --- deterministic after-open swap regression -----------------------------

// TestFSAfterOpenSwapUsesHeldFD is the deterministic TOCTOU regression
// for the single-held-descriptor design: the afterOpen hook swaps the
// unit directory's on-disk PATH (rename original away, symlink a
// different directory into place) AFTER the directory descriptor has
// been opened and verified, but BEFORE any credential is read. Because
// every read is relative to the held descriptor, the load must either
// succeed with the ORIGINAL content or fail — it must never read from
// the attacker's swapped-in directory.
func TestFSAfterOpenSwapUsesHeldFD(t *testing.T) {
	base := t.TempDir()
	unit := filepath.Join(base, "unit")
	if err := os.MkdirAll(unit, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCred(t, unit, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
	writeCred(t, unit, "egress.crt", certEgressCanary)
	writeCred(t, unit, "egress.key", keyEgressCanary)

	// Attacker directory with different content.
	evil := t.TempDir()
	writeCred(t, evil, "GATEWAY_EGRESS_PASSWORD_1", "cw-evil-swap-0001")
	writeCred(t, evil, "egress.crt", "cw-evil-crt-0002")
	writeCred(t, evil, "egress.key", "cw-evil-key-0003")

	src := newSystemdSource(base, func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return unit
		}
		return ""
	})
	// Swap AFTER open, BEFORE reads: move the real dir aside and put a
	// symlink to evil in its place.
	src.afterOpen = func() {
		moved := filepath.Join(base, "unit-moved")
		if err := os.Rename(unit, moved); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if err := os.Symlink(evil, unit); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}

	b, err := load("egress", src)
	if err != nil {
		// Failing closed is acceptable; leaking attacker content is not.
		assertNoLeak(t, err)
		if strings.Contains(fmt.Sprint(err), "cw-evil-swap-0001") {
			t.Fatalf("error leaks attacker content: %v", err)
		}
		return
	}
	// Success path: the content must be the ORIGINAL, never the
	// attacker's.
	got, ok := b.Scalar("GATEWAY_EGRESS_PASSWORD_1")
	if !ok || got != gatewayEgressCanary {
		t.Fatalf("after-open swap read wrong content: %q,%v", got, ok)
	}
	if got == "cw-evil-swap-0001" {
		t.Fatalf("load read attacker directory after path swap")
	}
	for _, a := range b.Materialize() {
		if strings.Contains(string(a.Data), "cw-evil") {
			t.Fatalf("asset %s read attacker content after swap", a.Dest)
		}
	}
}
