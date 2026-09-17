//go:build linux

package render

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"proxyctl/internal/safex"
)

// chdirForTest points the process working directory at dir for the
// duration of the test and restores it afterwards. The relative-path
// anchor is process state, so these tests must not run in parallel with
// anything else in the package (none of them calls t.Parallel).
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore chdir: %v", err)
		}
	})
}

// Real-filesystem regressions for the production Linux backend's
// component-by-component path walk (openOutputDirLinux). They run only
// on Linux because they exercise the production syscall path itself;
// the platform-independent contracts are pinned by the fake-backend
// tests in writer_test.go.

// TestOpenOutputDirRejectsIntermediateSymlink is the reason the walk
// exists: a single open(path, O_NOFOLLOW|O_DIRECTORY) refuses a
// symlink only at the FINAL component, so an INTERMEDIATE symlink is
// followed silently and the whole bundle lands in the attacker's
// directory. The walk must refuse it.
func TestOpenOutputDirRejectsIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	// real/out is the legitimate 0700 output directory.
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	// link -> real, so link/out resolves to real/out through an
	// INTERMEDIATE symlink.
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink not supported")
	}
	via := filepath.Join(link, "out")
	// Sanity: the path really does resolve (the refusal below is the
	// walk's decision, not a missing directory).
	if fi, err := os.Stat(via); err != nil || !fi.IsDir() {
		t.Fatalf("stat %s: %v", via, err)
	}
	h, err := openOutputDirLinux(via)
	if err == nil {
		closeDirLinux(h)
		t.Fatal("openOutputDirLinux followed an intermediate symlink")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)

	// End to end: nothing may be written through the symlinked path.
	werr := writeTransaction(via, writerFiles())
	requireFixedMessage(t, werr, safex.RenderUnsafe)
	assertFS(t, filepath.Join(real, "out"), map[string]string{})
}

// TestOpenOutputDirRejectsDeepIntermediateSymlink pins the walk at
// every depth, including a symlink several components above the target
// and a symlink that is itself reached through another directory.
func TestOpenOutputDirRejectsDeepIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target", "a", "b")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(base, "mid")
	if err := os.Mkdir(mid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "target"), filepath.Join(mid, "hop")); err != nil {
		t.Skip("symlink not supported")
	}
	// base/mid/hop/a/b: the symlink is three components from the end.
	via := filepath.Join(mid, "hop", "a", "b")
	h, err := openOutputDirLinux(via)
	if err == nil {
		closeDirLinux(h)
		t.Fatal("openOutputDirLinux followed a deep intermediate symlink")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)
	requireFixedMessage(t, writeTransaction(via, writerFiles()), safex.RenderUnsafe)
	assertFS(t, target, map[string]string{})
}

// TestOpenOutputDirAcceptsDeepRealPath proves the walk is not simply
// refusing everything: a fully symlink-free absolute path with several
// components is accepted and the transaction publishes into it.
func TestOpenOutputDirAcceptsDeepRealPath(t *testing.T) {
	base := t.TempDir()
	// Only the final directory must be 0700; the walk requires the
	// intermediates to be real directories, not a particular mode.
	deep := filepath.Join(base, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	h, err := openOutputDirLinux(deep)
	if err != nil {
		t.Fatalf("openOutputDirLinux(%s): %v", deep, err)
	}
	closeDirLinux(h)
	files := writerFiles()
	if err := writeTransaction(deep, files); err != nil {
		t.Fatalf("writeTransaction: %v", err)
	}
	want := map[string]string{}
	for n, b := range files {
		want[n] = string(b)
	}
	assertFS(t, deep, want)
}

// TestOpenOutputDirRelativePathUsesWorkingDir pins the relative-path
// anchor: a relative output dir is resolved against the working
// directory, component by component, with the same no-symlink rule.
func TestOpenOutputDirRelativePathUsesWorkingDir(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "nested", "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	chdirForTest(t, base)

	files := writerFiles()
	if err := writeTransaction(filepath.Join("nested", "out"), files); err != nil {
		t.Fatalf("relative writeTransaction: %v", err)
	}
	want := map[string]string{}
	for n, b := range files {
		want[n] = string(b)
	}
	assertFS(t, filepath.Join(base, "nested", "out"), want)

	// "./" and doubled separators are pure syntax and must resolve to
	// the same directory, not be treated as components.
	if err := os.Mkdir(filepath.Join(base, "second"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeTransaction("./second//", files); err != nil {
		t.Fatalf("dot-relative writeTransaction: %v", err)
	}
	assertFS(t, filepath.Join(base, "second"), want)
}

// TestOpenOutputDirRelativeRejectsIntermediateSymlink is the relative
// twin of the intermediate-symlink refusal.
func TestOpenOutputDirRelativeRejectsIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Skip("symlink not supported")
	}
	chdirForTest(t, base)

	h, err := openOutputDirLinux(filepath.Join("link", "out"))
	if err == nil {
		closeDirLinux(h)
		t.Fatal("relative walk followed an intermediate symlink")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)
	requireFixedMessage(t, writeTransaction("link/out", writerFiles()), safex.RenderUnsafe)
	assertFS(t, filepath.Join(real, "out"), map[string]string{})
}

// TestOpenOutputDirRejectsTraversalComponent pins the ".." refusal at
// the backend itself (writeTransactionWithBackend also rejects it, so
// the guarantee does not depend on one layer). A traversal component is
// never resolved, even when the resulting directory would be valid.
func TestOpenOutputDirRejectsTraversalComponent(t *testing.T) {
	base := t.TempDir()
	out := filepath.Join(base, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "side"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The paths are concatenated by hand: filepath.Join would Clean
	// ".." away, and the point of the test is that the walk receives
	// the traversal component verbatim and refuses it.
	for _, p := range []string{
		base + "/side/../out",
		base + "/../" + filepath.Base(base) + "/out",
		base + "/out/..",
		"..",
	} {
		h, err := openOutputDirLinux(p)
		if err == nil {
			closeDirLinux(h)
			t.Fatalf("openOutputDirLinux resolved a traversal component: %s", p)
		}
		requireFixedMessage(t, err, safex.RenderUnsafe)
	}
	assertFS(t, out, map[string]string{})
}

// TestOpenOutputDirRejectsFinalSymlinkAndNonDir keeps the final
// component's rules intact after the walk change: a symlinked or
// non-directory final component is refused, and a missing one is
// not-found.
func TestOpenOutputDirRejectsFinalSymlinkAndNonDir(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink not supported")
	}
	h, err := openOutputDirLinux(link)
	if err == nil {
		closeDirLinux(h)
		t.Fatal("final symlink accepted")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)

	plain := filepath.Join(base, "file")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err = openOutputDirLinux(plain)
	if err == nil {
		closeDirLinux(h)
		t.Fatal("non-directory accepted")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)

	h, err = openOutputDirLinux(filepath.Join(base, "missing"))
	if err == nil {
		closeDirLinux(h)
		t.Fatal("missing directory accepted")
	}
	requireFixedMessage(t, err, safex.CodeNotFound)

	// A non-directory INTERMEDIATE component is refused too.
	h, err = openOutputDirLinux(filepath.Join(plain, "out"))
	if err == nil {
		closeDirLinux(h)
		t.Fatal("non-directory intermediate accepted")
	}
	requireFixedMessage(t, err, safex.RenderUnsafe)
}

// TestOpenOutputDirEnforcesFinalPermOnHeldFD pins the 0700 check after
// the walk: it is decided by the fstat of the final held descriptor.
func TestOpenOutputDirEnforcesFinalPermOnHeldFD(t *testing.T) {
	base := t.TempDir()
	for _, mode := range []os.FileMode{0o755, 0o770, 0o777, 0o750, 0o600} {
		dir := filepath.Join(base, fmt.Sprintf("d%o", mode))
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		// Mkdir is umask-filtered; force the exact mode.
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		h, err := openOutputDirLinux(dir)
		if err == nil {
			closeDirLinux(h)
			t.Fatalf("mode %o accepted", mode)
		}
		requireFixedMessage(t, err, safex.RenderUnsafe)
	}
}

// TestWriteTransactionRetainsPublishedOnRealFS is guarantee 3 on the
// real filesystem: a midway publish failure leaves every already
// published final file on disk, byte-for-byte, and returns the fixed
// bundle-state-undefined error.
func TestWriteTransactionRetainsPublishedOnRealFS(t *testing.T) {
	dir := newOutDir(t)
	files := writerFiles()
	prod := defaultBackend()
	basePublish := prod.publish
	// Fail the publish of egress.crt (the fifth name in the fixed order),
	// so the four before it are genuinely published on disk first.
	prod.publish = func(d, staging *dirHandle, name string) (bool, error) {
		if name == "egress.crt" {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		return basePublish(d, staging, name)
	}
	err := writeTransactionWithBackend(dir, files, prod)
	requireBundleStateUndefined(t, err)

	want := map[string]string{}
	for _, name := range outputNameOrder {
		if name == "egress.crt" {
			break
		}
		want[name] = string(files[name])
	}
	if len(want) == 0 {
		t.Fatal("test setup published nothing")
	}
	// Published finals retained, nothing after the failure point
	// present, and no staging residue (assertFS checks the prefix).
	assertFS(t, dir, want)
	for _, name := range []string{"egress.crt", "egress.key", "gateway-client.crt"} {
		if _, serr := os.Lstat(filepath.Join(dir, name)); serr == nil {
			t.Errorf("%s must not exist: its publish never ran", name)
		}
	}
}

// TestWriteTransactionUnlinkFailureRetainsPublishedOnRealFS drives the
// genuine link-success / unlink-failure split through the production
// primitive: the staging directory is made non-writable right before
// publishLinux runs, so its linkat succeeds (the output dir is still
// writable) and its own unlinkat of the staging link then fails with
// EACCES. publishLinux must report (true, error), the transaction must
// record the final name as published, and rollback must retain it.
func TestWriteTransactionUnlinkFailureRetainsPublishedOnRealFS(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny the unlink")
	}
	dir := newOutDir(t)
	// The staging dir is left non-writable by the failure under test, so
	// TempDir's own cleanup could not remove it: restore 0700 first.
	t.Cleanup(func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), stagingPrefix) {
				os.Chmod(filepath.Join(dir, e.Name()), 0o700)
			}
		}
	})
	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " gateway.crt\n"),
		"gateway.key": []byte(writerCanary + " gateway.key\n"),
	}
	prod := defaultBackend()
	basePublish := prod.publish
	var linkedReported bool
	prod.publish = func(d, staging *dirHandle, name string) (bool, error) {
		if name != "gateway.crt" {
			return basePublish(d, staging, name)
		}
		// Drop write permission on the staging directory itself, via
		// its held descriptor: linkat still resolves the source (search
		// permission is enough) but unlinkat needs write.
		if err := syscall.Fchmod(staging.fd, 0o500); err != nil {
			t.Fatalf("fchmod: %v", err)
		}
		linked, perr := basePublish(d, staging, name)
		if perr == nil {
			t.Fatal("staging unlink must fail on a non-writable staging dir")
		}
		if !linked {
			t.Error("publishLinux reported linked = false after linkat succeeded")
		}
		linkedReported = linked
		return linked, perr
	}
	err := writeTransactionWithBackend(dir, files, prod)
	requireBundleStateUndefined(t, err)
	if !linkedReported {
		t.Fatal("the link-success / unlink-failure path was not exercised")
	}
	// gateway.crt exists with the intended content: it was published, so it
	// is retained, never deleted.
	got, rerr := os.ReadFile(filepath.Join(dir, "gateway.crt"))
	if rerr != nil {
		t.Fatalf("published gateway.crt was deleted: %v", rerr)
	}
	if string(got) != string(files["gateway.crt"]) {
		t.Errorf("gateway.crt = %q, want %q", got, files["gateway.crt"])
	}
}

// TestPublishLinuxReportsLinkedOnUnlinkFailure pins the production
// primitive's two-value contract directly: after linkat succeeds the
// bool is true even when the staging unlink fails.
func TestPublishLinuxReportsLinkedOnUnlinkFailure(t *testing.T) {
	dir := newOutDir(t)
	h, err := openOutputDirLinux(dir)
	if err != nil {
		t.Fatalf("openOutputDirLinux: %v", err)
	}
	defer closeDirLinux(h)
	stagingName := stagingPrefix + "test"
	if err := mkdirAtLinux(h, stagingName, outputDirPerm); err != nil {
		t.Fatalf("mkdirAt: %v", err)
	}
	sh, err := openSubdirLinux(h, stagingName)
	if err != nil {
		t.Fatalf("openSubdir: %v", err)
	}
	defer closeDirLinux(sh)
	f, _, err := createAtLinux(sh, "gateway.crt", outputFilePerm)
	if err != nil {
		t.Fatalf("createAt: %v", err)
	}
	if err := f.write([]byte(writerCanary)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Link the final name, then remove the staging link so
	// publishLinux's linkat fails with EEXIST — the "not linked by egress"
	// case, which must report false.
	if err := linkatLinux(sh.fd, "gateway.crt", h.fd, "gateway.crt", 0); err != nil {
		t.Fatalf("linkat: %v", err)
	}
	linked, perr := publishLinux(h, sh, "gateway.crt")
	if perr == nil {
		t.Fatal("publish onto an existing final name must fail")
	}
	if linked {
		t.Error("publish reported linked = true for a refused (EEXIST) link")
	}

	// The positive half: a fresh name whose linkat succeeds while the
	// staging unlink is denied must report (true, error), and the final
	// link must survive.
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny the unlink")
	}
	f2, _, err := createAtLinux(sh, "gateway.key", outputFilePerm)
	if err != nil {
		t.Fatalf("createAt: %v", err)
	}
	if err := f2.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Denying write on the staging directory leaves linkat's source
	// lookup working (search permission) but blocks unlinkat.
	if err := syscall.Fchmod(sh.fd, 0o500); err != nil {
		t.Fatalf("fchmod: %v", err)
	}
	// Restore permissions while sh is still open. t.Cleanup runs after
	// deferred descriptor closure, so using it here leaves the staging
	// directory non-writable and makes TempDir cleanup fail on Linux.
	defer func() {
		if err := syscall.Fchmod(sh.fd, 0o700); err != nil {
			t.Errorf("restore staging permissions: %v", err)
		}
	}()
	linked, perr = publishLinux(h, sh, "gateway.key")
	if !linked {
		t.Error("publish reported linked = false after linkat created the final name")
	}
	if perr == nil {
		t.Error("publish must report the staging unlink failure")
	}
	if _, err := os.Lstat(filepath.Join(dir, "gateway.key")); err != nil {
		t.Fatalf("final gateway.key must exist and stay: %v", err)
	}
}

// TestOpenOutputDirDoesNotLeakDescriptors walks a deep path many times
// and asserts the process descriptor count does not grow: only the
// deepest descriptor is retained, every parent is closed.
func TestOpenOutputDirDoesNotLeakDescriptors(t *testing.T) {
	base := t.TempDir()
	deep := filepath.Join(base, "a", "b", "c", "d")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	openFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("/proc/self/fd unavailable: %v", err)
		}
		return len(entries)
	}
	// Warm up so one-off runtime descriptors are not counted.
	for i := 0; i < 8; i++ {
		h, err := openOutputDirLinux(deep)
		if err != nil {
			t.Fatalf("openOutputDirLinux: %v", err)
		}
		closeDirLinux(h)
	}
	before := openFDs()
	for i := 0; i < 64; i++ {
		h, err := openOutputDirLinux(deep)
		if err != nil {
			t.Fatalf("openOutputDirLinux: %v", err)
		}
		closeDirLinux(h)
		// Failure paths must not leak either.
		if _, err := openOutputDirLinux(filepath.Join(deep, "missing")); err == nil {
			t.Fatal("missing directory accepted")
		}
	}
	if after := openFDs(); after > before+2 {
		t.Errorf("descriptor count grew from %d to %d (leak)", before, after)
	}
}
