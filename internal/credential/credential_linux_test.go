//go:build linux

package credential

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"proxyctl/internal/safex"
)

// Filesystem-backed tests for the real Linux descriptor source. These
// exercise the production code paths (openat/O_NOFOLLOW, permissions,
// confinement, swap regression) against isolated t.TempDir() trees.

// Filesystem-backed tests for the real Linux descriptor source. These
// exercise the production code paths (openat/O_NOFOLLOW, permissions,
// confinement, swap regression) against isolated t.TempDir() trees.

// writeCred creates one credential file with restrictive permissions.
func writeCred(t *testing.T, dir, name, content string) {
	t.Helper()
	writeCredMode(t, dir, name, content, 0o600)
}

func writeCredMode(t *testing.T, dir, name, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
}

// makeGatewayRoot builds an isolated root with a complete gateway credential dir.
func makeGatewayRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "private-proxy-mihomo.service")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCred(t, dir, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
	writeCred(t, dir, "TROJAN_USER_1", trojanUC)
	writeCred(t, dir, "TROJAN_PASSWORD_1", trojanPC)
	writeCred(t, dir, "HTTPS_USER_1", httpsUC)
	writeCred(t, dir, "HTTPS_PASSWORD_1", httpsPC)
	writeCred(t, dir, "HTTPS_USER_2", httpsUC2)
	writeCred(t, dir, "HTTPS_PASSWORD_2", httpsPC2)
	writeCred(t, dir, "gateway.crt", certGatewayCanary)
	writeCred(t, dir, "gateway.key", keyGatewayCanary)
	return root, dir
}

// makeEgressRoot builds an isolated root with a complete egress credential dir.
func makeEgressRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "private-proxy-hysteria.service")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCred(t, dir, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
	writeCred(t, dir, "egress.crt", certEgressCanary)
	writeCred(t, dir, "egress.key", keyEgressCanary)
	return root, dir
}

// --- happy path through the real filesystem source -------------------

func TestFSLoadGatewayHappy(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	b, err := loadFromTestRoot("gateway", root, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, ok := b.Scalar("TROJAN_PASSWORD_1"); !ok || got != trojanPC {
		t.Errorf("Scalar(TROJAN_PASSWORD_1) = %q,%v", got, ok)
	}
	if n := len(b.Materialize()); n != 2 {
		t.Errorf("assets = %d, want 2", n)
	}
}

// --- root validation -------------------------------------------------

func TestFSRootUnsetRejected(t *testing.T) {
	root := t.TempDir()
	_, err := loadFromTestRoot("egress", root, "")
	assertCode(t, err, safex.CodeNotFound)
	assertNoLeak(t, err)
}

func TestFSRootRelativeRejected(t *testing.T) {
	root := t.TempDir()
	_, err := loadFromTestRoot("egress", root, "relative/creds")
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSRootTraversalRejected(t *testing.T) {
	root, _ := makeEgressRoot(t)
	_, err := loadFromTestRoot("egress", root, root+"/../outside")
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSRootOutsideAllowedRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_, err := loadFromTestRoot("egress", root, outside)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSRootNotDirectoryRejected(t *testing.T) {
	root := t.TempDir()
	writeCred(t, root, "afile", "x")
	_, err := loadFromTestRoot("egress", root, filepath.Join(root, "afile"))
	// A file (not a directory) as the credentials directory is unsafe.
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSUnitDirGroupWorldAccessibleRejected(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o705, 0o755} {
		t.Run(fmt.Sprintf("mode-%o", mode), func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "unit")
			if err := os.MkdirAll(dir, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			writeCred(t, dir, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
			writeCred(t, dir, "egress.crt", certEgressCanary)
			writeCred(t, dir, "egress.key", keyEgressCanary)
			_, err := loadFromTestRoot("egress", root, dir)
			assertCode(t, err, safex.CodePermission)
			assertNoLeak(t, err)
		})
	}
}

func TestSystemd257RootOwnedCredentialModesAccepted(t *testing.T) {
	if !secureCredentialMetadata(credentialMetadata{mode: 0o550, uid: 0, gid: 0}, true) {
		t.Fatal("systemd 257 root:root 0550 credential directory rejected")
	}
	if !secureCredentialMetadata(credentialMetadata{mode: 0o440, uid: 0, gid: 0}, false) {
		t.Fatal("systemd 257 root:root 0440 credential file rejected")
	}
}

func TestSystemdCredentialModeExceptionsRemainFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		meta      credentialMetadata
		directory bool
	}{
		{"non-root directory group", credentialMetadata{mode: 0o550, uid: 1000, gid: 1000}, true},
		{"root directory group writable", credentialMetadata{mode: 0o570, uid: 0, gid: 0}, true},
		{"root directory world accessible", credentialMetadata{mode: 0o555, uid: 0, gid: 0}, true},
		{"non-root file group readable", credentialMetadata{mode: 0o440, uid: 1000, gid: 1000}, false},
		{"root file group writable", credentialMetadata{mode: 0o460, uid: 0, gid: 0}, false},
		{"root file world readable", credentialMetadata{mode: 0o444, uid: 0, gid: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if secureCredentialMetadata(tt.meta, tt.directory) {
				t.Fatal("unsafe credential metadata accepted")
			}
		})
	}
}

func TestFSRootAtAllowedRootBoundary(t *testing.T) {
	// CREDENTIALS_DIRECTORY directly equal to the allowed root is
	// refused: the unit dir must be strictly beneath the root.
	root, _ := makeEgressRoot(t)
	dir := root
	writeCred(t, dir, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
	writeCred(t, dir, "egress.crt", certEgressCanary)
	writeCred(t, dir, "egress.key", keyEgressCanary)
	_, err := loadFromTestRoot("egress", root, dir)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

// --- symlinks ----------------------------------------------------------

func TestFSSymlinkFinalComponentRejected(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	target := filepath.Join(t.TempDir(), "real-secret")
	writeCred(t, filepath.Dir(target), filepath.Base(target), "cw-swapped-9911")
	if err := os.Remove(filepath.Join(dir, "gateway.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "gateway.crt")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
	if strings.Contains(fmt.Sprint(err), "cw-swapped-9911") {
		t.Errorf("error leaks swapped target content: %v", err)
	}
}

func TestFSSymlinkIntermediateComponentRejected(t *testing.T) {
	// root/realdir/... holds credentials; root/link -> realdir. Using
	// the symlinked path as CREDENTIALS_DIRECTORY must fail even though
	// it resolves INSIDE the allowed root (no escape).
	base := t.TempDir()
	realDir := filepath.Join(base, "realdir", "unit")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCred(t, realDir, "GATEWAY_EGRESS_PASSWORD_1", gatewayEgressCanary)
	writeCred(t, realDir, "egress.crt", certEgressCanary)
	writeCred(t, realDir, "egress.key", keyEgressCanary)
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "realdir"), link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err := loadFromTestRoot("egress", base, filepath.Join(link, "unit"))
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

// --- permissions ---------------------------------------------------------

func TestFSGroupWorldReadableCredentialRejected(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o777} {
		t.Run(fmt.Sprintf("mode-%o", mode), func(t *testing.T) {
			root, dir := makeGatewayRoot(t)
			writeCredMode(t, dir, "TROJAN_USER_1", trojanUC, mode)
			_, err := loadFromTestRoot("gateway", root, dir)
			assertCode(t, err, safex.CodePermission)
			assertNoLeak(t, err)
		})
	}
}

// --- non-regular / missing -------------------------------------------------

func TestFSNonRegularCredentialRejected(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	sub := filepath.Join(dir, "gateway.crt")
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSMissingRequiredCredential(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	if err := os.Remove(filepath.Join(dir, "TROJAN_PASSWORD_1")); err != nil {
		t.Fatal(err)
	}
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.CodeNotFound)
	assertNoLeak(t, err)
}

// --- duplicates / ambiguity -------------------------------------------------

func TestFSDuplicateCaseCollisionRejected(t *testing.T) {
	root, dir := makeEgressRoot(t)
	// Same name, different ASCII case: ambiguous even though Linux
	// allows both files to exist.
	writeCred(t, dir, "gateway_egress_password_1", "cw-lower-dup-5522")
	_, err := loadFromTestRoot("egress", root, dir)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
	if strings.Contains(fmt.Sprint(err), "cw-lower-dup-5522") {
		t.Errorf("error leaks duplicate file content: %v", err)
	}
}

// --- optional credentials through the filesystem ----------------------------

func TestFSOptionalAbsentOK(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	b, err := loadFromTestRoot("gateway", root, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(b.OptionalLoaded()); n != 0 {
		t.Errorf("optional = %d, want 0", n)
	}
}

func TestFSOptionalPresentLoaded(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	writeCred(t, dir, "gateway-client.crt", optGatewayClientCr)
	b, err := loadFromTestRoot("gateway", root, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	opt := b.OptionalLoaded()
	if len(opt) != 1 || opt[0] != "gateway-client.crt" {
		t.Errorf("optional = %v", opt)
	}
}

func TestFSOptionalBadPermissionFails(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	writeCredMode(t, dir, "gateway-client.crt", optGatewayClientCr, 0o644)
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.CodePermission)
	assertNoLeak(t, err)
}

func TestFSOptionalSymlinkFails(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	target := filepath.Join(t.TempDir(), "target")
	writeCred(t, filepath.Dir(target), filepath.Base(target), optGatewayClientCr)
	if err := os.Symlink(target, filepath.Join(dir, "gateway-client.crt")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.RenderUnsafe)
	assertNoLeak(t, err)
}

func TestFSOptionalOversizeFails(t *testing.T) {
	root, dir := makeGatewayRoot(t)
	writeCred(t, dir, "gateway-client.crt", strings.Repeat("x", maxAssetBytes+1))
	_, err := loadFromTestRoot("gateway", root, dir)
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestFSOptionalEmptyFails(t *testing.T) {
	root, dir := makeEgressRoot(t)
	writeCred(t, dir, "gateway-client-ca.crt", "")
	_, err := loadFromTestRoot("egress", root, dir)
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

// --- bounded enumeration / bounded read work -------------------------------

func TestFSExcessiveEntriesFailClosed(t *testing.T) {
	root, dir := makeEgressRoot(t)
	// Fill the unit directory past the fixed enumeration cap with
	// unrelated entries. The duplicate scan must fail closed with a
	// stable error, and the error must not echo any planted content.
	for i := 0; i < maxCredentialEntries; i++ {
		writeCred(t, dir, fmt.Sprintf("filler-%04d", i), "x")
	}
	_, err := loadFromTestRoot("egress", root, dir)
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestFSReadCapFailsClosed(t *testing.T) {
	// A source whose reads never fail but run past the fixed per-load
	// read cap must be cut off with a stable, canary-free error. The
	// cap is exercised through the production read() counter on the
	// real descriptor source.
	root, dir := makeEgressRoot(t)
	src := newSystemdSource(root, func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return dir
		}
		return ""
	})
	if err := src.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer src.close()
	for i := 0; i < maxCredentialReads; i++ {
		if _, err := src.read("egress.crt"); err != nil {
			t.Fatalf("read %d within cap failed: %v", i, err)
		}
	}
	_, err := src.read("egress.crt")
	assertCode(t, err, safex.CodeConfigRejected)
	assertNoLeak(t, err)
}

func TestFSShrinkAfterOpenReadsBounded(t *testing.T) {
	// A credential file shrunk (rewritten shorter) between the
	// directory open and the file read must yield exactly the new,
	// shorter content or fail closed (bounded read): never hang, never
	// return stale/garbage bytes, and never leak partial content into
	// an error.
	root, dir := makeEgressRoot(t)
	writeCred(t, dir, "gateway-client-ca.crt", strings.Repeat("y", 4096))
	src := newSystemdSource(root, func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return dir
		}
		return ""
	})
	if err := src.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer src.close()
	// Rewrite the on-disk file to a single byte AFTER the directory
	// descriptor is held; the read path opens by name relative to the
	// held descriptor, so it sees the shrunk file and must return
	// exactly the bounded content or fail — never garbage.
	if err := os.WriteFile(filepath.Join(dir, "gateway-client-ca.crt"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := src.read("gateway-client-ca.crt")
	if err != nil {
		assertNoLeak(t, err)
		return
	}
	if string(data) != "y" {
		t.Fatalf("read after shrink returned unexpected %d bytes", len(data))
	}
}

// --- no-follow open primitive --------------------------------------------

func TestFSOpenDirNoFollowRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	d, err := openDirNoFollow(-1, link)
	if err == nil {
		d.close()
		t.Fatalf("openDirNoFollow followed a symlink")
	}
	// Symlinked directory component: ENOTDIR/ELOOP -> RenderUnsafe.
	assertCode(t, err, safex.RenderUnsafe)
}

func TestFSOpenDirNoFollowOpensRealDir(t *testing.T) {
	base := t.TempDir()
	d, err := openDirNoFollow(-1, base)
	if err != nil {
		t.Fatalf("openDirNoFollow: %v", err)
	}
	defer d.close()
}

// --- error classification ------------------------------------------------

// TestMapErrnoClassification pins the errno->stable-code contract at
// the unit level, per operation context. Directory open: only ENOENT
// is not-found; ENOTDIR/ELOOP are unsafe. File open: ENOENT/ENOTDIR
// are not-found; ELOOP is unsafe. Permission is distinct in both.
func TestMapErrnoClassification(t *testing.T) {
	dirCases := []struct {
		err  error
		want safex.Code
	}{
		{syscall.ENOENT, safex.CodeNotFound},
		{syscall.ENOTDIR, safex.RenderUnsafe},
		{syscall.ELOOP, safex.RenderUnsafe},
		{syscall.EACCES, safex.CodePermission},
		{syscall.EPERM, safex.CodePermission},
		{syscall.EIO, safex.CodeIO},
	}
	for _, c := range dirCases {
		got := mapDirOpenErrno(c.err)
		se, ok := got.(*safex.Error)
		if !ok || se.Code != c.want {
			t.Errorf("mapDirOpenErrno(%v) code = %v, want %s", c.err, got, c.want)
		}
		assertNoLeak(t, got)
	}
	fileCases := []struct {
		err  error
		want safex.Code
	}{
		{syscall.ENOENT, safex.CodeNotFound},
		{syscall.ENOTDIR, safex.CodeNotFound},
		{syscall.ELOOP, safex.RenderUnsafe},
		{syscall.EACCES, safex.CodePermission},
		{syscall.EPERM, safex.CodePermission},
		{syscall.EIO, safex.CodeIO},
	}
	for _, c := range fileCases {
		got := mapFileOpenErrno(c.err)
		se, ok := got.(*safex.Error)
		if !ok || se.Code != c.want {
			t.Errorf("mapFileOpenErrno(%v) code = %v, want %s", c.err, got, c.want)
		}
		if c.want == safex.CodeNotFound && got != errNotFound {
			t.Errorf("mapFileOpenErrno(%v) is not the stable errNotFound", c.err)
		}
		assertNoLeak(t, got)
	}
}
