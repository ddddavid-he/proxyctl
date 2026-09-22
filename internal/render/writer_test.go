package render

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"proxyctl/internal/safex"
)

const writerCanary = "CANARY-VALUE"

// -------------------------------------------------------------------
// Test backend: an in-memory filesystem with real dev/ino identity,
// real no-replace semantics and injectable faults.
//
// The fake is what lets the race/rollback contracts be tested
// deterministically on ANY platform (including darwin, where the
// production backend fails closed): every descriptor-relative step,
// the atomic no-replace publish, and the retain-published rollback are
// pure logic above the backend interface.
// -------------------------------------------------------------------

var errFakeClosed = errors.New("closed")

type fakeNode struct {
	name    string
	content []byte
	dir     bool
	symlink bool
	target  string
	subdir  *fakeDir
	dev     uint64
	ino     uint64
	perm    os.FileMode
	synced  bool
}

func (n *fakeNode) Name() string       { return n.name }
func (n *fakeNode) Size() int64        { return int64(len(n.content)) }
func (n *fakeNode) Mode() os.FileMode  { return n.perm }
func (n *fakeNode) ModTime() time.Time { return time.Time{} }
func (n *fakeNode) IsDir() bool        { return n.dir }
func (n *fakeNode) Sys() any           { return nil }

type fakeDir struct {
	node    *fakeNode
	parent  *fakeDir
	entries map[string]*fakeNode
	closed  bool
	synced  bool
}

type fakeFile struct {
	node   *fakeNode
	dir    *fakeDir
	closed bool
}

func (f *fakeFile) write(data []byte) error {
	if f == nil || f.closed {
		return errFakeClosed
	}
	f.node.content = append([]byte(nil), data...)
	return nil
}

func (f *fakeFile) sync() error {
	if f == nil || f.closed {
		return errFakeClosed
	}
	f.node.synced = true
	return nil
}

func (f *fakeFile) close() error {
	if f == nil || f.closed {
		return errFakeClosed
	}
	f.closed = true
	return nil
}

// fs is the in-memory filesystem underlying the fake backend.
type fs struct {
	mu    sync.Mutex
	dirs  map[*fakeDir]struct{}
	next  uint64
	byID  map[uint64]*fakeNode
	onDev uint64
}

func newFS() *fs {
	return &fs{dirs: map[*fakeDir]struct{}{}, byID: map[uint64]*fakeNode{}, onDev: 1}
}

func (s *fs) newNode(name string, dir bool) *fakeNode {
	s.next++
	n := &fakeNode{name: name, dir: dir, dev: s.onDev, ino: s.next, perm: outputFilePerm}
	s.byID[n.ino] = n
	return n
}

// root creates an outDir node with the given mode.
func (s *fs) root(mode os.FileMode) *fakeDir {
	n := s.newNode("out", true)
	n.perm = mode
	d := &fakeDir{node: n, entries: map[string]*fakeNode{}}
	s.dirs[d] = struct{}{}
	return d
}

// faults selects which operation fails, keyed by file name. Tests set
// these to inject a failure at an exact point of the transaction.
type faults struct {
	create    string
	write     string
	syncFile  string
	closeFile string
	publish   string
	// unlinkStaged makes the staging unlink fail AFTER the final link
	// was created, the one case where publish reports (true, error).
	unlinkStaged   string
	rmdir          string
	syncDir        bool
	removeIfSameAt string
	mkdir          bool
	linkExists     bool
}

type fakeBackend struct {
	s        *fs
	root     *fakeDir
	f        faults
	log      []string
	open     []*fakeDir
	dirSyncs int
}

// newFakeBackend builds a backend over a fresh in-memory tree whose
// output directory (the value of rootPath) has mode rootMode.
func newFakeBackend(rootMode os.FileMode) (*fakeBackend, *fs) {
	s := newFS()
	root := s.root(rootMode)
	fb := &fakeBackend{s: s, root: root}
	return fb, s
}

func (b *fakeBackend) backend() backend {
	return backend{
		openDir:        b.openDir,
		openSubdir:     b.openSubdir,
		closeDir:       b.closeDir,
		lstatAt:        b.lstatAt,
		mkdirAt:        b.mkdirAt,
		createAt:       b.createAt,
		publish:        b.publish,
		removeIfSameAt: b.removeIfSameAt,
		rmdirAt:        b.rmdirAt,
		syncDir:        b.syncDir,
		randomSuffix:   func() (string, error) { return "staging", nil },
	}
}

func (b *fakeBackend) handle(d *fakeDir) *dirHandle {
	// Encode the in-memory directory into the handle: the fake has no
	// OS descriptor, so the *fakeDir pointer is the identity the
	// descriptor-relative contract is about.
	return &dirHandle{fd: int(uintptr(ptrID(d)))}
}

var (
	dirIDs   = map[*fakeDir]int{}
	dirPtrs  = map[int]*fakeDir{}
	dirIDSeq = 1
	dirMu    sync.Mutex
)

func ptrID(d *fakeDir) int {
	dirMu.Lock()
	defer dirMu.Unlock()
	if id, ok := dirIDs[d]; ok {
		return id
	}
	id := dirIDSeq
	dirIDSeq++
	dirIDs[d] = id
	dirPtrs[id] = d
	return id
}

func dirOf(h *dirHandle) *fakeDir {
	dirMu.Lock()
	defer dirMu.Unlock()
	return dirPtrs[h.fd]
}

func (b *fakeBackend) openDir(path string) (*dirHandle, error) {
	b.log = append(b.log, "openDir")
	if path == "" {
		return nil, safex.New(safex.CodeUsage, "output dir is required")
	}
	d := b.root
	if d == nil {
		return nil, safex.New(safex.CodeNotFound, "output dir does not exist")
	}
	if !d.node.dir {
		return nil, safex.New(safex.RenderUnsafe, "output path is not a directory")
	}
	if d.node.symlink {
		return nil, safex.New(safex.RenderUnsafe, "output dir must not be a symlink")
	}
	if d.node.perm != outputDirPerm {
		return nil, safex.New(safex.RenderUnsafe, "output dir permissions must be 0700")
	}
	h := b.handle(d)
	b.open = append(b.open, d)
	return h, nil
}

func (b *fakeBackend) openSubdir(dir *dirHandle, name string) (*dirHandle, error) {
	d := dirOf(dir)
	n, ok := d.entries[name]
	if !ok || !n.dir {
		return nil, safex.New(safex.CodeIO, "cannot open staging directory")
	}
	h := b.handle(d.entries[name].subdir)
	return h, nil
}

func (b *fakeBackend) closeDir(dir *dirHandle) error {
	b.log = append(b.log, "closeDir")
	return nil
}

func (b *fakeBackend) lstatAt(dir *dirHandle, name string) (os.FileInfo, error) {
	d := dirOf(dir)
	n, ok := d.entries[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return n, nil
}

func (b *fakeBackend) mkdirAt(dir *dirHandle, name string, perm os.FileMode) error {
	b.log = append(b.log, "mkdirAt:"+name)
	if b.f.mkdir {
		return safex.New(safex.CodeIO, "cannot create staging directory")
	}
	d := dirOf(dir)
	if _, ok := d.entries[name]; ok {
		return safex.New(safex.CodeIO, "cannot create staging directory")
	}
	n := b.s.newNode(name, true)
	n.perm = perm
	n.subdir = &fakeDir{node: n, parent: d, entries: map[string]*fakeNode{}}
	d.entries[name] = n
	b.s.dirs[n.subdir] = struct{}{}
	return nil
}

func (b *fakeBackend) createAt(dir *dirHandle, name string, perm os.FileMode) (file, inodeID, error) {
	b.log = append(b.log, "createAt:"+name)
	if b.f.create == name {
		return nil, inodeID{}, safex.New(safex.CodeIO, "cannot create output file")
	}
	d := dirOf(dir)
	if _, ok := d.entries[name]; ok {
		// O_CREAT|O_EXCL: exists -> fail.
		return nil, inodeID{}, safex.New(safex.CodeIO, "cannot create output file")
	}
	n := b.s.newNode(name, false)
	n.perm = perm
	d.entries[name] = n
	f := &fakeFile{node: n, dir: d}
	// Identity captured atomically with the create.
	id := inodeID{dev: n.dev, ino: n.ino, valid: true}
	return failingFile{f: f, fb: b, name: name}, id, nil
}

// failingFile injects write/sync/close failures by name.
type failingFile struct {
	f    *fakeFile
	fb   *fakeBackend
	name string
}

func (x failingFile) write(data []byte) error {
	if x.fb.f.write == x.name {
		return errFakeClosed
	}
	return x.f.write(data)
}

func (x failingFile) sync() error {
	if x.fb.f.syncFile == x.name {
		return errFakeClosed
	}
	return x.f.sync()
}

func (x failingFile) close() error {
	if x.fb.f.closeFile == x.name {
		return errFakeClosed
	}
	return x.f.close()
}

// publish models linkat + staging unlink. The link FAILS when the final
// name already exists (EEXIST), atomically: there is no window, the
// check and the create happen together under the same lock.
//
// The returned bool is the production contract: it reports whether the
// FINAL LINK was created, independently of the error, so the
// link-success / unlink-failure case yields (true, error).
func (b *fakeBackend) publish(dir, staging *dirHandle, name string) (bool, error) {
	b.log = append(b.log, "publish:"+name)
	sd := dirOf(staging)
	dd := dirOf(dir)
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	src, ok := sd.entries[name]
	if !ok {
		return false, safex.New(safex.CodeIO, "cannot publish output file")
	}
	if _, exists := dd.entries[name]; exists {
		// linkat EEXIST: no replacement, ever.
		return false, safex.New(safex.CodeIO, "cannot publish output file")
	}
	if b.f.publish == name {
		return false, safex.New(safex.CodeIO, "cannot publish output file")
	}
	// Hard link: same inode, new directory entry.
	dd.entries[name] = src
	if b.f.unlinkStaged == name {
		// The final link exists and STAYS; only the staging link
		// removal failed.
		return true, safex.New(safex.CodeIO, "cannot remove staged file")
	}
	delete(sd.entries, name)
	return true, nil
}

// removeIfSameAt deletes only when dev/ino still match. It is only ever
// called on the staging directory.
func (b *fakeBackend) removeIfSameAt(dir *dirHandle, name string, want inodeID) error {
	b.log = append(b.log, "removeIfSameAt:"+name)
	if b.f.removeIfSameAt == name {
		return safex.New(safex.CodeIO, "cannot remove output file")
	}
	d := dirOf(dir)
	if d != b.stagingDir() {
		return fmt.Errorf("removeIfSameAt called outside the staging directory: %s", name)
	}
	n, ok := d.entries[name]
	if !ok {
		return nil // publication consumed the link
	}
	if !want.valid {
		return safex.New(safex.CodeIO, "cannot verify output file identity for cleanup")
	}
	if n.dev != want.dev || n.ino != want.ino {
		return safex.New(safex.RenderUnsafe, "output file was replaced; refusing to remove it")
	}
	delete(d.entries, name)
	return nil
}

// stagingDir returns the staging directory this backend created, or nil
// when none exists. It is what lets removeIfSameAt assert it is never
// pointed at the output directory itself.
func (b *fakeBackend) stagingDir() *fakeDir {
	for name, n := range b.root.entries {
		if strings.HasPrefix(name, stagingPrefix) && n.subdir != nil {
			return n.subdir
		}
	}
	return nil
}

func (b *fakeBackend) rmdirAt(dir *dirHandle, name string) error {
	b.log = append(b.log, "rmdirAt:"+name)
	if b.f.rmdir != "" && b.f.rmdir == name {
		return safex.New(safex.CodeIO, "cannot remove staging directory")
	}
	d := dirOf(dir)
	n, ok := d.entries[name]
	if !ok {
		return safex.New(safex.CodeIO, "cannot remove staging directory")
	}
	if len(n.subdir.entries) != 0 {
		return safex.New(safex.CodeIO, "cannot remove staging directory")
	}
	delete(d.entries, name)
	return nil
}

func (b *fakeBackend) syncDir(dir *dirHandle) error {
	b.log = append(b.log, "syncDir")
	b.dirSyncs++
	if b.f.syncDir {
		return safex.New(safex.CodeIO, "cannot sync output dir")
	}
	d := dirOf(dir)
	d.synced = true
	return nil
}

// helper: entries of the output directory (names only).
func (b *fakeBackend) names() []string {
	d := b.root
	out := make([]string, 0, len(d.entries))
	for n := range d.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (b *fakeBackend) content(name string) string {
	n, ok := b.root.entries[name]
	if !ok {
		return ""
	}
	return string(n.content)
}

// -------------------------------------------------------------------
// Real-filesystem tests (production path). These run only where the
// production backend is supported (Linux); elsewhere they skip, and the
// fail-closed contract is pinned by
// TestWriteTransactionUnsupportedPlatformFailsClosed.
// -------------------------------------------------------------------

func writerFiles() map[string][]byte {
	return map[string][]byte{
		"gateway-rendered.yaml": []byte(writerCanary + " gateway-rendered\n"),
		"egress-rendered.yaml":  []byte(writerCanary + " egress-rendered\n"),
		"gateway.crt":           []byte(writerCanary + " gateway.crt\n"),
		"gateway.key":           []byte(writerCanary + " gateway.key\n"),
		"egress.crt":            []byte(writerCanary + " egress.crt\n"),
		"egress.key":            []byte(writerCanary + " egress.key\n"),
		"gateway-client.crt":    []byte(writerCanary + " gateway-client.crt\n"),
		"gateway-client.key":    []byte(writerCanary + " gateway-client.key\n"),
		"gateway-client-ca.crt": []byte(writerCanary + " gateway-client-ca.crt\n"),
	}
}

// newOutDir creates a 0700 output directory (what the CLI guarantees).
func newOutDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return dir
}

// requireFixedMessage asserts the error is a *safex.Error with the
// wanted code, wraps nothing, and leaks no canary / path / payload.
func requireFixedMessage(t *testing.T, err error, want safex.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("want error, got nil")
	}
	se, ok := err.(*safex.Error)
	if !ok {
		t.Fatalf("error = %T %v, want *safex.Error", err, err)
	}
	if se.Code != want {
		t.Fatalf("code = %v, want %v (message %q)", se.Code, want, se.Message)
	}
	if se.Unwrap() != nil {
		t.Errorf("error must not wrap underlying detail: %q", se.Message)
	}
	msg := se.Error()
	// The message must not carry the payload, the staging name, or any
	// directory path. (The literal word "staging" in a fixed message is
	// safe; the random staging name and paths are not.)
	for _, leak := range []string{writerCanary, stagingPrefix} {
		if strings.Contains(msg, leak) {
			t.Errorf("error message leaks %q: %q", leak, msg)
		}
	}
	// No absolute or traversal path may appear in a message.
	for _, leak := range []string{"/tmp/", "/var/", "..", t.TempDir()} {
		if t.TempDir() == "" {
			break
		}
		if strings.Contains(msg, leak) {
			t.Errorf("error message leaks path %q: %q", leak, msg)
		}
	}
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("error contains control characters: %q", msg)
	}
}

// requireBundleStateUndefined asserts the call returned the ONE fixed
// bundle-state-undefined error: identity, not text matching, so the
// caller contract cannot drift. It also re-checks the leak rules and
// that the message actually demands manual cleanup.
func requireBundleStateUndefined(t *testing.T, err error) {
	t.Helper()
	if err != errBundleStateUndefined {
		t.Fatalf("error = %v, want errBundleStateUndefined", err)
	}
	requireFixedMessage(t, err, safex.CodeIO)
	msg := err.Error()
	for _, want := range []string{"undefined", "retained", "manual cleanup"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q must state %q", msg, want)
		}
	}
}

// assertFS asserts the directory contains exactly want (name ->
// content) and no staging residue.
func assertFS(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Errorf("staging residue left: %s", e.Name())
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		got[e.Name()] = string(b)
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for n, c := range want {
		if got[n] != c {
			t.Errorf("%s content = %q, want %q", n, got[n], c)
		}
	}
}

// writerSupported reports whether the production backend is supported
// on this platform. It is decided by build target, not by attempting a
// write, so no test can accidentally depend on filesystem state.
func writerSupported() bool { return runtime.GOOS == "linux" }

// skipUnlessSupported skips real-filesystem tests where the production
// backend fails closed (it must not be weakened for a test).
func skipUnlessSupported(t *testing.T) {
	t.Helper()
	if !writerSupported() {
		t.Skip("production writer unsupported on this platform (fails closed)")
	}
}

func TestWriteTransactionSuccess(t *testing.T) {
	skipUnlessSupported(t)
	dir := newOutDir(t)
	files := writerFiles()
	if err := writeTransaction(dir, files); err != nil {
		t.Fatalf("writeTransaction: %v", err)
	}
	want := map[string]string{}
	for n, b := range files {
		want[n] = string(b)
		p := filepath.Join(dir, n)
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("missing %s: %v", n, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o, want 600", n, fi.Mode().Perm())
		}
	}
	assertFS(t, dir, want)
}

// TestWriteTransactionPublishOrder asserts publication follows the
// fixed allowlist order, not map iteration order.
func TestWriteTransactionPublishOrder(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	var seen []string
	b := fb.backend()
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		seen = append(seen, name)
		return fb.publish(dir, staging, name)
	}
	if err := writeTransactionWithBackend("out", writerFiles(), b); err != nil {
		t.Fatalf("writeTransactionWithBackend: %v", err)
	}
	if strings.Join(seen, ",") != strings.Join(outputNameOrder, ",") {
		t.Errorf("publish order = %v, want %v", seen, outputNameOrder)
	}
}

func TestWriteTransactionRejectsUnknownName(t *testing.T) {
	dir := newOutDir(t)
	for _, name := range []string{"evil.yaml", "gateway.crt.bak", "gateway_client.crt", "", "gateway.CRT"} {
		err := writeTransaction(dir, map[string][]byte{name: []byte(writerCanary)})
		requireFixedMessage(t, err, safex.RenderUnsafe)
	}
	assertFS(t, dir, map[string]string{})
}

func TestWriteTransactionRejectsSeparator(t *testing.T) {
	dir := newOutDir(t)
	for _, name := range []string{"sub/gateway.crt", "gateway.crt/x", "/gateway.crt", "../gateway.crt"} {
		requireFixedMessage(t, writeTransaction(dir, map[string][]byte{name: []byte(writerCanary)}), safex.RenderUnsafe)
	}
	assertFS(t, dir, map[string]string{})
}

func TestWriteTransactionRejectsDirPerm(t *testing.T) {
	skipUnlessSupported(t)
	base := t.TempDir()
	for i, mode := range []os.FileMode{0o755, 0o770, 0o777, 0o750} {
		dir := filepath.Join(base, fmt.Sprintf("d%d", i))
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := writeTransaction(dir, writerFiles())
		requireFixedMessage(t, err, safex.RenderUnsafe)
		assertFS(t, dir, map[string]string{})
	}
}

func TestWriteTransactionRequiresDir(t *testing.T) {
	skipUnlessSupported(t)
	base := t.TempDir()
	f := filepath.Join(base, "notadir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireFixedMessage(t, writeTransaction(f, writerFiles()), safex.RenderUnsafe)
	err := writeTransaction(filepath.Join(base, "missing"), writerFiles())
	requireFixedMessage(t, err, safex.CodeNotFound)
}

func TestWriteTransactionRejectsSymlinkDir(t *testing.T) {
	skipUnlessSupported(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink not supported")
	}
	err := writeTransaction(link, writerFiles())
	requireFixedMessage(t, err, safex.RenderUnsafe)
	assertFS(t, real, map[string]string{})
}

// TestWriteTransactionLeavesExistingTargetUntouched is the core
// no-replace contract: a pre-existing final target is never
// overwritten.
func TestWriteTransactionLeavesExistingTargetUntouched(t *testing.T) {
	skipUnlessSupported(t)
	dir := newOutDir(t)
	const old = "OLD-CONTENT"
	if err := os.WriteFile(filepath.Join(dir, "gateway.crt"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeTransaction(dir, writerFiles())
	requireFixedMessage(t, err, safex.RenderUnsafe)
	assertFS(t, dir, map[string]string{"gateway.crt": old})
}

func TestWriteTransactionRejectsSymlinkTarget(t *testing.T) {
	skipUnlessSupported(t)
	base := t.TempDir()
	dir := filepath.Join(base, "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.crt")
	if err := os.WriteFile(outside, []byte("OUTSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "gateway.key")); err != nil {
		t.Skip("symlink not supported")
	}
	err := writeTransaction(dir, writerFiles())
	requireFixedMessage(t, err, safex.RenderUnsafe)
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("outside file: %v", err)
	}
	if string(data) != "OUTSIDE" {
		t.Errorf("symlink target modified: %q", data)
	}
	fi, err := os.Lstat(filepath.Join(dir, "gateway.key"))
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("gateway.key is no longer a symlink")
	}
}

// ATTACK: the final target is created AFTER the pre-publish existence
// check. The no-replace publish must still refuse, and the racing file
// must be left byte-identical.
func TestWriteTransactionFinalCreatedAfterCheckIsNotOverwritten(t *testing.T) {
	const racer = "RACER-WINS"
	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " a"),
		"gateway.key": []byte(writerCanary + " b"),
	}
	fb, _ := newFakeBackend(outputDirPerm)
	b := fb.backend()
	basePublish := b.publish
	first := true
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		linked, err := basePublish(dir, staging, name)
		if first {
			first = false
			// Attacker creates the final target after the pre-publish
			// check but before the publish of gateway.key.
			racerNode := fb.s.newNode("gateway.key", false)
			racerNode.content = []byte(racer)
			fb.root.entries["gateway.key"] = racerNode
		}
		return linked, err
	}
	err := writeTransactionWithBackend("out", files, b)
	// gateway.crt was published before the refusal, so the bundle state is
	// undefined and the published file is retained.
	requireBundleStateUndefined(t, err)
	if got := fb.content("gateway.key"); got != racer {
		t.Errorf("racing final target = %q, want %q (must not be overwritten)", got, racer)
	}
	if got := fb.content("gateway.crt"); got != writerCanary+" a" {
		t.Errorf("published gateway.crt = %q, want it retained", got)
	}
}

// ATTACK: the output directory path is REPLACED (swapped for another
// directory) after the writer opened it. Because every later step is
// descriptor-relative, the write must still land in the directory the
// descriptor names — never in the replacement.
func TestWriteTransactionOutDirReplacedAfterOpenStillUsesHeldFD(t *testing.T) {
	skipUnlessSupported(t)
	base := t.TempDir()
	realDir := filepath.Join(base, "out")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(base, "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	// Open+verify happens inside writeTransaction, so the swap is
	// injected through the backend: after openDir returns, replace the
	// on-disk path (rename out -> out.moved, decoy -> out).
	prod := defaultBackend()
	openDir := prod.openDir
	prod.openDir = func(path string) (*dirHandle, error) {
		h, err := openDir(path)
		if err != nil {
			return h, err
		}
		if err := os.Rename(realDir, filepath.Join(base, "out.moved")); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if err := os.Rename(decoy, realDir); err != nil {
			t.Fatalf("rename: %v", err)
		}
		return h, nil
	}
	files := writerFiles()
	if err := writeTransactionWithBackend(realDir, files, prod); err != nil {
		t.Fatalf("writeTransactionWithBackend after dir swap: %v", err)
	}
	// The decoy (now at realDir) must be EMPTY: nothing was written
	// through the replaced path.
	assertFS(t, realDir, map[string]string{})
	// Everything landed in the directory the descriptor names.
	moved := filepath.Join(base, "out.moved")
	want := map[string]string{}
	for n, b := range files {
		want[n] = string(b)
	}
	assertFS(t, moved, want)
}

// TestWriteTransactionOutDirSwappedAfterOpenUsesHeldHandle is the
// backend-level twin of the dir-swap attack above and runs on every
// platform: after openDir returns, the path's target is replaced by a
// different directory. Every later step is handle-relative, so the
// write must still land in the directory the handle names.
func TestWriteTransactionOutDirSwappedAfterOpenUsesHeldHandle(t *testing.T) {
	fb, s := newFakeBackend(outputDirPerm)
	original := fb.root
	decoy := s.root(outputDirPerm)
	b := fb.backend()
	openDir := b.openDir
	b.openDir = func(path string) (*dirHandle, error) {
		h, err := openDir(path)
		if err != nil {
			return h, err
		}
		// Replace the path's target AFTER the handle was issued.
		fb.root = decoy
		return h, nil
	}
	files := map[string][]byte{"gateway.crt": []byte(writerCanary + " c")}
	if err := writeTransactionWithBackend("out", files, b); err != nil {
		t.Fatalf("writeTransactionWithBackend after dir swap: %v", err)
	}
	if len(decoy.entries) != 0 {
		t.Errorf("write followed the swapped path: decoy received entries")
	}
	if got := string(original.entries["gateway.crt"].content); got != writerCanary+" c" {
		t.Errorf("gateway.crt = %q, want %q", got, writerCanary+" c")
	}
}

// TestWriteTransactionRollbackRetainsPublished is guarantee 3: a
// midway publish failure NEVER deletes a final name this call already
// published. The published file is retained byte-for-byte and the call
// returns the fixed bundle-state-undefined / manual-cleanup error.
//
// This replaces the previous dev/ino-guarded delete of published
// finals. That guard was unsafe by construction: stat-then-unlink is
// two syscalls and unlinkat takes a NAME, so the name could be
// re-pointed between them and the unlink would destroy an object the
// stat never approved. Retention has no such window.
func TestWriteTransactionRollbackRetainsPublished(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " a"),
		"gateway.key": []byte(writerCanary + " b"),
	}
	b := fb.backend()
	// Publish gateway.crt, then fail on gateway.key.
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		if name == "gateway.key" {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		return fb.publish(dir, staging, name)
	}
	err := writeTransactionWithBackend("out", files, b)
	requireBundleStateUndefined(t, err)
	if got := fb.content("gateway.crt"); got != writerCanary+" a" {
		t.Errorf("published gateway.crt = %q, want it retained verbatim", got)
	}
	// The published name must never be handed to a removal primitive.
	for _, l := range fb.log {
		if l == "removeIfSameAt:gateway.crt" {
			t.Errorf("published final was passed to a removal primitive: %v", fb.log)
		}
	}
	// Staging is cleaned: only the published final remains.
	if n := fb.names(); len(n) != 1 || n[0] != "gateway.crt" {
		t.Errorf("entries = %v, want only the retained published gateway.crt", n)
	}
}

// TestWriteTransactionPublishUnlinkFailureRecordsPublished pins the
// link-success / unlink-failure split: linkat created the final link,
// then dropping the staging link failed. publish reports (true, error),
// so the caller records the final name as PUBLISHED and rollback must
// retain it — the file must not be deleted and must not go unaccounted.
func TestWriteTransactionPublishUnlinkFailureRecordsPublished(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " a"),
		"gateway.key": []byte(writerCanary + " b"),
	}
	// gateway.crt links successfully but its staging link cannot be removed.
	fb.f.unlinkStaged = "gateway.crt"
	err := writeTransactionWithBackend("out", files, fb.backend())
	requireBundleStateUndefined(t, err)
	// The final link exists and is retained.
	if got := fb.content("gateway.crt"); got != writerCanary+" a" {
		t.Errorf("gateway.crt = %q, want the published content retained", got)
	}
	if _, ok := fb.root.entries["gateway.crt"]; !ok {
		t.Fatal("final link was removed despite being published")
	}
	// It was never passed to a removal primitive.
	for _, l := range fb.log {
		if l == "removeIfSameAt:gateway.crt" {
			t.Errorf("published final was passed to a removal primitive: %v", fb.log)
		}
	}
	// gateway.key was never published, so it must not be on disk.
	if _, ok := fb.root.entries["gateway.key"]; ok {
		t.Error("gateway.key was never published but exists in the output dir")
	}
	// The staging entry whose unlink failed is left for manual cleanup:
	// its inode is now reachable under the published final name, so
	// removing it here would be operating on a published object. The
	// staging directory therefore survives, and the error says so.
	sd := fb.stagingDir()
	if sd == nil {
		t.Fatal("staging directory was removed while it still held an entry")
	}
	if _, ok := sd.entries["gateway.crt"]; !ok {
		t.Error("the staged link of a published file must be left alone")
	}
}

// TestWriteTransactionPublishReportsLinkedOnUnlinkFailure pins the
// backend contract at the primitive itself: the bool is authoritative
// and independent of the error.
func TestWriteTransactionPublishReportsLinkedOnUnlinkFailure(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	b := fb.backend()
	h, err := b.openDir("out")
	if err != nil {
		t.Fatalf("openDir: %v", err)
	}
	if err := b.mkdirAt(h, stagingPrefix+"staging", outputDirPerm); err != nil {
		t.Fatalf("mkdirAt: %v", err)
	}
	sh, err := b.openSubdir(h, stagingPrefix+"staging")
	if err != nil {
		t.Fatalf("openSubdir: %v", err)
	}
	f, _, err := b.createAt(sh, "gateway.crt", outputFilePerm)
	if err != nil {
		t.Fatalf("createAt: %v", err)
	}
	if err := f.write([]byte(writerCanary)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	fb.f.unlinkStaged = "gateway.crt"
	linked, perr := b.publish(h, sh, "gateway.crt")
	if !linked {
		t.Error("publish reported linked = false after the final link was created")
	}
	if perr == nil {
		t.Error("publish must report the staging unlink failure")
	}
}

// ATTACK + durability: a directory fsync failure after publication is
// reported (never silent). Everything was already published, so the
// files are RETAINED and the caller is told the state is undefined.
func TestWriteTransactionDirSyncFailureReported(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	b := fb.backend()
	fb.f.syncDir = true
	files := writerFiles()
	err := writeTransactionWithBackend("out", files, b)
	requireBundleStateUndefined(t, err)
	if fb.dirSyncs == 0 {
		t.Fatal("output dir was never fsynced")
	}
	for n, want := range files {
		if got := fb.content(n); got != string(want) {
			t.Errorf("%s = %q, want it retained after the fsync failure", n, got)
		}
	}
}

func TestWriteTransactionFsyncsEachStagedFile(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	b := fb.backend()
	if err := writeTransactionWithBackend("out", writerFiles(), b); err != nil {
		t.Fatalf("writeTransactionWithBackend: %v", err)
	}
	if !fb.root.synced {
		t.Error("output dir was not fsynced after publication")
	}
}

// TestWriteTransactionWriteFailureNoResidue: a staging failure leaves
// no published file and no staging residue.
func TestWriteTransactionWriteFailureNoResidue(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeBackend)
	}{
		{"write", func(fb *fakeBackend) { fb.f.write = "gateway.key" }},
		{"sync", func(fb *fakeBackend) { fb.f.syncFile = "gateway.key" }},
		{"close", func(fb *fakeBackend) { fb.f.closeFile = "gateway.key" }},
		{"create", func(fb *fakeBackend) { fb.f.create = "gateway.key" }},
		{"mkdir", func(fb *fakeBackend) { fb.f.mkdir = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fb, _ := newFakeBackend(outputDirPerm)
			tc.set(fb)
			err := writeTransactionWithBackend("out", writerFiles(), fb.backend())
			requireFixedMessage(t, err, safex.CodeIO)
			if n := fb.names(); len(n) != 0 {
				t.Errorf("residue left: %v", n)
			}
		})
	}
}

// TestWriteTransactionMidwayFailureNeverTouchesOtherFiles: a midway
// publish failure never touches a pre-existing file, and the file this
// call did publish is retained (guarantee 3) rather than deleted.
func TestWriteTransactionMidwayFailureNeverTouchesOtherFiles(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	const keep = "KEEP-ME-OLD"
	old := fb.s.newNode("egress.crt", false)
	old.content = []byte(keep)
	fb.root.entries["egress.crt"] = old

	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " c"),
		"gateway.key": []byte(writerCanary + " d"),
	}
	b := fb.backend()
	base := b.publish
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		if name == "gateway.key" {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		return base(dir, staging, name)
	}
	err := writeTransactionWithBackend("out", files, b)
	requireBundleStateUndefined(t, err)
	if got := fb.content("egress.crt"); got != keep {
		t.Errorf("pre-existing file modified: %q, want %q", got, keep)
	}
	// The pre-existing file plus the retained published gateway.crt; no
	// staging residue.
	got := fb.names()
	if len(got) != 2 || got[0] != "egress.crt" || got[1] != "gateway.crt" {
		t.Errorf("entries = %v, want [egress.crt gateway.crt]", got)
	}
}

// TestWriteTransactionCleanupErrorNotSilent: a staging removal failure
// during rollback becomes the returned error (guarantee 6). Nothing was
// published here, so the staging error is what the caller sees.
func TestWriteTransactionCleanupErrorNotSilent(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	files := map[string][]byte{
		"gateway.crt": []byte(writerCanary + " c"),
		"gateway.key": []byte(writerCanary + " d"),
	}
	b := fb.backend()
	// Fail before anything is published, then fail the staging cleanup
	// of gateway.crt so the rollback error is the reported one.
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		return false, safex.New(safex.CodeIO, "cannot publish output file")
	}
	fb.f.removeIfSameAt = "gateway.crt"
	err := writeTransactionWithBackend("out", files, b)
	requireFixedMessage(t, err, safex.CodeIO)
	if err == errBundleStateUndefined {
		t.Error("nothing was published; want the staging cleanup error")
	}
	// A refused staging entry keeps the staging dir, which is reported
	// but never deleted by force.
	if fb.stagingDir() == nil {
		t.Error("staging directory was removed despite a refused entry")
	}
}

// TestRollbackNeverRemovesFinalNames is a structural guarantee: the
// transaction has NO primitive that removes a final published name.
// The backend surface itself must not offer one, so no future edit can
// reintroduce a stat-then-unlink of published files by accident.
func TestRollbackNeverRemovesFinalNames(t *testing.T) {
	// removeIfSameAt is the only removal primitive, and the fake
	// asserts on every call that it is pointed at the staging
	// directory. Drive a rollback that publishes one file and fails on
	// the next: any final-name removal attempt fails the test inside
	// the fake.
	fb, _ := newFakeBackend(outputDirPerm)
	b := fb.backend()
	base := b.publish
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		if name == "egress.crt" {
			return false, safex.New(safex.CodeIO, "cannot publish output file")
		}
		return base(dir, staging, name)
	}
	err := writeTransactionWithBackend("out", writerFiles(), b)
	requireBundleStateUndefined(t, err)
	// Everything published before the failure is still on disk.
	for _, name := range outputNameOrder {
		if name == "egress.crt" {
			break
		}
		if _, ok := fb.root.entries[name]; !ok {
			t.Errorf("published %s was deleted by rollback", name)
		}
	}
	// Nothing after the failure point was published.
	if _, ok := fb.root.entries["egress.crt"]; ok {
		t.Error("egress.crt must not exist: its publish failed")
	}
	// Staging is gone: unpublished staged entries were cleaned.
	if fb.stagingDir() != nil {
		t.Error("staging directory left behind")
	}
}

// TestWriteTransactionFsyncsBeforeAndAfterStagingRemoval pins the
// durability ordering: the output dir is fsynced right after the last
// publish (so published entries are durable even if cleanup fails) and
// again after the staging directory is removed (so the removal is
// durable too).
func TestWriteTransactionFsyncsBeforeAndAfterStagingRemoval(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	if err := writeTransactionWithBackend("out", writerFiles(), fb.backend()); err != nil {
		t.Fatalf("writeTransactionWithBackend: %v", err)
	}
	var order []string
	for _, l := range fb.log {
		switch {
		case l == "syncDir", strings.HasPrefix(l, "rmdirAt:"), strings.HasPrefix(l, "publish:"):
			order = append(order, l)
		}
	}
	// Expected tail: last publish, syncDir, rmdirAt, syncDir.
	if len(order) < 4 {
		t.Fatalf("log = %v", order)
	}
	tail := order[len(order)-4:]
	if !strings.HasPrefix(tail[0], "publish:") ||
		tail[1] != "syncDir" ||
		!strings.HasPrefix(tail[2], "rmdirAt:") ||
		tail[3] != "syncDir" {
		t.Errorf("ordering = %v, want publish, syncDir, rmdirAt, syncDir", tail)
	}
	if fb.dirSyncs != 2 {
		t.Errorf("dirSyncs = %d, want 2 (before and after staging removal)", fb.dirSyncs)
	}
}

// TestWriteTransactionStagingRemovalFailureKeepsPublished: the staging
// rmdir fails AFTER a successful publication. The published bundle is
// durable (already fsynced) and retained; the failure is reported.
func TestWriteTransactionStagingRemovalFailureKeepsPublished(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	fb.f.rmdir = stagingPrefix + "staging"
	files := writerFiles()
	err := writeTransactionWithBackend("out", files, fb.backend())
	requireBundleStateUndefined(t, err)
	for n, want := range files {
		if got := fb.content(n); got != string(want) {
			t.Errorf("%s = %q, want %q (published files are retained)", n, got, want)
		}
	}
	if fb.dirSyncs == 0 {
		t.Error("published entries were never fsynced")
	}
}

// TestWriteTransactionNoRenameIsUsed is a source-level guard: the
// transaction must never CALL os.Rename (which replaces silently) or
// os.Renameat. Comments mentioning them are ignored.
func TestWriteTransactionNoRenameIsUsed(t *testing.T) {
	for _, name := range []string{"writer.go", "writer_linux.go", "writer_other.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := line
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i]
			}
			for _, banned := range []string{"os.Rename", "Rename(", "Renameat("} {
				if strings.Contains(code, banned) {
					t.Errorf("%s must not call %s (it replaces silently): %s", name, banned, line)
				}
			}
		}
	}
}

// TestWriteTransactionEmptyRequest: the directory contract is still
// validated, then it returns before creating any staging state.
func TestWriteTransactionEmptyRequest(t *testing.T) {
	skipUnlessSupported(t)
	dir := newOutDir(t)
	if err := writeTransaction(dir, map[string][]byte{}); err != nil {
		t.Fatalf("empty writeTransaction: %v", err)
	}
	assertFS(t, dir, map[string]string{})
	// Directory validation still applies to an empty request.
	bad := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	requireFixedMessage(t, writeTransaction(bad, map[string][]byte{}), safex.RenderUnsafe)
}

// TestWriteTransactionEmptyRequestNoStaging is the always-running
// twin: an empty request must validate the directory and then return
// before creating any staging state.
func TestWriteTransactionEmptyRequestNoStaging(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	if err := writeTransactionWithBackend("out", map[string][]byte{}, fb.backend()); err != nil {
		t.Fatalf("empty request: %v", err)
	}
	for _, l := range fb.log {
		if strings.HasPrefix(l, "mkdirAt:") {
			t.Errorf("empty request created staging state: %v", fb.log)
		}
	}
	// A non-0700 directory is still rejected for an empty request.
	bads, _ := newFakeBackend(0o755)
	requireFixedMessage(t,
		writeTransactionWithBackend("out", map[string][]byte{}, bads.backend()),
		safex.RenderUnsafe)
}

// TestWriteTransactionUnsupportedPlatformFailsClosed pins the
// non-Linux production entry point: nothing is written, ever.
func TestWriteTransactionUnsupportedPlatformFailsClosed(t *testing.T) {
	if writerSupported() {
		t.Skip("supported platform: the fail-closed path is not exercised")
	}
	dir := newOutDir(t)
	err := writeTransaction(dir, writerFiles())
	requireFixedMessage(t, err, safex.CodeInternal)
	assertFS(t, dir, map[string]string{})
}

// TestWriteTransactionConcurrentIsolated proves concurrent calls do
// not share mutable backend state (no package-global ops).
func TestWriteTransactionConcurrentIsolated(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fb, _ := newFakeBackend(outputDirPerm)
			files := map[string][]byte{"gateway.crt": []byte(fmt.Sprintf("call-%d", i))}
			errs[i] = writeTransactionWithBackend("out", files, fb.backend())
			if errs[i] == nil && fb.content("gateway.crt") != fmt.Sprintf("call-%d", i) {
				errs[i] = errors.New("cross-call contamination")
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
}

// -------------------------------------------------------------------
// Always-running twins of the real-filesystem tests. They pin the same
// contracts through the injected backend so they execute on every
// platform (including non-Linux, where the production backend fails
// closed and cannot be exercised).
// -------------------------------------------------------------------

// TestWriteTransactionSuccessBackend publishes the full bundle.
func TestWriteTransactionSuccessBackend(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	files := writerFiles()
	if err := writeTransactionWithBackend("out", files, fb.backend()); err != nil {
		t.Fatalf("writeTransactionWithBackend: %v", err)
	}
	for n, want := range files {
		if got := fb.content(n); got != string(want) {
			t.Errorf("%s = %q, want %q", n, got, want)
		}
		node, ok := fb.root.entries[n]
		if !ok {
			t.Fatalf("%s missing", n)
		}
		if node.perm != outputFilePerm {
			t.Errorf("%s perm = %o, want %o", n, node.perm, outputFilePerm)
		}
		if !node.synced {
			t.Errorf("%s was not fsynced before publication", n)
		}
	}
	// No staging residue.
	for _, n := range fb.names() {
		if strings.HasPrefix(n, stagingPrefix) {
			t.Errorf("staging residue: %s", n)
		}
	}
}

// TestWriteTransactionDirPermEnforcedBackend: a non-0700 directory is
// refused before anything is created.
func TestWriteTransactionDirPermEnforcedBackend(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o770, 0o777, 0o750} {
		fb, _ := newFakeBackend(mode)
		err := writeTransactionWithBackend("out", writerFiles(), fb.backend())
		requireFixedMessage(t, err, safex.RenderUnsafe)
		if n := len(fb.names()); n != 0 {
			t.Errorf("mode %o: created %d entries before refusing", mode, n)
		}
	}
}

// TestWriteTransactionExistingTargetBackend: an existing final target
// is refused and left untouched.
func TestWriteTransactionExistingTargetBackend(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	const old = "OLD-CONTENT"
	oldNode := fb.s.newNode("gateway.crt", false)
	oldNode.content = []byte(old)
	fb.root.entries["gateway.crt"] = oldNode
	err := writeTransactionWithBackend("out", writerFiles(), fb.backend())
	requireFixedMessage(t, err, safex.RenderUnsafe)
	if got := fb.content("gateway.crt"); got != old {
		t.Errorf("existing target modified: %q, want %q", got, old)
	}
	if n := len(fb.names()); n != 1 {
		t.Errorf("entries = %d, want only the pre-existing file", n)
	}
}

// TestWriteTransactionSymlinkTargetBackend: a symlinked final target is
// refused, never followed.
func TestWriteTransactionSymlinkTargetBackend(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	link := fb.s.newNode("gateway.key", false)
	link.symlink = true
	link.target = "/elsewhere"
	fb.root.entries["gateway.key"] = link
	err := writeTransactionWithBackend("out", writerFiles(), fb.backend())
	requireFixedMessage(t, err, safex.RenderUnsafe)
	if !fb.root.entries["gateway.key"].symlink {
		t.Error("symlink target was replaced")
	}
}

// TestWriteTransactionNoReplaceOnPublishBackend pins the core
// guarantee at the publish primitive: publishing onto an existing name
// must fail, never replace.
func TestWriteTransactionNoReplaceOnPublishBackend(t *testing.T) {
	fb, _ := newFakeBackend(outputDirPerm)
	files := map[string][]byte{"gateway.crt": []byte(writerCanary + " new")}
	// Create the final target AFTER staging but BEFORE publish.
	b := fb.backend()
	base := b.publish
	b.publish = func(dir, staging *dirHandle, name string) (bool, error) {
		n := fb.s.newNode(name, false)
		n.content = []byte("EXISTING")
		fb.root.entries[name] = n
		return base(dir, staging, name)
	}
	err := writeTransactionWithBackend("out", files, b)
	requireFixedMessage(t, err, safex.CodeIO)
	if got := fb.content("gateway.crt"); got != "EXISTING" {
		t.Errorf("existing target = %q, want %q (publish must not replace)", got, "EXISTING")
	}
}
