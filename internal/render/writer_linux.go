//go:build linux

package render

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"proxyctl/internal/safex"
)

// Linux backend constants. These AT_* values are part of the kernel
// ABI and are stable across all Linux architectures (they are not
// exported by the Go syscall package on every target), so they are
// declared here next to their only use.
const (
	atSymlinkNoFollow = 0x100 // AT_SYMLINK_NOFOLLOW
	atRemovedir       = 0x200 // AT_REMOVEDIR
)

// defaultBackend is the production backend for Linux. It is an
// IMMUTABLE value, rebuilt per call: nothing here is package-global
// mutable state, so concurrent writeTransaction calls cannot observe
// or disturb each other.
//
// Every step is descriptor-relative:
//   - openDir: walks EVERY path component with
//     openat(O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) from a pinned anchor
//     ("/" for absolute, the held working directory for relative),
//     rejecting ".." and every symlink at any depth, then Fstat, so
//     the "is a directory" and 0700 checks apply to the very object
//     the descriptor names (no check-then-use on a string path).
//   - mkdirAt/createAt/lstatAt/removeIfSameAt/rmdirAt: the *at
//     family against the held dirfd.
//   - publish: linkat, which fails with EEXIST when the final name
//     already exists — an atomic no-replace publish. It reports link
//     creation separately from the error so a staging-unlink failure
//     cannot hide an already-published final name.
//
// The linkat and unlinkat wrappers use the maintained raw-syscall
// entry points (syscall.Syscall with SYS_LINKAT / SYS_UNLINKAT)
// because the Linux syscall package does not export Linkat or the
// AT_* constants. This is the same style as
// internal/credential/fd_linux.go: standard-library syscall only, no
// cgo and no hand-written assembly.
func defaultBackend() backend {
	return backend{
		openDir:    openOutputDirLinux,
		openSubdir: openSubdirLinux,
		closeDir:   closeDirLinux,
		lstatAt:    lstatAtLinux,
		mkdirAt:    mkdirAtLinux,
		createAt:   createAtLinux,
		publish:    publishLinux,
		// Publication consumes the staged link, so staged cleanup
		// tolerates ENOENT but still refuses an identity mismatch.
		// There is no final-name removal: published files are never
		// deleted (guarantee 3).
		removeIfSameAt: removeIfSameAtLinux,
		rmdirAt:        rmdirAtLinux,
		syncDir:        syncDirLinux,
		randomSuffix:   randomSuffixLinux,
	}
}

// randomSuffixLinux returns the random part of the staging dir name.
func randomSuffixLinux() (string, error) {
	var b [stagingRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", safex.New(safex.CodeIO, "cannot create staging directory")
	}
	return hex.EncodeToString(b[:]), nil
}

// linkatLinux is linkat(olddirfd, oldpath, newdirfd, newpath, 0).
//
// Creating a second hard link to the staged inode fails with EEXIST
// when the new path already exists, and the kernel performs the
// existence check and the directory-entry creation as ONE atomic
// operation. That is what makes publication no-replace: there is no
// window in which an existing final target is truncated or swapped.
func linkatLinux(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) error {
	op, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT,
		uintptr(olddirfd), uintptr(unsafe.Pointer(op)),
		uintptr(newdirfd), uintptr(unsafe.Pointer(np)),
		uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// unlinkatLinux is unlinkat(dirfd, path, flags).
func unlinkatLinux(dirfd int, path string, flags int) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
	if errno != 0 {
		return errno
	}
	return nil
}

// mapDirOpenErrnoLinux classifies a directory-open failure by
// OPERATION CONTEXT, not by guessing which errno a given kernel
// version prefers: for an O_NOFOLLOW|O_DIRECTORY open, ENOENT is the
// stable not-found, while ENOTDIR and ELOOP both mean the component is
// not a real directory (a symlink, or a non-directory) and are
// therefore refused as unsafe.
func mapDirOpenErrnoLinux(err error) error {
	switch err {
	case syscall.ENOENT:
		return safex.New(safex.CodeNotFound, "output dir does not exist")
	case syscall.ENOTDIR, syscall.ELOOP:
		// A symlink or non-directory component: never act on it.
		return safex.New(safex.RenderUnsafe, "output dir must not be a symlink")
	case syscall.EACCES, syscall.EPERM:
		return safex.New(safex.CodePermission, "output dir access denied")
	}
	return safex.New(safex.CodeIO, "output dir cannot be opened")
}

// openOutputDirLinux opens the output directory by WALKING EVERY PATH
// COMPONENT and verifies, on the final OPEN descriptor, that it is a
// real directory with mode 0700.
//
// Why a walk and not one open(path, O_NOFOLLOW|O_DIRECTORY): O_NOFOLLOW
// only refuses a symlink at the FINAL component. Every INTERMEDIATE
// component is still resolved by the kernel, so a single open follows
// an intermediate symlink silently — /a/b/out with b a symlink to an
// attacker-controlled directory would be accepted, and the whole
// bundle would be written there. The walk removes that entirely:
//
//   - The anchor is pinned once: "/" for an absolute path, the process
//     working directory (".") for a relative one. The relative anchor
//     is opened ONCE and held, so a later chdir cannot re-point the
//     walk.
//   - Each component is opened with openat(parentfd, component,
//     O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) relative to its parent's
//     descriptor, so EVERY component — not just the last — must be a
//     real directory and must not be a symlink (a symlink fails with
//     ELOOP, a non-directory with ENOTDIR).
//   - ".." is rejected outright: it is never resolved, so no walk can
//     climb out of the anchor.
//
// Empty and "." components are skipped: they are pure path syntax
// ("a//b", "./a") and name the same directory the walk already holds.
func openOutputDirLinux(path string) (*dirHandle, error) {
	if path == "" {
		return nil, safex.New(safex.CodeUsage, "output dir is required")
	}
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	// Pin the anchor: an absolute path starts at the real root, a
	// relative one at the working directory as it is RIGHT NOW.
	anchor := "."
	if strings.HasPrefix(path, "/") {
		anchor = "/"
	}
	fd, err := syscall.Open(anchor, flags, 0)
	if err != nil {
		return nil, mapDirOpenErrnoLinux(err)
	}
	d := &dirHandle{fd: fd}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			d.closeLinux()
			return nil, safex.New(safex.RenderUnsafe, "path traversal rejected in output dir")
		}
		next, oerr := syscall.Openat(d.fd, part, flags, 0)
		// The parent descriptor has served its purpose; only the
		// deepest descriptor is kept, so no fd is leaked on any path.
		d.closeLinux()
		if oerr != nil {
			return nil, mapDirOpenErrnoLinux(oerr)
		}
		d = &dirHandle{fd: next}
	}
	// The contract is verified on the FINAL held descriptor: the "is a
	// directory" and 0700 checks describe the very object every later
	// step acts on, never a re-resolved path.
	var st syscall.Stat_t
	if err := syscall.Fstat(d.fd, &st); err != nil {
		d.closeLinux()
		return nil, safex.New(safex.CodeIO, "output dir cannot be inspected")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		d.closeLinux()
		return nil, safex.New(safex.RenderUnsafe, "output path is not a directory")
	}
	if os.FileMode(st.Mode&0o777) != outputDirPerm {
		d.closeLinux()
		return nil, safex.New(safex.RenderUnsafe, "output dir permissions must be 0700")
	}
	return d, nil
}

// openSubdirLinux opens an existing subdirectory relative to an open
// directory descriptor with the same no-follow guarantees, pinning the
// staging directory identity for the rest of the transaction.
func openSubdirLinux(dir *dirHandle, name string) (*dirHandle, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	fd, err := syscall.Openat(dir.fd, name, flags, 0)
	if err != nil {
		return nil, safex.New(safex.CodeIO, "cannot open staging directory")
	}
	return &dirHandle{fd: fd}, nil
}

func (d *dirHandle) closeLinux() {
	if d != nil && d.fd >= 0 {
		syscall.Close(d.fd)
		d.fd = -1
	}
}

func closeDirLinux(d *dirHandle) error {
	d.closeLinux()
	return nil
}

// statAtLinux stats name relative to dir WITHOUT following a final
// symlink: it opens the entry with O_NOFOLLOW (a symlink at the final
// component fails with ELOOP, so nothing is ever followed) and fstats
// the OPEN descriptor, which is what the identity check needs.
//
// openat + Fstat is used instead of fstatat because the syscall number
// for newfstatat/fstatat64 is not the same on every Linux
// architecture, while openat and Fstat are stable and exported
// everywhere. O_NONBLOCK keeps the open from blocking on a FIFO that
// an attacker may have planted under one of the allowed names.
func statAtLinux(dir *dirHandle, name string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, err := syscall.Openat(dir.fd, name,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return st, err
	}
	ferr := syscall.Fstat(fd, &st)
	syscall.Close(fd)
	if ferr != nil {
		return st, ferr
	}
	return st, nil
}

func lstatAtLinux(dir *dirHandle, name string) (os.FileInfo, error) {
	st, err := statAtLinux(dir, name)
	if err != nil {
		// Return the errno verbatim so os.IsNotExist works upstream.
		return nil, err
	}
	return newStatInfo(name, &st), nil
}

func mkdirAtLinux(dir *dirHandle, name string, perm os.FileMode) error {
	if err := syscall.Mkdirat(dir.fd, name, uint32(perm&0o777)); err != nil {
		return safex.New(safex.CodeIO, "cannot create staging directory")
	}
	return nil
}

// osFile adapts an *os.File to the file interface.
type osFile struct{ f *os.File }

func (o osFile) write(data []byte) error { _, err := o.f.Write(data); return err }
func (o osFile) sync() error             { return o.f.Sync() }
func (o osFile) close() error            { return o.f.Close() }

// createAtLinux creates name relative to dir with
// O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW at perm. O_EXCL makes the create
// fail atomically when the name exists; O_NOFOLLOW refuses a symlink
// at the final component; the descriptor-relative form removes any
// check-then-create window on the parent.
func createAtLinux(dir *dirHandle, name string, perm os.FileMode) (file, inodeID, error) {
	flags := syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Openat(dir.fd, name, flags, uint32(perm&0o777))
	if err != nil {
		return nil, inodeID{}, safex.New(safex.CodeIO, "cannot create output file")
	}
	// Fstat the OPEN descriptor: the identity captured here belongs to
	// the inode just created, never to a later replacement.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, inodeID{}, safex.New(safex.CodeIO, "output file cannot be inspected")
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		syscall.Close(fd)
		return nil, inodeID{}, safex.New(safex.CodeIO, "cannot create output file")
	}
	return osFile{f: f}, inodeID{dev: uint64(st.Dev), ino: uint64(st.Ino), valid: true}, nil
}

// publishLinux makes the staged file visible under its final name in
// dir WITHOUT REPLACING an existing entry.
//
// It uses linkat (see linkatLinux): the kernel's existence check and
// directory-entry creation are one atomic operation, so there is no
// window in which an existing final target is truncated or swapped,
// and no window in which a partially visible final name exists. The
// staging link is then unlinked, leaving exactly one link under the
// final name.
//
// The returned bool reports whether THE FINAL LINK WAS CREATED, and it
// is independent of the error. The two steps can disagree: once linkat
// succeeds the final name is visible and stays visible even if the
// staging unlink then fails, so that case returns (true, err). The
// caller records the final name as published from the bool alone, which
// is what keeps a published file out of any deletion path (guarantee 3)
// and out of the "silently unaccounted" category.
//
// os.Rename is deliberately NOT used: it replaces an existing target
// silently, which is exactly what this must prevent. A
// renameat2(RENAME_NOREPLACE) implementation would be equally
// acceptable; linkat is used because its syscall number is stable and
// exported on every Linux architecture, and because the staged file
// stays reachable until the link succeeds (nothing is lost when the
// link is refused).
//
// The staging unlink is safe to do by name: it targets the staging
// directory this call created, whose name carries 128 bits of entropy,
// through the descriptor still held for it, so the name cannot be
// re-pointed at an object owned by anyone else. That is precisely the
// property final names lack, which is why final names are never
// unlinked.
func publishLinux(dir, staging *dirHandle, name string) (bool, error) {
	if err := linkatLinux(staging.fd, name, dir.fd, name, 0); err != nil {
		return false, safex.New(safex.CodeIO, "cannot publish output file")
	}
	// The final name now exists — report that even if the next step
	// fails. Dropping the staging link is cleanup, not publication.
	if err := unlinkatLinux(staging.fd, name, 0); err != nil {
		return true, safex.New(safex.CodeIO, "cannot remove staged file")
	}
	return true, nil
}

// removeIfSameAtLinux removes name relative to dir only while its
// dev/ino still equals what this call created, tolerating an
// already-absent entry (publication already consumed the link) and
// refusing an identity mismatch.
//
// It is called ONLY on the held staging directory. The stat-then-unlink
// shape is not a safe guard in general (unlinkat takes a name, so the
// name can be re-pointed between the two syscalls), and it is NOT used
// on final published names for exactly that reason. Here the directory
// is this call's private, high-entropy staging directory reached through
// a held descriptor, so no other writer can name an entry inside it.
func removeIfSameAtLinux(dir *dirHandle, name string, want inodeID) error {
	if !want.valid {
		return safex.New(safex.CodeIO, "cannot verify output file identity for cleanup")
	}
	st, err := statAtLinux(dir, name)
	if err != nil {
		// Publication consumes the staged link, so an absent entry
		// here is the normal case, not an error. err is the raw errno.
		if os.IsNotExist(err) {
			return nil
		}
		return safex.New(safex.CodeIO, "cannot inspect output file for cleanup")
	}
	got := inodeID{dev: uint64(st.Dev), ino: uint64(st.Ino), valid: true}
	if got.dev != want.dev || got.ino != want.ino {
		return safex.New(safex.RenderUnsafe, "output file was replaced; refusing to remove it")
	}
	if err := unlinkatLinux(dir.fd, name, 0); err != nil {
		return safex.New(safex.CodeIO, "cannot remove output file")
	}
	return nil
}

func rmdirAtLinux(dir *dirHandle, name string) error {
	if err := unlinkatLinux(dir.fd, name, atRemovedir); err != nil {
		return safex.New(safex.CodeIO, "cannot remove staging directory")
	}
	return nil
}

// syncDirLinux fsyncs the open directory descriptor so the new
// directory entries survive a crash.
func syncDirLinux(dir *dirHandle) error {
	if err := syscall.Fsync(dir.fd); err != nil {
		return safex.New(safex.CodeIO, "cannot sync output dir")
	}
	return nil
}

// statInfo is the minimal os.FileInfo the identity checks need.
type statInfo struct {
	name string
	mode os.FileMode
}

func newStatInfo(name string, st *syscall.Stat_t) statInfo {
	mode := os.FileMode(st.Mode & 0o777)
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		mode |= os.ModeDir
	case syscall.S_IFLNK:
		mode |= os.ModeSymlink
	}
	return statInfo{name: name, mode: mode}
}

func (s statInfo) Name() string       { return s.name }
func (s statInfo) Size() int64        { return 0 }
func (s statInfo) Mode() os.FileMode  { return s.mode }
func (s statInfo) ModTime() time.Time { return time.Time{} }
func (s statInfo) IsDir() bool        { return s.mode&os.ModeDir != 0 }
func (s statInfo) Sys() any           { return nil }
