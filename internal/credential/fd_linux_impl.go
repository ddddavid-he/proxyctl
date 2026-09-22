//go:build linux

package credential

import (
	"io"
	"os"
	"syscall"

	"proxyctl/internal/safex"
)

// dirFD holds an open descriptor for a credential directory. All file
// reads are performed relative to this descriptor (openat-style), so
// swapping path components after the directory was opened cannot
// redirect a read. The descriptor is held until the load completes.
type dirFD struct {
	fd int
}

func (d *dirFD) close() {
	if d.fd >= 0 {
		syscall.Close(d.fd)
		d.fd = -1
	}
}

// openDirNoFollow opens the directory named by path relative to the
// parent descriptor dirfd (dirfd < 0 means path is absolute). The open
// uses O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC. Error classification is by
// OPERATION CONTEXT (directory open), not by forcing specific errnos:
// for a directory open, ENOENT is the stable not-found, while ENOTDIR
// and ELOOP both mean the component is not a real directory (a symlink
// or non-directory in the path) and are RenderUnsafe. The descriptor
// is fstat-verified to be a real directory before use.
func openDirNoFollow(dirfd int, path string) (*dirFD, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	var fd int
	var err error
	if dirfd >= 0 {
		fd, err = openat(dirfd, path, flags)
	} else {
		fd, err = openat(-1, path, flags) // absolute path: dirfd ignored
	}
	if err != nil {
		return nil, mapDirOpenErrno(err)
	}
	d := &dirFD{fd: fd}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		d.close()
		return nil, safex.New(safex.CodeIO, "credentials directory cannot be inspected")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		d.close()
		return nil, safex.New(safex.RenderUnsafe, "credentials directory is not a directory")
	}
	return d, nil
}

// metadata returns content-free inode metadata for the open directory.
func (d *dirFD) metadata() (credentialMetadata, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(d.fd, &st); err != nil {
		return credentialMetadata{}, safex.New(safex.CodeIO, "credentials directory cannot be inspected")
	}
	return credentialMetadata{
		mode: os.FileMode(st.Mode & 0o777),
		uid:  st.Uid,
		gid:  st.Gid,
	}, nil
}

// readNames lists the entry names of the open directory. It uses a
// dup'ed *os.File so os.ReadDir semantics apply without disturbing the
// raw descriptor's lifetime.
func (d *dirFD) readNames() ([]string, error) {
	// os.NewFile takes ownership of the fd it is given; duplicate so
	// the raw descriptor stays owned by dirFD.
	dup, err := syscall.Dup(d.fd)
	if err != nil {
		return nil, safex.New(safex.CodeIO, "credentials directory cannot be listed")
	}
	f := os.NewFile(uintptr(dup), "credentials")
	if f == nil {
		syscall.Close(dup)
		return nil, safex.New(safex.CodeIO, "credentials directory cannot be listed")
	}
	defer f.Close()
	// Bounded enumeration: ReadDir in fixed batches with a hard entry
	// cap, so a pathological or swapped-in directory cannot turn one
	// load into unbounded enumeration work. Exceeding the cap fails
	// closed with a fixed message (no entry names, no counts from the
	// attacker side beyond the fixed bound).
	names := make([]string, 0, 16)
	for {
		entries, err := f.ReadDir(64)
		if len(entries) > 0 {
			if len(names)+len(entries) > maxCredentialEntries {
				return nil, safex.New(safex.CodeConfigRejected, "credentials directory exceeds entry limit")
			}
			for _, e := range entries {
				names = append(names, e.Name())
			}
		}
		if err == io.EOF {
			return names, nil
		}
		if err != nil {
			return nil, safex.New(safex.CodeIO, "credentials directory cannot be listed")
		}
	}
}

// readFile opens one plain-named credential file relative to the
// directory descriptor with O_NOFOLLOW|O_CLOEXEC, then fstats the OPEN
// descriptor and enforces the full contract (regular file, restrictive
// permissions, size cap) on the opened inode. Opening with O_NOFOLLOW
// already fails on a symlinked final component, and the fstat is on
// the very inode we read, so no pre-open stat is needed (no check-then-
// open window at all).
func (d *dirFD) readFile(name string) ([]byte, error) {
	fd, err := openat(d.fd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, mapFileOpenErrno(err)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		syscall.Close(fd)
		return nil, safex.New(safex.CodeIO, "credential cannot be opened")
	}
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, safex.New(safex.CodeIO, "credential cannot be inspected")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, safex.New(safex.RenderUnsafe, "credential is not a regular file")
	}
	meta := credentialMetadata{
		mode: os.FileMode(st.Mode & 0o777),
		uid:  st.Uid,
		gid:  st.Gid,
	}
	if !secureCredentialMetadata(meta, false) {
		return nil, safex.New(safex.CodePermission, "credential permissions are unsafe")
	}
	if st.Size > maxAssetBytes {
		return nil, safex.New(safex.CodeConfigRejected, "credential exceeds size limit")
	}
	if st.Size < 0 {
		// Defensive: a non-regular node reaching this point with a
		// negative size must never drive an allocation.
		return nil, safex.New(safex.CodeConfigRejected, "credential exceeds size limit")
	}

	// Bounded read: allocate up-front from the fstat'ed size of the
	// very inode we hold open (regular file, size already capped), and
	// read with io.ReadFull so the read work is bounded by that fixed
	// size even if the file is being concurrently truncated/extended
	// (short read -> hard failure; appended garbage past the stat'ed
	// size is ignored, never silently consumed).
	data := make([]byte, int(st.Size))
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, safex.New(safex.CodeIO, "credential cannot be read")
	}
	return data, nil
}

// mapDirOpenErrno classifies errors from opening a DIRECTORY. Only
// ENOENT is the stable not-found. ENOTDIR and ELOOP both mean the
// component is not a real directory (symlink or non-directory in the
// path) and are unsafe; permission is distinct. Underlying OS text is
// never surfaced.
func mapDirOpenErrno(err error) error {
	switch err {
	case syscall.ENOENT:
		return errNotFound
	case syscall.ENOTDIR, syscall.ELOOP:
		return safex.New(safex.RenderUnsafe, "credentials directory path is not a real directory")
	case syscall.EACCES, syscall.EPERM:
		return safex.New(safex.CodePermission, "credential access denied")
	}
	return safex.New(safex.CodeIO, "credential cannot be accessed")
}

// mapFileOpenErrno classifies errors from opening a credential FILE.
// ENOENT/ENOTDIR are the stable not-found (the only ignorable
// condition for optional credentials); ELOOP means a symlinked final
// component (unsafe); permission is distinct.
func mapFileOpenErrno(err error) error {
	switch err {
	case syscall.ENOENT, syscall.ENOTDIR:
		return errNotFound
	case syscall.ELOOP:
		return safex.New(safex.RenderUnsafe, "credential must not be a symlink")
	case syscall.EACCES, syscall.EPERM:
		return safex.New(safex.CodePermission, "credential access denied")
	}
	return safex.New(safex.CodeIO, "credential cannot be accessed")
}
