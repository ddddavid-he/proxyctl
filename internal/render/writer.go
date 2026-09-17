package render

import (
	"os"
	"strings"

	"proxyctl/internal/safex"
)

const (
	// outputDirPerm is the only accepted permission mask for the output
	// directory: caller-isolated, owner-only.
	outputDirPerm os.FileMode = 0o700
	// outputFilePerm is the mode every staged (and therefore published)
	// credential file gets.
	outputFilePerm os.FileMode = 0o600
	// stagingPrefix makes the transaction staging directory hidden and
	// recognizable inside the output directory.
	stagingPrefix = ".proxyctl-render-"
	// stagingRandomBytes is the entropy size of the staging directory
	// suffix (32 hex characters).
	stagingRandomBytes = 16
)

// outputNameOrder is the fixed publication order of writeTransaction.
// It is also the exact allowlist: every requested file name must appear
// here, so no other name can ever reach the filesystem.
var outputNameOrder = []string{
	"gateway-rendered.yaml",
	"egress-rendered.yaml",
	"gateway.crt",
	"gateway.key",
	"egress.crt",
	"egress.key",
	"gateway-client.crt",
	"gateway-client.key",
	"gateway-client-ca.crt",
}

// allowedOutputNames is the allowlist membership set derived from
// outputNameOrder.
var allowedOutputNames = func() map[string]struct{} {
	m := make(map[string]struct{}, len(outputNameOrder))
	for _, n := range outputNameOrder {
		m[n] = struct{}{}
	}
	return m
}()

// dirHandle is an open, verified descriptor for a directory.
//
// It is produced once by backend.openDir (or backend.openSubdir) and
// every later step — staging mkdir, file create, publish, cleanup,
// directory fsync — is performed RELATIVE TO IT. Re-resolving a string
// path after a check is a check-then-use race: whoever can swap a path
// component between the check and the use makes the check describe a
// different object than the one acted on. Holding the descriptor (and
// the backend's own object reference behind it) pins the identity for
// the whole transaction.
type dirHandle struct {
	// fd is the platform descriptor, owned by this handle. It is >= 0
	// only for a successfully opened directory; unsupported targets
	// never produce a handle.
	fd int
}

// inodeID identifies one object by device and inode. It is captured
// atomically with the create (fstat of the OPEN descriptor) and used
// ONLY for staging-directory cleanup: rollback refuses to remove a
// staged entry whose identity has since changed. Final published names
// are never identified for deletion because they are never deleted —
// see guarantee 3.
type inodeID struct {
	dev uint64
	ino uint64
	// valid reports whether the identity was captured. false disables
	// the guarded delete: an unidentified object is never removed.
	valid bool
}

// file is the write side of a staged file.
type file interface {
	write(data []byte) error
	sync() error
	close() error
}

// backend is the complete filesystem boundary of writeTransactionWithBackend.
// Every method takes the held directory descriptor: no method takes the
// output-directory string path except openDir, which runs exactly once.
//
// A backend is an immutable value produced by defaultBackend(); nothing
// in the transaction is package-global mutable state, so concurrent
// calls cannot observe or disturb each other.
type backend struct {
	// openDir opens and verifies the output directory and returns a
	// handle owning a descriptor. The production implementation walks
	// every path component with O_NOFOLLOW|O_DIRECTORY, so no symlink
	// at ANY depth is followed; the 0700 check is applied to the fstat
	// of the final OPEN descriptor, never to a path Lstat.
	openDir func(path string) (*dirHandle, error)
	// openSubdir opens an existing subdirectory of dir, returning a
	// handle pinned to that subdirectory.
	openSubdir func(dir *dirHandle, name string) (*dirHandle, error)
	// closeDir releases a descriptor.
	closeDir func(dir *dirHandle) error
	// lstatAt stats name relative to dir without following a final
	// symlink. A missing name yields an error satisfying
	// os.IsNotExist.
	lstatAt func(dir *dirHandle, name string) (os.FileInfo, error)
	// createAt creates and opens name relative to dir with
	// O_CREAT|O_EXCL|O_NOFOLLOW at perm, returning the identity
	// (dev/ino) of the very inode it created. Returning the identity
	// with the handle is deliberate: the fstat happens on the OPEN
	// descriptor, so the identity is captured atomically with the
	// create and can never belong to a later replacement.
	createAt func(dir *dirHandle, name string, perm os.FileMode) (file, inodeID, error)
	// mkdirAt creates name as a directory relative to dir.
	mkdirAt func(dir *dirHandle, name string, perm os.FileMode) error
	// publish makes the staged file visible under its final name in
	// dir WITHOUT REPLACING an existing entry. It must fail atomically
	// (EEXIST) when the final name already exists — os.Rename, which
	// replaces silently, is forbidden. See writer_linux.go.
	//
	// The bool reports whether THE FINAL LINK WAS CREATED, and it is
	// authoritative independently of the error: publication is a link
	// followed by the removal of the staging link, so the second step
	// can fail after the first has already made the final name
	// visible. In that case publish returns (true, err). Reporting the
	// two facts separately is what lets the caller record the final
	// name as published — and therefore as something rollback must
	// keep — instead of inferring "not published" from the error and
	// leaving an unaccounted file behind.
	publish func(dir, staging *dirHandle, name string) (linked bool, err error)
	// removeIfSameAt removes name relative to dir only when its
	// dev/ino still equals want, tolerating an already-absent entry
	// (publication consumes the staged link). Identity mismatch is
	// refused.
	//
	// It is called ONLY on the held staging directory. There is
	// deliberately no counterpart for final published names: see
	// guarantee 3 — published files are never deleted.
	removeIfSameAt func(dir *dirHandle, name string, want inodeID) error
	// rmdirAt removes an empty directory relative to dir.
	rmdirAt func(dir *dirHandle, name string) error
	// syncDir fsyncs the directory descriptor.
	syncDir func(dir *dirHandle) error
	// randomSuffix returns the random part of the staging dir name.
	randomSuffix func() (string, error)
}

// writeTransaction is the production entry point. It validates the
// request and the output directory under the platform default backend,
// which is produced fresh per call (no shared mutable state).
func writeTransaction(outDir string, files map[string][]byte) error {
	return writeTransactionWithBackend(outDir, files, defaultBackend())
}

// writeTransactionWithBackend publishes files into outDir.
//
// GUARANTEES, stated exactly:
//
//  1. NO-REPLACE PUBLISH, PER FILE, ATOMIC. A final target is never
//     replaced. Publication uses linkat (Linux), which creates the
//     final name and fails with EEXIST when it already exists, in one
//     atomic operation: there is no window in which an existing target
//     is truncated or swapped. os.Rename — which replaces silently —
//     is never used. A pre-publication existence check also runs, but
//     it is only an early refusal: the guarantee is the no-replace
//     publish, which still holds if the target appears after the check.
//
//  2. DESCRIPTOR-RELATIVE, WHOLE-PATH VERIFIED. openDir resolves the
//     output directory one component at a time under O_NOFOLLOW, so no
//     symlink at any depth — not just the final component — is ever
//     followed, and ".." is rejected. After openDir the path is never
//     resolved again: every staging, create, publish, cleanup and fsync
//     step is relative to the held descriptor, so replacing the output
//     directory path mid-transaction cannot redirect a write.
//
//  3. PUBLISHED FILES ARE NEVER DELETED. Rollback NEVER unlinks a
//     final published name. It only cleans UNPUBLISHED staged entries,
//     and only inside the staging directory this call created, through
//     the descriptor it still holds — a directory whose name carries
//     128 bits of entropy and which no other writer can name.
//
//     This is a deliberate replacement of a dev/ino-guarded delete of
//     final entries. That guard could not be made safe: stat-then-
//     unlink is two syscalls, and unlinkat() takes a NAME, not an
//     inode. Whatever the stat observed, the name can be re-pointed at
//     a different object before the unlink runs, and the unlink then
//     destroys that object. The check narrows the window; it cannot
//     close it, because the kernel offers no "unlink this name only if
//     it still resolves to this inode". Since a credential file that
//     was published is exactly the file an attacker wants egress to
//     unlink, the operation is removed rather than guarded: residue is
//     recoverable, deleting the wrong file is not.
//
//     When any published name exists at rollback time the call returns
//     the fixed bundle-state-undefined error demanding manual cleanup
//     (errBundleStateUndefined), and the published files stay on disk.
//
//  4. DURABILITY. Every staged file is fsynced before publication. The
//     output directory is fsynced immediately after the last publish —
//     before the staging directory is removed, so persistence of the
//     published entries never depends on cleanup — and again after the
//     removal, so a crash cannot resurrect the staging entry.
//
//  5. BEST-EFFORT ROLLBACK, NOT ATOMIC AS A SET. The bundle is NOT
//     atomic. A per-file publish is atomic and no-replace; the SET is
//     not rolled back at all once a name is published (guarantee 3). A
//     crash, ENOSPC, a killed process, or a cleanup refusal can leave a
//     partial bundle on disk. Callers must treat an error as "bundle
//     state undefined", never as "nothing was written".
//
//  6. NON-SILENT CLEANUP. A cleanup failure is reported: it replaces
//     the returned error rather than being swallowed.
//
//  7. SYNCHRONOUS WRITE, NO RETENTION. Every bytes value in files is
//     written inside this call, and no reference to it is kept
//     afterwards. The caller may therefore overwrite its own buffers the
//     moment writeTransactionWithBackend returns — which render does on
//     every path, to zero the rendered config and the materialized asset
//     copies while they still hold live secret material.
//
//     A backend that deferred a write or retained the slice would
//     silently write zeroed data, so this is a hard contract on every
//     implementation. The production backend writes through the held
//     descriptor during the call and stores nothing; an injected backend
//     must do the same. To copy data it needs to keep, a backend copies
//     it explicitly.
//
// All errors carry fixed messages: no path, file name or payload byte
// is echoed and no underlying cause is wrapped.
func writeTransactionWithBackend(outDir string, files map[string][]byte, b backend) (err error) {
	names, err := validateOutputNames(files)
	if err != nil {
		return err
	}
	if outDir == "" {
		return safex.New(safex.CodeUsage, "output dir is required")
	}
	for _, part := range strings.Split(outDir, "/") {
		if part == ".." {
			return safex.New(safex.RenderUnsafe, "path traversal rejected in output dir")
		}
	}
	// Open and verify the directory ONCE. From here on every step is
	// descriptor-relative: the string path is never resolved again.
	dir, err := b.openDir(outDir)
	if err != nil {
		return err
	}
	defer b.closeDir(dir)

	// Empty request: the directory contract is still validated above,
	// then return before any staging state exists.
	if len(names) == 0 {
		return nil
	}

	// Early refusal for an existing final target. NOT the guarantee —
	// see guarantee 1: publish itself is no-replace.
	for _, name := range names {
		fi, lerr := b.lstatAt(dir, name)
		if lerr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return safex.New(safex.RenderUnsafe, "output path is a symlink; refusing to write")
			}
			return safex.New(safex.RenderUnsafe, "output path already exists; refusing to overwrite")
		}
		if !os.IsNotExist(lerr) {
			return safex.New(safex.RenderUnsafe, "output path cannot be inspected; refusing to write")
		}
	}

	suffix, err := b.randomSuffix()
	if err != nil {
		return err
	}
	stagingName := stagingPrefix + suffix
	if err := b.mkdirAt(dir, stagingName, outputDirPerm); err != nil {
		return err
	}
	staging, err := b.openSubdir(dir, stagingName)
	if err != nil {
		if rerr := b.rmdirAt(dir, stagingName); rerr != nil {
			return rerr
		}
		return err
	}
	defer b.closeDir(staging)

	// staged records what this call created inside the staging
	// directory; published records the final names this call made
	// visible. A name is moved from "to clean" to "must be retained"
	// the instant its final link exists.
	staged := make(map[string]inodeID, len(names))
	published := make(map[string]struct{}, len(names))
	committed := false
	defer func() {
		if committed {
			return
		}
		// Cleanup failure is never silent: it becomes the returned
		// error so the caller learns the bundle state is undefined.
		if cerr := rollback(b, dir, staging, stagingName, staged, published); cerr != nil {
			err = cerr
		}
	}()

	for _, name := range names {
		f, id, cerr := b.createAt(staging, name, outputFilePerm)
		if cerr != nil {
			return cerr
		}
		staged[name] = id
		if werr := f.write(files[name]); werr != nil {
			f.close()
			return safex.New(safex.CodeIO, "cannot write output file")
		}
		if serr := f.sync(); serr != nil {
			f.close()
			return safex.New(safex.CodeIO, "cannot sync output file")
		}
		if clerr := f.close(); clerr != nil {
			return safex.New(safex.CodeIO, "cannot close output file")
		}
	}
	// Publication: per-file atomic no-replace; the set is best-effort.
	for _, name := range names {
		linked, perr := b.publish(dir, staging, name)
		// Record the final name as published BEFORE inspecting the
		// error. publish reports link creation independently of
		// failure (a staging-unlink failure leaves the final link in
		// place), and rollback must retain — never delete — every
		// published name. Recording first means no ordering of the two
		// results can lose that fact.
		if linked {
			published[name] = struct{}{}
		}
		if perr != nil {
			return perr
		}
	}
	// Durability BEFORE cleanup: the published entries must survive a
	// crash whether or not the staging removal below succeeds. Doing
	// the fsync first means guarantee 4 never depends on cleanup.
	if serr := b.syncDir(dir); serr != nil {
		return serr
	}
	// Publication consumed every staged link, so staging is empty and
	// the rmdir can only fail for a real reason — which is reported,
	// never swallowed (guarantee 6).
	if rerr := b.rmdirAt(dir, stagingName); rerr != nil {
		return rerr
	}
	// Second fsync: persist the staging directory's REMOVAL, so a crash
	// here cannot resurrect the staging entry as residue. The publish
	// entries are already durable from the fsync above.
	if serr := b.syncDir(dir); serr != nil {
		return serr
	}
	committed = true
	return nil
}

// errBundleStateUndefined is the fixed error a rollback returns when
// any final name was already published. The published files are LEFT ON
// DISK (guarantee 3) and the operator must inspect and remove them: the
// message says exactly that and nothing else — no path, no file name.
//
// It is a single package-level value, so a caller (or a test) can
// identify the condition by identity instead of by matching text, and
// the code stays CodeIO: this is a partially completed write that left
// residue, not a refusal to render.
var errBundleStateUndefined = safex.New(safex.CodeIO,
	"output bundle state undefined; published files retained, manual cleanup required")

// rollback cleans up a failed transaction WITHOUT EVER DELETING A
// PUBLISHED FINAL NAME.
//
// What it does, exactly:
//
//   - Every entry still present in the staging directory is removed,
//     in reverse publication order, through the HELD staging
//     descriptor and only while its dev/ino still equals what this
//     call created. Those entries are unpublished by definition: a
//     published name has its own final link, and a staged entry that
//     was already consumed by publication is simply absent (tolerated).
//     The staging directory's name carries 128 bits of entropy and was
//     created by this call, so nothing another writer owns can be
//     reached here.
//
//   - The staging directory itself is rmdir'ed. It is only removed when
//     empty, so a refused entry removal above surfaces here too.
//
//   - Published final names are RETAINED. Not stat'ed, not unlinked,
//     not touched. When at least one exists, the fixed
//     bundle-state-undefined error is returned so the caller cannot
//     mistake the outcome for "nothing was written", and the operator
//     is told to clean up manually.
//
// Why published names are not deleted even under a dev/ino guard: the
// guard would be stat-then-unlink, and unlinkat() takes a NAME. Between
// the stat that approved the inode and the unlink that acts on the
// name, the name can be re-pointed at another object, which the unlink
// then destroys. No kernel primitive removes "this name only if it
// still resolves to this inode", so the window cannot be closed — only
// narrowed. Residue is recoverable; deleting a file that is not ours is
// not. See guarantee 3.
//
// Removal failures are returned, never swallowed. The published-name
// error takes precedence because it is the more serious statement about
// the resulting on-disk state.
func rollback(b backend, dir, staging *dirHandle, stagingName string, staged map[string]inodeID, published map[string]struct{}) error {
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for i := len(outputNameOrder) - 1; i >= 0; i-- {
		name := outputNameOrder[i]
		id, ok := staged[name]
		if !ok {
			continue
		}
		if _, isPublished := published[name]; isPublished {
			// The final link exists. The staging link, if publication
			// managed to drop it, is gone; if it did not, removing it
			// here would be operating on an inode that is now reachable
			// under its final name, so it is left to manual cleanup
			// together with the published entry.
			continue
		}
		// Publication consumes the staged link, so an absent entry
		// here is normal and not an error.
		if err := b.removeIfSameAt(staging, name, id); err != nil {
			fail(err)
		}
	}
	// The staging directory is only removed when it is ours and empty;
	// a non-empty staging dir (a refused removal above) is reported.
	if err := b.rmdirAt(dir, stagingName); err != nil {
		fail(err)
	}
	// Published finals are retained: state is undefined and the
	// operator must clean up. This outranks a cleanup error.
	if len(published) != 0 {
		return errBundleStateUndefined
	}
	return firstErr
}

// validateOutputNames returns the requested names in the fixed
// publication order, rejecting unknown names and any name carrying a
// path separator. Duplicates are structurally impossible: files is a
// map keyed by file name, so the loop below can never see the same name
// twice and no duplicate branch exists.
func validateOutputNames(files map[string][]byte) ([]string, error) {
	for name := range files {
		if strings.ContainsAny(name, `/\`) {
			return nil, safex.New(safex.RenderUnsafe, "output file name must not contain a path separator")
		}
		if _, ok := allowedOutputNames[name]; !ok {
			return nil, safex.New(safex.RenderUnsafe, "output file name is not allowed")
		}
	}
	ordered := make([]string, 0, len(files))
	for _, name := range outputNameOrder {
		if _, ok := files[name]; ok {
			ordered = append(ordered, name)
		}
	}
	return ordered, nil
}
