//go:build linux

package credential

import "syscall"

// openat wraps the maintained syscall.Openat on Linux. dirfd < 0 means
// path is absolute (the dirfd is ignored), matching POSIX usage.
func openat(dirfd int, path string, flags int) (int, error) {
	return syscall.Openat(dirfd, path, flags, 0)
}
