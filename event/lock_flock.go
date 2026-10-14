//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package event

import (
	"os"
	"syscall"
)

// lockExclusive takes flock(2) LOCK_EX on f, blocking until it is granted.
//
// flock and not fcntl, for one reason that matters here: a flock lock belongs
// to the open file description, so two ChainedWriters in ONE process on one
// path exclude each other as two processes do, and closing an unrelated
// descriptor of the same file (a verifier opening it to read, say) does not
// release it. An fcntl lock belongs to the process and has both faults.
//
// On a Linux NFS client flock is emulated with a whole-file byte-range lock
// that the server arbitrates, which is what makes it hold across nodes on an
// NFS share, and taking it is the client's cache coherency point: the cached
// size and pages of the file are revalidated, and releasing it writes back
// what was written under it. Both halves are what Write relies on, and the
// live measurement is in the pull request that added this file.
//
// EINTR is retried: the Go runtime preempts with signals, and a blocking flock
// interrupted by one returns EINTR rather than a lock.
func lockExclusive(f *os.File) error {
	return flock(f, syscall.LOCK_EX)
}

// unlockFile releases the lock lockExclusive took on f.
func unlockFile(f *os.File) error {
	return flock(f, syscall.LOCK_UN)
}

func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = syscall.Flock(int(fd), how)
			if ferr != syscall.EINTR {
				return
			}
		}
	}); err != nil {
		return err
	}
	return ferr
}
