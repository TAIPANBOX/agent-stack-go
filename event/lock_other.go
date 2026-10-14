//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package event

import "os"

// Where flock(2) does not exist (Windows among the release targets) there is
// no cross-process lock. ChainedWriter still re-reads the tail of the file
// before every append and still serializes its own goroutines, but nothing
// stops ANOTHER process appending to the same file between that read and the
// append. No bus in the estate is written from such a platform; the
// agent-conform release for Windows writes only its own watch-dir stream.
func lockExclusive(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
