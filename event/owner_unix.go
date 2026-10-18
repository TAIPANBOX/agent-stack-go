//go:build unix

package event

import (
	"errors"
	"os"
	"syscall"
)

// dirOwnedByUs reports whether dir's owner is this process's effective uid.
func dirOwnedByUs(dir string) (bool, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("event: the owner of " + dir + " cannot be read, so no file is created in it")
	}
	return int(st.Uid) == os.Geteuid(), nil
}
