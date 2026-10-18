//go:build !unix

package event

import "errors"

// dirOwnedByUs cannot read a directory's owner on this platform, so it answers
// no: a writer refuses to create a file it cannot place. No bus runs here (see
// invariant 27); existing files are still opened.
func dirOwnedByUs(dir string) (bool, error) {
	return false, errors.New("event: the owner of " + dir + " cannot be read on this platform, so no file is created in it")
}
