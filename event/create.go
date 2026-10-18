package event

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// dirOwner reports whether dir belongs to this process. A variable so a test
// can make a directory somebody else's.
var dirOwner = dirOwnedByUs

// openAppend opens an event stream or a checkpoint file for appending. mode is
// os.O_WRONLY or os.O_RDWR.
//
// A file that exists is opened as it is. A file that does not is created with
// mode 0640, and only when its directory belongs to this process: a writer
// never places a file in a directory somebody else controls, because a file
// created there by the wrong uid is a file the rightful owner cannot write, and
// a writer that does not notice is a writer that cannot be trusted with the
// name (F-021). The create is exclusive, so a file another writer created in the
// meantime is opened, never re-moded.
func openAppend(path string, mode int) (*os.File, error) {
	f, err := os.OpenFile(path, mode|os.O_APPEND, 0)
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	owned, err := dirOwner(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, errors.New("event: " + path + " does not exist and its directory is not owned by this process, so it is not created here")
	}
	f, err = os.OpenFile(path, mode|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, fs.ErrExist) {
		return os.OpenFile(path, mode|os.O_APPEND, 0)
	}
	if err != nil {
		return nil, err
	}
	// The umask can only take bits away, so 0640 is set exactly on the file we
	// just made.
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
