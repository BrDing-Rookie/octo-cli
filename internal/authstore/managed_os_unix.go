//go:build darwin || linux

package authstore

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockManagedFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func replaceManagedFile(from, to string) (bool, error) {
	if err := os.Rename(from, to); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(to))
	if err != nil {
		return true, err
	}
	return true, errors.Join(dir.Sync(), dir.Close())
}
