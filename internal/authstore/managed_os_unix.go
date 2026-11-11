//go:build darwin || linux

package authstore

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func tryLockManagedFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	return err == nil, err
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

func protectManagedPath(path string, info os.FileInfo, perm os.FileMode) error {
	if info.Mode().Perm() != perm {
		return os.Chmod(path, perm)
	}
	return nil
}

func checkManagedFilePrivacy(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed storage file must be private")
	}
	return nil
}
