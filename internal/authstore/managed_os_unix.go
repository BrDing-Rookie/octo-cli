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

func openExistingManagedFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func managedFileLinkCount(file *os.File) (uint64, error) {
	var info unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &info)
	return uint64(info.Nlink), err
}

func replaceManagedFile(from, to string) (bool, error) {
	if err := os.Rename(from, to); err != nil {
		return false, err
	}
	return true, syncManagedDirectory(filepath.Dir(to))
}

func syncManagedDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func protectManagedPath(path string, info os.FileInfo, perm os.FileMode) error {
	if err := checkManagedACL(path); err != nil {
		return err
	}
	if info.Mode().Perm() != perm {
		return os.Chmod(path, perm)
	}
	return nil
}

func checkManagedFilePrivacy(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed storage file must be private")
	}
	return checkManagedACL(path)
}
