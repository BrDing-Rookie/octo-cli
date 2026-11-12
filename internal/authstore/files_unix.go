//go:build darwin || linux

package authstore

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func makePrivateDir(path string) error {
	return os.Mkdir(path, 0o700)
}

func checkPrivate(_ string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return fs.ErrPermission
	}
	if info.Mode().IsRegular() && stat.Nlink != 1 {
		return fs.ErrPermission
	}
	return nil
}

func openManagedFile(path string, create bool) (*os.File, error) {
	flags := os.O_RDONLY
	if create {
		flags = os.O_RDWR | os.O_CREATE
	}
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}

func tryLock(file *os.File) (func(), error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return func() {}, nil // closing the handle releases flock
}

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck // sync reports the write failure
	return dir.Sync()
}
