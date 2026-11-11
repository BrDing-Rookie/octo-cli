//go:build darwin || linux

package authstore

import (
	"context"
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

func replaceManagedFile(ctx context.Context, from, to string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Rename(from, to); err != nil {
		return false, err
	}
	return true, syncManagedDirectory(filepath.Dir(to))
}

func publishManagedAnchor(ctx context.Context, stage, anchor string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Link(stage, anchor); err != nil {
		return false, err
	}
	return true, syncManagedDirectory(filepath.Dir(anchor))
}

func syncManagedDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// Replacing a file on Unix does not require delete access on the file or
// exclusive sharing. Mail separately checks that its directory is writable.
func checkAtomicReplaceTarget(string) error { return nil }

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
