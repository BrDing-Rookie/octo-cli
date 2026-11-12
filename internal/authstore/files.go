package authstore

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func (s *Store) checkDir(create bool) (bool, error) {
	info, err := os.Lstat(s.dir)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := os.MkdirAll(filepath.Dir(s.dir), 0o700); err != nil {
			return false, err
		}
		if err := makePrivateDir(s.dir); err != nil && !errors.Is(err, fs.ErrExist) {
			return false, err
		}
		info, err = os.Lstat(s.dir)
	}
	if errors.Is(err, fs.ErrNotExist) && !create {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, storeError("configuration path is not a directory")
	}
	return true, checkPrivate(s.dir, info, nil)
}

func lockDirectory(ctx context.Context, dir string) (func(), error) {
	file, err := openPrivate(filepath.Join(dir, ".lock"), true)
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		unlock, err := tryLock(file)
		if err != nil {
			_ = file.Close() //nolint:errcheck // preserve the locking failure
			return nil, err
		}
		if unlock != nil {
			return func() {
				unlock()
				_ = file.Close() //nolint:errcheck // no buffered writes on the lock file
			}, nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
		}
	}
	_ = file.Close() //nolint:errcheck // preserve the cancellation error
	return nil, ctx.Err()
}

func openPrivate(path string, create bool) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return nil, storeError("managed path is not a regular file")
	}
	if err != nil && (!create || !errors.Is(err, fs.ErrNotExist)) {
		return nil, err
	}

	file, err := openManagedFile(path, create)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err == nil {
		if !info.Mode().IsRegular() {
			err = storeError("managed path is not a regular file")
		} else {
			err = checkPrivate(path, info, file)
		}
	}
	if err != nil {
		_ = file.Close() //nolint:errcheck // preserve the validation error
		return nil, err
	}
	return file, nil
}

func readPrivate(path string) ([]byte, error) {
	file, err := openPrivate(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck // read-only file
	return io.ReadAll(file)
}

// writePrivate reports whether the rename made the new file visible, including
// when the following directory sync fails.
func writePrivate(ctx context.Context, path string, data []byte) (bool, error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return false, err
	}
	name := temp.Name()
	defer func() {
		_ = temp.Close()    //nolint:errcheck // already closed on the publication path
		_ = os.Remove(name) //nolint:errcheck // no-op after rename
	}()
	info, err := temp.Stat()
	if err != nil {
		return false, err
	}
	if err := checkPrivate(name, info, temp); err != nil {
		return false, err
	}
	if _, err := temp.Write(data); err != nil {
		return false, err
	}
	if err := temp.Sync(); err != nil {
		return false, err
	}
	if err := temp.Close(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := replaceFile(name, path); err != nil {
		return false, err
	}
	return true, syncDirectory(dir)
}
