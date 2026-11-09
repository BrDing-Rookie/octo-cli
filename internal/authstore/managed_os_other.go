//go:build !darwin && !linux && !windows

package authstore

import (
	"errors"
	"os"
)

func syncManagedDirectory(string) error { return nil }

func lockManagedFile(*os.File) error {
	return errors.New("managed credential writes are unavailable on this platform")
}

func replaceManagedFile(string, string) (bool, error) {
	return false, errors.New("managed credential writes are unavailable on this platform")
}

func protectManagedPath(string, os.FileInfo, os.FileMode) error {
	return errors.New("managed credential writes are unavailable on this platform")
}

func checkManagedFilePrivacy(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed storage file must be private")
	}
	return nil
}
