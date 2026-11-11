//go:build !darwin && !linux && !windows

package authstore

import (
	"context"
	"errors"
	"os"
)

func syncManagedDirectory(string) error { return nil }

func checkAtomicReplaceTarget(string) error { return nil }

func openExistingManagedFile(string) (*os.File, error) {
	return nil, errors.New("managed credential writes are unavailable on this platform")
}

func managedFileLinkCount(*os.File) (uint64, error) {
	return 0, errors.New("managed credential writes are unavailable on this platform")
}

func tryLockManagedFile(*os.File) (bool, error) {
	return false, errors.New("managed credential writes are unavailable on this platform")
}

func replaceManagedFile(context.Context, string, string) (bool, error) {
	return false, errors.New("managed credential writes are unavailable on this platform")
}

func publishManagedAnchor(ctx context.Context, stage, anchor string) (bool, error) {
	return replaceManagedFile(ctx, stage, anchor)
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
