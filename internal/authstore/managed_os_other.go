//go:build !darwin && !linux && !windows

package authstore

import (
	"errors"
	"os"
)

func lockManagedFile(*os.File) error {
	return errors.New("managed credential writes are unavailable on this platform")
}

func replaceManagedFile(string, string) (bool, error) {
	return false, errors.New("managed credential writes are unavailable on this platform")
}
