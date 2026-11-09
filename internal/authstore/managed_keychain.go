//go:build !darwin

package authstore

import "path/filepath"

func systemKeychain() Keychain {
	return unavailableKeychain{}
}

func canonicalManagedDirectory(dir string) (string, error) {
	return filepath.EvalSymlinks(dir)
}
