//go:build linux || windows

package authstore

func credentialDirectory(path string) (string, error) {
	// EvalSymlinks already restores the case of path components on Windows.
	return path, nil
}
