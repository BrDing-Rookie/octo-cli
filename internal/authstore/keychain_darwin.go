package authstore

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"strings"
)

type nativeStore struct{}

// Put saves a new credential in the platform store.
func (nativeStore) Put(ctx context.Context, account, token string) error {
	// In interactive mode security reads the command from a pipe. Neither the
	// token nor its encoding is passed as a process argument.
	line := "add-generic-password -s " + keychainService + " -a " + account + " -w " + encodeSecret(token) + "\n"
	if len(line) >= 4096 {
		return storeError("credential exceeds the system storage limit")
	}
	_, stderr, err := runKeychainTool(ctx, "/usr/bin/security", line, "-q", "-i")
	// Interactive mode can report command failures with a zero exit status.
	if err == nil && stderr != "" {
		err = storeError("macOS Keychain rejected the credential")
	}
	return macKeychainError(stderr, err)
}

// Get reads the credential for the namespaced account.
func (nativeStore) Get(ctx context.Context, account string) (string, error) {
	data, stderr, err := runKeychainTool(ctx, "/usr/bin/security", "", "find-generic-password", "-w", "-s", keychainService, "-a", account)
	if err := macKeychainError(stderr, err); err != nil {
		return "", err
	}
	return decodeSecret(data)
}

// Delete removes the credential for the namespaced account.
func (nativeStore) Delete(ctx context.Context, account string) error {
	_, stderr, err := runKeychainTool(ctx, "/usr/bin/security", "", "delete-generic-password", "-s", keychainService, "-a", account)
	return macKeychainError(stderr, err)
}

func macKeychainError(stderr string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist),
		strings.Contains(stderr, "No keychain is available."),
		strings.Contains(stderr, "A default keychain could not be found."),
		strings.Contains(stderr, "The specified keychain could not be found."):
		return ErrUnavailable
	case strings.Contains(stderr, "The specified item could not be found in the keychain."):
		return fs.ErrNotExist
	case errors.Is(err, fs.ErrPermission),
		strings.Contains(stderr, "User interaction is not allowed."),
		strings.Contains(stderr, "User canceled the operation."),
		strings.Contains(stderr, "The user name or passphrase you entered is not correct."):
		return fs.ErrPermission
	default:
		return storeError("macOS Keychain operation failed")
	}
}
