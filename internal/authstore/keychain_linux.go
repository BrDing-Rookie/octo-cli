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
	_, stderr, err := runKeychainTool(ctx, "secret-tool", encodeSecret(token), "store", "--label=Octo CLI", "application", keychainService, "entry", account)
	return secretServiceError(stderr, err)
}

// Get reads the credential for the namespaced account.
func (nativeStore) Get(ctx context.Context, account string) (string, error) {
	data, stderr, err := runKeychainTool(ctx, "secret-tool", "", "lookup", "application", keychainService, "entry", account)
	if err := secretServiceError(stderr, err); err != nil {
		return "", err
	}
	return decodeSecret(data)
}

// Delete removes the credential for the namespaced account.
func (nativeStore) Delete(ctx context.Context, account string) error {
	_, stderr, err := runKeychainTool(ctx, "secret-tool", "", "clear", "application", keychainService, "entry", account)
	return secretServiceError(stderr, err)
}

func secretServiceError(stderr string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist),
		strings.Contains(stderr, "org.freedesktop.DBus.Error.ServiceUnknown"),
		strings.Contains(stderr, "org.freedesktop.DBus.Error.Spawn.ServiceNotFound"),
		strings.Contains(stderr, "Cannot autolaunch D-Bus without X11"),
		strings.Contains(stderr, "Could not connect: No such file or directory"):
		return ErrUnavailable
	case errors.Is(err, fs.ErrPermission),
		strings.Contains(stderr, "AccessDenied"),
		strings.Contains(stderr, "Permission denied"),
		strings.Contains(stderr, "IsLocked"):
		return fs.ErrPermission
	default:
		return storeError("Secret Service operation failed")
	}
}
