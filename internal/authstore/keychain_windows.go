package authstore

import (
	"context"
	"io/fs"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	credTypeGeneric  = 1
	credPersistLocal = 2
	credentialPrefix = "com.octo-cli.profile.v1/"
)

// winCredential mirrors CREDENTIALW from wincred.h.
type winCredential struct {
	Flags          uint32
	Type           uint32
	TargetName     *uint16
	Comment        *uint16
	LastWritten    windows.Filetime
	BlobSize       uint32
	Blob           *byte
	Persist        uint32
	AttributeCount uint32
	Attributes     unsafe.Pointer
	TargetAlias    *uint16
	UserName       *uint16
}

type nativeStore struct{}

// Put saves a new credential in the platform store.
func (nativeStore) Put(ctx context.Context, account, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(credentialPrefix + account)
	if err != nil {
		return err
	}
	secret := []byte(token)
	item := winCredential{
		Type: credTypeGeneric, TargetName: target, Persist: credPersistLocal,
		BlobSize: uint32(len(secret)), Blob: unsafe.SliceData(secret),
	}
	dll := windows.NewLazySystemDLL("advapi32.dll")
	ok, _, callErr := dll.NewProc("CredWriteW").Call(uintptr(unsafe.Pointer(&item)), 0)
	runtime.KeepAlive(item)
	return winKeychainError(ok, callErr)
}

// Get reads the credential for the namespaced account.
func (nativeStore) Get(ctx context.Context, account string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	target, err := windows.UTF16PtrFromString(credentialPrefix + account)
	if err != nil {
		return "", err
	}
	dll := windows.NewLazySystemDLL("advapi32.dll")
	var item *winCredential
	ok, _, callErr := dll.NewProc("CredReadW").Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&item)))
	if err := winKeychainError(ok, callErr); err != nil {
		return "", err
	}
	secret := string(unsafe.Slice(item.Blob, item.BlobSize))
	_, _, _ = dll.NewProc("CredFree").Call(uintptr(unsafe.Pointer(item))) //nolint:errcheck // CredFree has no return value
	return secret, nil
}

// Delete removes the credential for the namespaced account.
func (nativeStore) Delete(ctx context.Context, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(credentialPrefix + account)
	if err != nil {
		return err
	}
	dll := windows.NewLazySystemDLL("advapi32.dll")
	ok, _, callErr := dll.NewProc("CredDeleteW").Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	return winKeychainError(ok, callErr)
}

func winKeychainError(ok uintptr, err error) error {
	if ok != 0 {
		return nil
	}
	switch err {
	case windows.ERROR_NO_SUCH_LOGON_SESSION, windows.ERROR_NOT_SUPPORTED:
		return ErrUnavailable
	case windows.ERROR_NOT_FOUND:
		return fs.ErrNotExist
	case windows.ERROR_ACCESS_DENIED, windows.ERROR_PRIVILEGE_NOT_HELD:
		return fs.ErrPermission
	default:
		return err
	}
}
