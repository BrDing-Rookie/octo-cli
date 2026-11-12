package authstore

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func makePrivateDir(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	name, err := windowsPath(path)
	if err != nil {
		return err
	}
	attrs := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	return windows.CreateDirectory(name, attrs)
}

func checkPrivate(path string, _ os.FileInfo, _ *os.File) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return fs.ErrPermission
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fs.ErrPermission
	}
	return checkAccessList(dacl, user.User.Sid)
}

func checkAccessList(dacl *windows.ACL, user *windows.SID) error {
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fs.ErrPermission
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return fs.ErrPermission
		}
	}
	return nil
}

func openManagedFile(path string, create bool) (*os.File, error) {
	if create {
		return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	}
	return os.Open(path)
}

func tryLock(file *os.File) (func(), error) {
	handle := windows.Handle(file.Fd())
	var offset windows.Overlapped
	err := windows.LockFileEx(handle, windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &offset)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &offset) //nolint:errcheck // closing the handle also releases the lock
	}, nil
}

func replaceFile(from, to string) error {
	src, err := windowsPath(from)
	if err != nil {
		return err
	}
	dst, err := windowsPath(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func syncDirectory(string) error { return nil } // replacement uses MOVEFILE_WRITE_THROUGH

func windowsPath(path string) (*uint16, error) {
	if strings.HasPrefix(path, `\\?\`) {
		return windows.UTF16PtrFromString(path)
	}
	if share, ok := strings.CutPrefix(path, `\\`); ok {
		return windows.UTF16PtrFromString(`\\?\UNC\` + share)
	}
	return windows.UTF16PtrFromString(`\\?\` + path)
}
