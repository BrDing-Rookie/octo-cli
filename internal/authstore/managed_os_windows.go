package authstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func lockManagedFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

func openExistingManagedFile(path string) (*os.File, error) {
	native, err := managedWindowsPath(path)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(native)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func managedFileLinkCount(file *os.File) (uint64, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info)
	return uint64(info.NumberOfLinks), err
}

// managedWindowsPath applies Go's conservative long-path threshold to calls
// made directly to Win32. Extended paths must be absolute and normalized.
func managedWindowsPath(path string) (string, error) {
	path = filepath.FromSlash(path)
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) || strings.HasPrefix(path, `\??\`) {
		return path, nil
	}
	full, err := windows.FullPath(path)
	if err != nil || len(full) < 248 {
		return full, err
	}
	if unc, ok := strings.CutPrefix(full, `\\`); ok {
		return `\\?\UNC\` + unc, nil
	}
	return `\\?\` + full, nil
}

func replaceManagedFile(from, to string) (bool, error) {
	return moveManagedFile(from, to, windows.MOVEFILE_REPLACE_EXISTING)
}

func publishManagedAnchor(stage, anchor string) (bool, error) {
	// Move the already prepared hard link without replacing any destination.
	// Write-through makes this publication durable before v1 retirement.
	return moveManagedFile(stage, anchor, 0)
}

func moveManagedFile(from, to string, flags uint32) (bool, error) {
	from, err := managedWindowsPath(from)
	if err != nil {
		return false, err
	}
	to, err = managedWindowsPath(to)
	if err != nil {
		return false, err
	}
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return false, err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return false, err
	}
	// Existing readers may briefly hold the destination without delete
	// sharing, including another CLI process loading config before locking.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		err = windows.MoveFileEx(src, dst, flags|windows.MOVEFILE_WRITE_THROUGH)
		if (!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED)) ||
			!time.Now().Before(deadline) {
			return err == nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Managed file publication requests write-through in MoveFileEx.
func syncManagedDirectory(string) error { return nil }

func checkAtomicReplaceTarget(path string) error {
	native, err := managedWindowsPath(path)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(native)
	if err != nil {
		return err
	}
	// os.Rename uses MoveFileEx with replacement. Probe delete access and
	// exclusive sharing without changing the destination directory entry.
	handle, err := windows.CreateFile(name, windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(handle, &info)
	if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		err = windows.ERROR_ACCESS_DENIED
	}
	return errors.Join(err, windows.CloseHandle(handle))
}

func protectManagedPath(path string, _ os.FileInfo, _ os.FileMode) error {
	path, err := managedWindowsPath(path)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	runtime.KeepAlive(user)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func checkManagedFilePrivacy(path string, _ os.FileInfo) error {
	path, err := managedWindowsPath(path)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount != 1 {
		return errors.New("managed storage file must have a private ACL")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		return errors.New("managed storage file must have a private ACL")
	}
	return nil
}
