package authstore

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func checkManagedACL(path string) error {
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	// The result starts with a length and an attribute_set_t. The kernel
	// includes EXTENDED_SECURITY in that set when the file has extended
	// security data. We do not need to read or interpret individual ACEs.
	attrs := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY,
	}
	var result [32]byte
	//nolint:staticcheck // x/sys has no getattrlist wrapper and release builds disable CGO.
	_, _, errno := syscall.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&result)), uintptr(len(result)),
		unix.FSOPT_NOFOLLOW|unix.FSOPT_REPORT_FULLSIZE, 0)
	if errno != 0 {
		return errno
	}
	if binary.NativeEndian.Uint32(result[:4]) < 24 {
		return errors.New("cannot verify managed storage ACL")
	}
	if binary.NativeEndian.Uint32(result[4:8])&unix.ATTR_CMN_EXTENDED_SECURITY != 0 {
		return errors.New("managed storage must not have an extended ACL")
	}
	return nil
}
