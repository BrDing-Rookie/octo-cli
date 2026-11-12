package authstore

import (
	"encoding/binary"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Sizes and tags from Darwin's sys/attr.h and sys/kauth.h.
const (
	darwinAttrReferenceOffset = 4 + 5*4 // Total length and returned attribute bitmap.
	darwinAttrReferenceSize   = 2 * 4   // Data offset and length.
	darwinFileSecuritySize    = 4 + 2*16 + 2*4
	darwinACEFlagsOffset      = 16
	darwinACESize             = darwinACEFlagsOffset + 2*4
	darwinACLMaxEntries       = 128
	darwinFileSecurityMagic   = 0x012cc16d
	darwinNoACL               = ^uint32(0)
	darwinACEKindMask         = 0x0f
	darwinACEDeny             = 2
)

func credentialDirectory(path string) (string, error) {
	dir, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer dir.Close() //nolint:errcheck // directory opened for metadata inspection

	// The descriptor's path uses the filesystem's spelling, even when the
	// path passed to open used a different case.
	var buf [unix.PathMax]byte
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, dir.Fd(), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(dir)
	if errno != 0 {
		return "", errno
	}
	return unix.ByteSliceToString(buf[:]), nil
}

func checkPrivateACL(path string, info os.FileInfo, file *os.File) error {
	if file != nil {
		return checkDarwinFileACL(file)
	}

	dir, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck // directory opened for metadata inspection
	opened, err := dir.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return fs.ErrPermission
	}
	return checkDarwinFileACL(dir)
}

func checkDarwinFileACL(file *os.File) error {
	attributes := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY,
	}
	var buf [darwinAttrReferenceOffset + darwinAttrReferenceSize + darwinFileSecuritySize + darwinACLMaxEntries*darwinACESize]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_FGETATTRLIST, file.Fd(),
		uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		unix.FSOPT_REPORT_FULLSIZE, 0)
	runtime.KeepAlive(file)
	if errno != 0 {
		return errno
	}
	return checkDarwinACLAttributes(buf[:])
}

func checkDarwinACLAttributes(buf []byte) error {
	size := int(binary.NativeEndian.Uint32(buf[:4]))
	if size < darwinAttrReferenceOffset || size > len(buf) {
		return storeError("invalid macOS file attributes")
	}
	if binary.NativeEndian.Uint32(buf[4:8])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return nil
	}
	const referenceEnd = darwinAttrReferenceOffset + darwinAttrReferenceSize
	if size < referenceEnd {
		return storeError("invalid macOS ACL reference")
	}
	ref := buf[darwinAttrReferenceOffset:referenceEnd]
	start := darwinAttrReferenceOffset + int(int32(binary.NativeEndian.Uint32(ref[:4])))
	length := int(binary.NativeEndian.Uint32(ref[4:]))
	if start < referenceEnd || start > size || length > size-start {
		return storeError("invalid macOS ACL reference")
	}
	return checkDarwinACLEntries(buf[start : start+length])
}

func checkDarwinACLEntries(acl []byte) error {
	if len(acl) < darwinFileSecuritySize || binary.NativeEndian.Uint32(acl[:4]) != darwinFileSecurityMagic {
		return storeError("invalid macOS ACL")
	}
	count := binary.NativeEndian.Uint32(acl[darwinFileSecuritySize-8:])
	if count == darwinNoACL {
		count = 0
	}
	if count > darwinACLMaxEntries || len(acl) != darwinFileSecuritySize+int(count)*darwinACESize {
		return storeError("invalid macOS ACL entries")
	}
	// Owner-only mode bits provide access. A deny-only ACL adds no grants.
	for entries := acl[darwinFileSecuritySize:]; len(entries) != 0; entries = entries[darwinACESize:] {
		if binary.NativeEndian.Uint32(entries[darwinACEFlagsOffset:])&darwinACEKindMask != darwinACEDeny {
			return fs.ErrPermission
		}
	}
	return nil
}
