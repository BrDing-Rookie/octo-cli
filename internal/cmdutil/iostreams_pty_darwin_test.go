package cmdutil

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func outputTestPTYSlave(t *testing.T, fd uintptr) string {
	t.Helper()
	if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYGRANT, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYUNLK, 0); err != nil {
		t.Fatal(err)
	}
	var name [128]byte
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); err != 0 { //nolint:staticcheck // x/sys has no wrapper for this test-only PTY ioctl
		t.Fatal(err)
	}
	return unix.ByteSliceToString(name[:])
}
