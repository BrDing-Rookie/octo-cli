package cmdutil

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func outputTestPTYSlave(t *testing.T, fd uintptr) string {
	t.Helper()
	if err := unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("/dev/pts/%d", number)
}
