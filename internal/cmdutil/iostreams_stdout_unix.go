//go:build darwin || linux

package cmdutil

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func (w stdoutPipeWriter) Write(data []byte) (int, error) {
	file, ok := w.out.(*os.File)
	if !ok {
		return w.out.Write(data)
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}

	// Go returns EPIPE on a duplicate descriptor above stderr instead of
	// terminating the process on a write to the broken standard stream.
	fd := -1
	var dupErr error
	if err := conn.Control(func(source uintptr) {
		if source == 1 || source == 2 {
			fd, dupErr = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 3)
		}
	}); err != nil {
		return 0, err
	}
	if dupErr != nil {
		return 0, dupErr
	}
	if fd < 0 {
		return file.Write(data)
	}
	dup := os.NewFile(uintptr(fd), file.Name())
	n, writeErr := dup.Write(data)
	return n, errors.Join(writeErr, dup.Close())
}
