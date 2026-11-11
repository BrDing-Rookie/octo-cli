//go:build darwin || linux

package cmdutil

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var pipeFlagsMu sync.Mutex

func writeCancelablePipe(ctx context.Context, file *os.File, data []byte) (int, error, bool) {
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return 0, nil, false
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return 0, err, true
	}
	var fd int
	var dupErr error
	if err := conn.Control(func(source uintptr) {
		fd, dupErr = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 3)
	}); err != nil || dupErr != nil {
		return 0, errors.Join(err, dupErr), true
	}
	n, err := writeUnixPipe(ctx, fd, data)
	return n, errors.Join(err, unix.Close(fd)), true
}

func writeUnixPipe(ctx context.Context, fd int, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, err := writeNonblocking(fd, data[written:])
		if n > 0 {
			written += n
		}
		switch err {
		case nil:
			if n == 0 {
				return written, io.ErrShortWrite
			}
		case unix.EINTR:
		case unix.EAGAIN:
			select {
			case <-ctx.Done():
				return written, ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		default:
			return written, err
		}
	}
	return written, nil
}

func writeNonblocking(fd int, data []byte) (int, error) {
	// Serialize flag changes for stdout and stderr redirected to the same pipe.
	pipeFlagsMu.Lock()
	defer pipeFlagsMu.Unlock()

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return 0, err
	}
	if flags&unix.O_NONBLOCK != 0 {
		return unix.Write(fd, data)
	}
	// A duplicate shares status flags. Restore them before waiting to retry.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		return 0, err
	}
	n, err := unix.Write(fd, data)
	if _, restoreErr := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); restoreErr != nil {
		return n, errors.Join(err, restoreErr)
	}
	return n, err
}

func (w standardPipeWriter) Write(data []byte) (int, error) {
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
