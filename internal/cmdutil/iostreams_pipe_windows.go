package cmdutil

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func (w standardPipeWriter) Write(data []byte) (int, error) {
	return w.out.Write(data)
}

// RunOutputWriterIfRequested is only needed by the Unix writer.
func RunOutputWriterIfRequested() {}

func writeCancelableFile(ctx context.Context, file *os.File, data []byte) (int, error, bool) {
	conn, err := file.SyscallConn()
	if err != nil {
		return 0, err, true
	}
	var isPipe bool
	if err := conn.Control(func(fd uintptr) {
		kind, err := windows.GetFileType(windows.Handle(fd))
		isPipe = err == nil && kind == windows.FILE_TYPE_PIPE
	}); err != nil || !isPipe {
		return 0, err, err != nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err, true
	}

	written := make(chan struct{})
	cancellerDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(cancellerDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-written:
				return
			default:
			}
			// Retry if cancellation ran just before Write submitted its I/O.
			_ = conn.Control(func(fd uintptr) { _ = windows.CancelIoEx(windows.Handle(fd), nil) })
			select {
			case <-written:
				return
			case <-ticker.C:
			}
		}
	})
	n, err := file.Write(data)
	close(written)
	if !stop() {
		<-cancellerDone
	}
	if ctx.Err() != nil && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return n, ctx.Err(), true
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err, true
}
