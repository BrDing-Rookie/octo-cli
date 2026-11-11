//go:build darwin || linux

package cmdutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

const (
	outputWriterArg        = "--octo-internal-write-output"
	outputWriterBrokenPipe = 2
)

func writeCancelableFile(ctx context.Context, file *os.File, data []byte) (int, error, bool) {
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice) == 0 {
		return 0, nil, false
	}
	executable, err := os.Executable()
	if err != nil {
		return 0, err, true
	}
	output, err := duplicateOutputFile(file, false)
	if err != nil {
		return 0, err, true
	}
	defer output.Close() //nolint:errcheck // close only the writer's duplicate
	// Reap the process before reporting cancellation. Its blocking write
	// needs no changes to the flags shared by inherited descriptors.
	writer := exec.CommandContext(ctx, executable, outputWriterArg)
	writer.Env = []string{"GORACE=atexit_sleep_ms=0"}
	writer.Stdin = bytes.NewReader(data)
	// Pass a fresh os.File so exec's Fd call preserves the original flags.
	writer.Stdout = output
	err = writer.Run()
	if err == nil || (errors.Is(err, ctx.Err()) && writer.ProcessState != nil && writer.ProcessState.Success()) {
		return len(data), nil, true
	}
	if err := ctx.Err(); err != nil {
		return 0, err, true
	}
	if writer.ProcessState != nil && writer.ProcessState.ExitCode() == outputWriterBrokenPipe {
		return 0, unix.EPIPE, true
	}
	return 0, err, true
}

// RunOutputWriterIfRequested dispatches an internal output process before CLI setup.
func RunOutputWriterIfRequested() {
	if len(os.Args) != 2 || os.Args[1] != outputWriterArg {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err == nil {
		_, err = (standardPipeWriter{out: os.Stdout}).Write(data)
	}
	if errors.Is(err, unix.EPIPE) {
		os.Exit(outputWriterBrokenPipe)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func (w standardPipeWriter) Write(data []byte) (int, error) {
	file, ok := w.out.(*os.File)
	if !ok {
		return w.out.Write(data)
	}
	// Go returns EPIPE on a duplicate descriptor above stderr instead of
	// terminating the process on a write to the broken standard stream.
	dup, err := duplicateOutputFile(file, true)
	if err != nil {
		return 0, err
	}
	if dup == nil {
		return file.Write(data)
	}
	n, writeErr := dup.Write(data)
	return n, errors.Join(writeErr, dup.Close())
}

func duplicateOutputFile(file *os.File, onlyStandardStreams bool) (*os.File, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var dupErr error
	if err := conn.Control(func(source uintptr) {
		if !onlyStandardStreams || source == 1 || source == 2 {
			fd, dupErr = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 3)
		}
	}); err != nil || dupErr != nil {
		return nil, errors.Join(err, dupErr)
	}
	if fd < 0 {
		return nil, nil
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}
