//go:build darwin || linux

package cmdutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCancelledStdoutDoesNotResumeWriting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		open      func(*testing.T) (*os.File, *os.File)
		committed bool
	}{
		{"pipe", openOutputTestPipe, false},
		{"pipe after commit", openOutputTestPipe, true},
		{"terminal", openOutputTestPTY, false},
		{"terminal after commit", openOutputTestPTY, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer := tc.open(t)
			// Inherited stdout normally starts in blocking mode.
			fd := writer.Fd()
			if err := unix.SetNonblock(int(fd), false); err != nil {
				t.Fatal(err)
			}
			stream := IOStreams{Out: writer}
			write := stream.WriteStdout
			if tc.committed {
				write = stream.WriteStdoutAfterCommit
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			payload := bytes.Repeat([]byte{'x'}, 4<<20)
			done := make(chan error, 1)
			go func() { done <- write(ctx, payload) }()
			if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Wait for the actual write to start, then leave most of the output blocked.
			var first [1]byte
			if _, err := io.ReadFull(reader, first[:]); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("write error = %v, want context.Canceled", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("write did not stop before the reader resumed")
			}
			if flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatalf("stdout did not return to blocking mode: flags=%d, error=%v", flags, err)
			}
			if err := reader.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			// Keep the writer open, as it would be while an error is written to stderr.
			n, err := io.Copy(io.Discard, reader)
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("drain pipe: %v", err)
			}
			if n+1 >= int64(len(payload)) {
				t.Fatalf("cancelled write completed after the reader resumed (%d bytes)", n+1)
			}
		})
	}
}

func TestCancellableOutputPreservesSharedPipeMode(t *testing.T) {
	reader, writer := openOutputTestPipe(t)
	if err := unix.SetNonblock(int(writer.Fd()), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	observer := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSharedPipeModeObserver$")
	observer.Env = append(os.Environ(), "TEST_SHARED_PIPE_MODE=1", "GORACE=atexit_sleep_ms=0")
	observer.ExtraFiles = []*os.File{writer}
	var diagnostics bytes.Buffer
	observer.Stderr = &diagnostics
	ready, err := observer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stop, err := observer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if observer.ProcessState == nil {
			_ = observer.Process.Kill()
			_ = observer.Wait()
		}
	})
	var marker [1]byte
	if _, err := io.ReadFull(ready, marker[:]); err != nil || marker[0] != 'R' {
		t.Fatalf("shared writer observer did not start: %v", err)
	}

	writeCtx, stopWrite := context.WithCancel(ctx)
	defer stopWrite()
	stream := IOStreams{Out: writer}
	done := make(chan error, 1)
	go func() { done <- stream.WriteStdout(writeCtx, bytes.Repeat([]byte{'x'}, 4<<20)) }()
	if err := reader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(reader, marker[:]); err != nil {
		t.Fatalf("write did not start: %v", err)
	}
	// Observe the inherited descriptor while the pipe stays full.
	time.Sleep(300 * time.Millisecond)
	stopWrite()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("write error = %v, want context.Canceled", err)
		}
	case <-ctx.Done():
		t.Error("write did not stop after cancellation")
	}
	if err := stop.Close(); err != nil {
		t.Fatal(err)
	}
	remaining, readErr := io.ReadAll(ready)
	if err := observer.Wait(); err != nil || readErr != nil {
		t.Fatalf("shared writer observed a change: %v (%v)\n%s%s", err, readErr, remaining, diagnostics.Bytes())
	}
}

func TestSharedPipeModeObserver(t *testing.T) {
	if os.Getenv("TEST_SHARED_PIPE_MODE") != "1" {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	if _, err := os.Stdout.Write([]byte{'R'}); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		flags, err := unix.FcntlInt(3, unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK != 0 {
			t.Fatalf("inherited writer lost blocking mode: flags=%d, error=%v", flags, err)
		}
	}
}

func openOutputTestPipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	var err error
	reader, writer, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	return reader, writer
}

func openOutputTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	var err error
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	slave, err = os.OpenFile(outputTestPTYSlave(t, master.Fd()), os.O_WRONLY|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}
