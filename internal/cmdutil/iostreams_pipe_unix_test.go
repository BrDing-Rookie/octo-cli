//go:build darwin || linux

package cmdutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCancelledStdoutDoesNotResumeWriting(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "ordinary output"
		if committed {
			name = "output after commit"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = reader.Close()
				_ = writer.Close()
			})
			// Inherited stdout normally starts in blocking mode.
			fd := writer.Fd()
			if err := unix.SetNonblock(int(fd), false); err != nil {
				t.Fatal(err)
			}
			stream := IOStreams{Out: writer}
			write := stream.WriteStdout
			if committed {
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
