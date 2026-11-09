package cmdutil

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"
)

const canceledErrorWriteGrace = 150 * time.Millisecond

// IOStreams groups the three io streams a command uses: stdin (for @- input),
// stdout (for envelope output), and stderr (for diagnostics / error envelopes).
// Tests substitute in-memory buffers; production wires os.Stdin/Stdout/Stderr.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// WriteStdout writes a rendered response and lets the CLI exit on cancellation
// even when an inherited stdout pipe stays blocked.
func (s *IOStreams) WriteStdout(ctx context.Context, data []byte) error {
	return writeStream(ctx, s.Out, data, 0)
}

func writeStream(ctx context.Context, out io.Writer, data []byte, grace time.Duration) error {
	if len(data) == 0 {
		return nil
	}
	writeCtx := ctx
	if grace > 0 {
		// Error envelopes should still reach a writable stderr after cancellation.
		writeCtx = context.WithoutCancel(ctx)
	}
	if err := writeCtx.Err(); err != nil {
		return err
	}
	write := func(data []byte) error {
		if err := writeCtx.Err(); err != nil {
			return err
		}
		n, err := out.Write(data)
		if err == nil && n != len(data) {
			return io.ErrShortWrite
		}
		return err
	}
	if ctx.Done() == nil {
		return write(data)
	}
	// The underlying writer can still be blocked when this method returns.
	// Give the write its own copy so the caller may release or reuse its buffer.
	data = bytes.Clone(data)
	done := make(chan error, 1)
	go func() { done <- write(data) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if grace > 0 {
			timer := time.NewTimer(grace)
			defer timer.Stop()
			select {
			case err := <-done:
				return err
			case <-timer.C:
			}
		}
		select {
		case err := <-done:
			return err
		default:
			return ctx.Err()
		}
	}
}

// NewStdIOStreams returns streams bound to the process stdio.
func NewStdIOStreams() *IOStreams {
	return &IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
}

// NewTestIOStreams returns in-memory streams plus the concrete buffers so the
// test can assert on captured output.
func NewTestIOStreams() (streams *IOStreams, inBuf, outBuf, errBuf *bytes.Buffer) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	return &IOStreams{In: in, Out: out, ErrOut: errOut}, in, out, errOut
}
