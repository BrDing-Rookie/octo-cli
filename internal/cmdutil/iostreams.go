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
	_, err := writeStream(ctx, s.Out, data, 0)
	return err
}

// WriteStdoutAfterCommit also reports a broken standard pipe as a write error
// on Unix so the caller can report the outcome of a completed mutation.
func (s *IOStreams) WriteStdoutAfterCommit(ctx context.Context, data []byte) error {
	_, err := writeStream(ctx, standardPipeWriter{out: s.Out}, data, 0)
	return err
}

// StderrAfterCommit keeps diagnostics cancellable and reports a broken
// standard pipe as a write error on Unix.
func (s *IOStreams) StderrAfterCommit(ctx context.Context) io.Writer {
	return contextStreamWriter{ctx: ctx, out: standardPipeWriter{out: s.ErrOut}}
}

type standardPipeWriter struct {
	out io.Writer
}

// StderrWithContext lets best-effort diagnostics stop waiting on cancellation.
func (s *IOStreams) StderrWithContext(ctx context.Context) io.Writer {
	if ctx.Done() == nil || s.ErrOut == nil {
		return s.ErrOut
	}
	return contextStreamWriter{ctx: ctx, out: s.ErrOut}
}

type contextStreamWriter struct {
	ctx context.Context
	out io.Writer
}

func (w contextStreamWriter) Write(data []byte) (int, error) {
	return writeStream(w.ctx, w.out, data, 0)
}

func writeStream(ctx context.Context, out io.Writer, data []byte, grace time.Duration) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	writeCtx := ctx
	if grace > 0 {
		// Error envelopes should still reach a writable stderr after cancellation.
		writeCtx = context.WithoutCancel(ctx)
	}
	if err := writeCtx.Err(); err != nil {
		return 0, err
	}
	write := func(data []byte) (int, error) {
		if err := writeCtx.Err(); err != nil {
			return 0, err
		}
		n, err := out.Write(data)
		if err == nil && n != len(data) {
			return n, io.ErrShortWrite
		}
		return n, err
	}
	if ctx.Done() == nil {
		return write(data)
	}
	// The underlying writer can still be blocked when this method returns.
	// Give the write its own copy so the caller may release or reuse its buffer.
	data = bytes.Clone(data)
	type writeResult struct {
		n   int
		err error
	}
	done := make(chan writeResult, 1)
	go func() {
		n, err := write(data)
		done <- writeResult{n: n, err: err}
	}()
	select {
	case result := <-done:
		return result.n, result.err
	case <-ctx.Done():
		if grace > 0 {
			timer := time.NewTimer(grace)
			defer timer.Stop()
			select {
			case result := <-done:
				return result.n, result.err
			case <-timer.C:
			}
		}
		select {
		case result := <-done:
			return result.n, result.err
		default:
			return 0, ctx.Err()
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
