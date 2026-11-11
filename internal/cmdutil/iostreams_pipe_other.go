//go:build !darwin && !linux && !windows

package cmdutil

import (
	"context"
	"os"
)

func (w standardPipeWriter) Write(data []byte) (int, error) {
	return w.out.Write(data)
}

func writeCancelableFile(context.Context, *os.File, []byte) (int, error, bool) {
	return 0, nil, false
}

// RunOutputWriterIfRequested is only needed by the Unix writer.
func RunOutputWriterIfRequested() {}
