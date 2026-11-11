//go:build !darwin && !linux && !windows

package cmdutil

import (
	"context"
	"os"
)

func (w standardPipeWriter) Write(data []byte) (int, error) {
	return w.out.Write(data)
}

func writeCancelablePipe(context.Context, *os.File, []byte) (int, error, bool) {
	return 0, nil, false
}
