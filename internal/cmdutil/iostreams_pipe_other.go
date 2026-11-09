//go:build !darwin && !linux

package cmdutil

func (w standardPipeWriter) Write(data []byte) (int, error) {
	return w.out.Write(data)
}
