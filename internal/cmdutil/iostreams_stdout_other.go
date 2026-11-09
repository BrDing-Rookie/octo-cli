//go:build !darwin && !linux

package cmdutil

func (w stdoutPipeWriter) Write(data []byte) (int, error) {
	return w.out.Write(data)
}
