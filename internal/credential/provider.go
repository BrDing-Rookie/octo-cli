// Package credential validates and reads opaque Bearer credentials.
package credential

import (
	"io"
	"os"
	"strings"
)

// Credential is the Bearer and its resolved request context.
type Credential struct {
	Token   string
	SpaceID string
	Source  string
	Profile string
	TokenID string
	OwnerID string
}

type inputError string

func (e inputError) Error() string { return string(e) }

// ValidateBearer checks only whether the value can be sent as a Bearer.
func ValidateBearer(token string) error {
	if token == "" {
		return inputError("token is required")
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] == 0x7f {
			return inputError("token contains whitespace or control characters unsafe for a Bearer header")
		}
	}
	return nil
}

// Read reads a single opaque token, allowing a text file's final line ending.
func Read(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", inputError("could not read token")
	}
	token := string(data)
	if strings.HasSuffix(token, "\n") {
		token = strings.TrimSuffix(strings.TrimSuffix(token, "\n"), "\r")
	}
	return token, ValidateBearer(token)
}

// ReadFile reads a caller-owned credential file without including its path in
// errors. A mistyped flag may contain the token itself.
func ReadFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", inputError("could not read a regular credential file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", inputError("could not open the credential file")
	}
	defer file.Close() //nolint:errcheck // read-only file
	return Read(file)
}
