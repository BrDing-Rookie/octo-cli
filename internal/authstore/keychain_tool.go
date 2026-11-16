//go:build darwin || linux

package authstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

const keychainService = "com.octo-cli.profile.v1"

func runKeychainTool(ctx context.Context, name, input string, args ...string) (stdout []byte, diagnostics string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = keychainEnvironment()
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	return out, strings.TrimSpace(stderr.String()), err
}

func keychainEnvironment() []string {
	var env []string
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if name != config.EnvToken && name != "LC_ALL" {
			env = append(env, variable)
		}
	}
	return append(env, "LC_ALL=C")
}

func encodeSecret(token string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(token))
}

func decodeSecret(data []byte) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil {
		return "", storeError("invalid system credential")
	}
	return string(decoded), nil
}
