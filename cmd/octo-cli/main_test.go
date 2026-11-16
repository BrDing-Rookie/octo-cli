package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hermeticEnv gives subprocess fixtures an explicit credential and config environment.
func hermeticEnv(extra ...string) []string {
	inherited := os.Environ()
	env := make([]string, 0, len(inherited)+len(extra))
	for _, kv := range inherited {
		if strings.HasPrefix(kv, "OCTO_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// TestMain_VersionCommand builds the binary and runs `octo-cli version` as a
// subprocess so the real main() path (including signal wiring, error
// classification, and os.Exit) is exercised.
func TestMain_VersionCommand(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "octo-cli")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	cmd := exec.Command(bin, "version")
	cmd.Env = hermeticEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(string(out), `"ok": true`) {
		t.Errorf("envelope missing: %s", out)
	}
	if !strings.Contains(string(out), `"version"`) {
		t.Errorf("version field missing: %s", out)
	}
}

// TestMain_UnknownCommandExitCode confirms that cobra framework errors reach
// main() and are wrapped into a validation-exit-code=2 envelope on stderr.
func TestMain_UnknownCommandExitCode(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "octo-cli")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	cmd := exec.Command(bin, "no-such-command")
	cmd.Env = hermeticEnv()
	// stderr carries the envelope for framework errors.
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("exit code = %d, want 2 (validation)", exitErr.ExitCode())
	}
	if !strings.Contains(string(errOut), "validation") {
		t.Errorf("envelope missing validation type:\n%s", errOut)
	}
}

func TestMain_AuthSubcommandExitCode(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "octo-cli")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"removed status", []string{"--profile", "work", "auth", "status"}, 2},
		{"unknown auth subcommand", []string{"auth", "no-such-subcommand"}, 2},
		{"explicit help", []string{"auth", "--help"}, 0},
		{"implicit help", []string{"auth"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, tc.args...)
			cmd.Env = hermeticEnv("OCTO_CONFIG_DIR=" + filepath.Join(t.TempDir(), "cli"))
			if tc.code == 0 {
				cmd.Env = append(cmd.Env, "OCTO_FORMAT=invalid-help-fixture")
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if cmd.ProcessState == nil {
				t.Fatalf("start octo-cli: %v", err)
			}
			if got := cmd.ProcessState.ExitCode(); got != tc.code {
				t.Fatalf("exit code = %d, want %d; stderr = %s", got, tc.code, stderr.String())
			}
			if tc.code == 0 {
				if stderr.Len() != 0 || !strings.Contains(string(stdout), "Available Commands:") {
					t.Fatalf("expected auth help on stdout, got stdout %q and stderr %q", stdout, stderr.String())
				}
				return
			}
			if len(stdout) != 0 {
				t.Errorf("unknown auth subcommand wrote to stdout: %q", stdout)
			}
			var envelope struct {
				OK    *bool
				Error struct{ Type, Code, Message string }
			}
			if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil {
				t.Fatalf("invalid JSON error envelope: %v; stderr = %s", err, stderr.String())
			}
			if envelope.OK == nil || *envelope.OK || envelope.Error.Type != "validation" ||
				envelope.Error.Code != "VALIDATION_ERROR" || !strings.Contains(envelope.Error.Message, "unknown subcommand") {
				t.Fatalf("expected an unknown subcommand validation error, got %s", stderr.String())
			}
		})
	}
}

// TestMain_MissingTokenExitCode verifies that the missing-token
// PersistentPreRunE error produces exit code 3 (auth_error).
func TestMain_MissingTokenExitCode(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "octo-cli")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	cmd := exec.Command(bin, "api", "GET", "/v1/records")
	// Drop every OCTO_ token/selector variable and point at an empty credential
	// store so no profile and no env token resolve, and Validate trips on the
	// missing token instead of the command reaching the network.
	cmd.Env = hermeticEnv("OCTO_CONFIG_DIR=" + filepath.Join(t.TempDir(), "cli"))
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3 (auth)", exitErr.ExitCode())
	}
	if !strings.Contains(string(errOut), "auth_error") {
		t.Errorf("envelope missing auth_error:\n%s", errOut)
	}
}
