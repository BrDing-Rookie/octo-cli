package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestSkillsInstallDryRunRejectsWithoutCreatingTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "skills", "nested")
	f := newTestFactoryWithReg()

	_, _, err := execRoot(t, f, "skills", "--install", target, "--dry-run")
	requireDryRunValidation(t, err)
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Errorf("skills --install --dry-run target stat error = %v, want target absent", statErr)
	}
}

func TestAuthLoginDryRunRejectsBeforeReadingTokenOrCreatingProfile(t *testing.T) {
	for _, mode := range []string{"stdin", "token file"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "profiles")
			t.Setenv(authstore.EnvConfigDir, configDir)

			f := newTestFactoryWithReg()
			args := []string{"auth", "login", "--dry-run", "--profile", "dry-run-profile"}
			if mode == "stdin" {
				const token = "app_dry_run_token"
				f.In.WriteString(token)
				args = append(args, "--with-token")
				defer func() {
					if f.In.Len() != len(token) {
						t.Errorf("stdin remaining bytes = %d, want %d (login read the token)", f.In.Len(), len(token))
					}
				}()
			} else {
				args = append(args, "--token-file", filepath.Join(root, "missing-token"))
			}

			_, _, err := execRoot(t, f, args...)
			requireDryRunValidation(t, err)
			if _, statErr := os.Lstat(configDir); !os.IsNotExist(statErr) {
				t.Errorf("auth login --dry-run config directory stat error = %v, want directory absent", statErr)
			}
		})
	}
}

func TestAuthLogoutDryRunKeepsProfile(t *testing.T) {
	configPath := writeExternalProfile(t, privateProfileFixtureDir(t), "agent", "https://gateway.example.test")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = execRoot(t, newAuthTestFactory(), "auth", "logout", "--dry-run", "--profile", "agent")
	requireDryRunValidation(t, err)
	after, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("auth logout changed config during dry run: %v", err)
	}
}

func requireDryRunValidation(t *testing.T, err error) {
	t.Helper()
	ee := output.AsExitError(err)
	if ee == nil || ee.Type != "validation" || ee.Code != "VALIDATION_ERROR" {
		t.Errorf("error = %v, want validation error", err)
		return
	}
	if !strings.Contains(ee.Message, "--dry-run") {
		t.Errorf("validation message = %q, want dry-run refusal before command work", ee.Message)
	}
}
