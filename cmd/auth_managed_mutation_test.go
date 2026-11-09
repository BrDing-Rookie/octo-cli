package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

func TestManagedAuthMutationKeepsVerifiedTarget(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	path := filepath.Join(dir, "config.json")
	raw := `{"version":1,"current_profile":"work","profiles":{"work":{"api_base_url":"https://gateway.example","space_id":"S1","token_source":{"type":"token_file","path":"external"}}}}`
	const fakeBearer = "demo-review-fake-bearer"
	phaseOneWrite(t, path, raw)
	phaseOneWrite(t, filepath.Join(dir, "external"), "external-test-bearer")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"auth", "update", "--api-base-url", "https://other.example"}, "cannot change the API origin"},
		{[]string{"auth", "update", "--clear-api-base-url"}, "cannot change the API origin"},
		{[]string{"auth", "update", "--api-base-url", "https://example.invalid/%ZZ?token=" + fakeBearer}, "invalid API base URL"},
		{[]string{"--bot-id", "legacy", "auth", "logout"}, "only --profile"},
		{[]string{"--credential-file", "external", "auth", "logout"}, "only --profile"},
		{[]string{"--dry-run", "auth", "logout"}, "--dry-run is not supported"},
		{[]string{"auth", "update", "--api-base-url", "https://gateway.example"}, ""},
	} {
		out, err := phaseOneRun(tc.args...)
		if strings.Contains(out, fakeBearer) || (err != nil && strings.Contains(err.Error(), fakeBearer)) {
			t.Fatal("auth update echoed the malformed URL's bearer")
		}
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%v: %v (%s)", tc.args, err, out)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%v: want %q, got %v (%s)", tc.args, tc.want, err, out)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, []byte(raw)) {
			t.Fatalf("binding changed after %v: %v", tc.args, readErr)
		}
	}
	out, err := phaseOneRun("auth", "logout")
	if err != nil || !strings.Contains(out, `"removed": "work"`) {
		t.Fatalf("logout: %v (%s)", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "external")); err != nil || string(data) != "external-test-bearer" {
		t.Fatalf("logout modified external credential: %v", err)
	}
	cfg, err := config.LoadProfileConfig()
	if err != nil || cfg.CurrentProfile != "" || len(cfg.Profiles) != 0 {
		t.Fatalf("profile reference remains after logout: %#v, %v", cfg, err)
	}
}

func TestManagedAuthLogoutRemovesManagedEntry(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	snap, err := store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Profile{APIBaseURL: "https://gateway.example", SpaceID: "S1"}
	if _, err := store.Import(snap, profile, "managed-test-bearer", authstore.BackendAuto); err != nil {
		t.Fatal(err)
	}
	args := []string{"--dry-run", "api", "GET", "/probe"}
	if out, err := phaseOneRun(args...); err != nil || !strings.Contains(out, "https://gateway.example/probe") ||
		strings.Contains(out, "managed-test-bearer") {
		t.Fatalf("managed resolver: %v (%s)", err, out)
	}
	if out, err := phaseOneRun("auth", "logout"); err != nil || strings.Contains(out, "cleanup_warning") {
		t.Fatalf("logout: %v (%s)", err, out)
	}
	remaining, err := filepath.Glob(filepath.Join(dir, "credentials", "*.enc"))
	if err != nil || len(remaining) != 0 {
		t.Fatalf("managed entry remains after logout: %v, %v", remaining, err)
	}
}
