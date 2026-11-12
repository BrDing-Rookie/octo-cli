package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestMissingExplicitProfileDoesNotCreateStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-cli")
	t.Setenv("OCTO_CONFIG_DIR", dir)
	t.Setenv(config.EnvToken, phaseOneToken)
	_, _, err := runPhaseOneCommand(t, "--profile", "agent", "config", "show")
	if exit := output.AsExitError(err); exit == nil || exit.Code != "UNAUTHORIZED" {
		t.Fatalf("missing profile did not produce an auth error: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("profile resolution created the config directory: %v", err)
	}
}

func TestProfileCredentialFileSelectsRequestTarget(t *testing.T) {
	const bearer = "fixture-file-bearer"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer || r.Header.Get("X-Space-Id") != "space-file" {
			t.Error("request did not use the file Bearer and profile Space")
		}
		io.WriteString(w, `{"records":[]}`)
	}))
	defer server.Close()
	dir := privateProfileFixtureDir(t)
	t.Setenv("OCTO_CONFIG_DIR", dir)
	t.Setenv(config.EnvAPIBaseURL, "")
	t.Setenv(config.EnvSpaceID, "")
	t.Setenv(config.EnvToken, phaseOneToken)
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(bearer+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{
		"version": 1, "current_profile": "file", "profiles": {
			"file": {"api_base_url": "`+server.URL+`", "space_id": "space-file",
			         "token_source": {"type": "token_file", "path": "token"}}
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runPhaseOneCommand(t, "--profile", "file", "--credential-file", path, "example", "record", "list")
	if err != nil {
		t.Fatalf("credential file request failed: %v", err)
	}
	if !strings.Contains(out, `"records"`) || strings.Contains(out, bearer) {
		t.Fatalf("unexpected response: %s", out)
	}
}

func TestProfileAndCredentialPrecedence(t *testing.T) {
	type request struct{ target, space, bearer string }
	requests := make(chan request, 1)
	fixture := func(target string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- request{target, r.Header.Get("X-Space-Id"), r.Header.Get("Authorization")}
			io.WriteString(w, `{"records":[]}`)
		}))
		t.Cleanup(server.Close)
		return server
	}
	a, b := fixture("a"), fixture("b")
	dir := privateProfileFixtureDir(t)
	t.Setenv(authstore.EnvConfigDir, dir)
	writeFixtureFile(t, filepath.Join(dir, "a"), "token-a\n")
	writeFixtureFile(t, filepath.Join(dir, "b"), "token-b\n")
	envFile := filepath.Join(dir, "env-file")
	writeFixtureFile(t, envFile, "token-env-file\n")
	explicitFile := filepath.Join(dir, "explicit-file")
	writeFixtureFile(t, explicitFile, "token-explicit-file\n")
	writeProfileIndex(t, dir, authstore.Config{Version: 1, CurrentProfile: "a", Profiles: map[string]authstore.Profile{
		"a": {APIBaseURL: a.URL, SpaceID: "space-a", TokenSource: authstore.TokenSource{Type: authstore.TokenFile, Path: "a"}},
		"b": {APIBaseURL: b.URL, SpaceID: "space-b", TokenSource: authstore.TokenSource{Type: authstore.TokenFile, Path: "b"}},
	}})

	for _, tc := range []struct {
		name    string
		env     map[string]string
		flags   []string
		want    request
		errCode string
	}{
		{name: "current_profile", want: request{"a", "space-a", "Bearer token-a"}},
		{name: "environment profile", env: map[string]string{config.EnvProfile: "b"}, want: request{"b", "space-b", "Bearer token-b"}},
		{name: "explicit profile", env: map[string]string{config.EnvProfile: "b"}, flags: []string{"--profile", "a"}, want: request{"a", "space-a", "Bearer token-a"}},
		{name: "env token bypasses current", env: map[string]string{config.EnvToken: "token-env", config.EnvAPIBaseURL: b.URL, config.EnvSpaceID: "runtime"},
			want: request{"b", "runtime", "Bearer token-env"}},
		{name: "env file with explicit profile", env: map[string]string{config.EnvTokenFile: envFile}, flags: []string{"--profile", "b"},
			want: request{"b", "space-b", "Bearer token-env-file"}},
		{name: "flag file overrides env file", env: map[string]string{config.EnvTokenFile: envFile, config.EnvProfile: "a"}, flags: []string{"--credential-file", explicitFile},
			want: request{"a", "space-a", "Bearer token-explicit-file"}},
		{name: "both token env vars conflict even with a file flag", env: map[string]string{config.EnvToken: "", config.EnvTokenFile: envFile},
			flags: []string{"--credential-file", explicitFile}, errCode: "VALIDATION_ERROR"},
		{name: "bad explicit file stops resolution", env: map[string]string{config.EnvToken: "token-env"},
			flags: []string{"--profile", "a", "--credential-file", "pasted-sensitive-file-path"}, errCode: "UNAUTHORIZED"},
		{name: "empty env file stops resolution", env: map[string]string{config.EnvTokenFile: ""}, errCode: "UNAUTHORIZED"},
		{name: "empty env token stops resolution", env: map[string]string{config.EnvToken: ""}, errCode: "UNAUTHORIZED"},
		{name: "missing explicit profile", env: map[string]string{config.EnvToken: "token-env"}, flags: []string{"--profile", "missing"}, errCode: "UNAUTHORIZED"},
		{name: "Space conflict", flags: []string{"--space", "space-b"}, errCode: "PROFILE_SCOPE_MISMATCH"},
		{name: "origin conflict", env: map[string]string{config.EnvAPIBaseURL: b.URL}, errCode: "PROFILE_SCOPE_MISMATCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			flags := append(append([]string(nil), tc.flags...), "api", "GET", "/v1/records")
			_, stderr, err := runPhaseOneCommand(t, flags...)
			if tc.errCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case actual := <-requests:
					if actual != tc.want {
						t.Errorf("request = %+v, want %+v", actual, tc.want)
					}
				default:
					t.Fatal("missing business request")
				}
				return
			}
			exit := output.AsExitError(err)
			if exit == nil || exit.Code != tc.errCode || strings.Contains(stderr+err.Error(), "pasted-sensitive-file-path") {
				t.Fatalf("expected safe %s error, got %v", tc.errCode, err)
			}
			select {
			case <-requests:
				t.Fatal("selection failure sent a request")
			default:
			}
		})
	}
}

func TestExternalProfileLogoutPreservesCallerFile(t *testing.T) {
	dir := privateProfileFixtureDir(t)
	writeExternalProfile(t, dir, "external", "https://gateway.example.test")
	out, _, err := runPhaseOneCommand(t, "--profile", "external", "auth", "logout")
	if err != nil || dataOf(t, out)["removed"] != "external" {
		t.Fatalf("external profile was not removed: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "external-token")); err != nil || string(data) != "external-file-fixture\n" {
		t.Fatalf("logout affected the caller file: %v", err)
	}
}

func TestExternalCredentialBypassesCorruptImplicitProfile(t *testing.T) {
	dir := privateProfileFixtureDir(t)
	t.Setenv(authstore.EnvConfigDir, dir)
	writeFixtureFile(t, filepath.Join(dir, "config.json"), `{"profiles":{"legacy":{}}}`)
	t.Setenv(config.EnvToken, phaseOneToken)
	t.Setenv(config.EnvAPIBaseURL, "https://runtime.example.test")
	out, _, err := runPhaseOneCommand(t, "config", "show")
	if err != nil {
		t.Fatalf("runtime credential opened the implicit profile: %v", err)
	}
	if data := dataOf(t, out); data["source"] != "env:OCTO_TOKEN" || data["api_base_url"] != "https://runtime.example.test" {
		t.Fatalf("unexpected runtime target: %v", data)
	}
	_, _, err = runPhaseOneCommand(t, "--profile", "legacy", "config", "show")
	if exit := output.AsExitError(err); exit == nil || exit.Code != "INVALID_PROFILE" {
		t.Fatalf("explicit selection did not report the corrupt index: %v", err)
	}
}

func TestDefaultProfileStoreIsIsolatedFromLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	unsetProfileEnv(t, authstore.EnvConfigDir)
	legacy := filepath.Join(home, ".octo-cli")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	const oldConfig = `{"profiles":{"agent":{"robot_id":"old-bot"}}}`
	legacyPath := filepath.Join(legacy, "config.json")
	writeFixtureFile(t, legacyPath, oldConfig)
	_, _, err := runPhaseOneCommand(t, "--profile", "agent", "config", "show")
	if exit := output.AsExitError(err); exit == nil || exit.Code != "UNAUTHORIZED" {
		t.Fatalf("legacy-only setup did not report a missing profile: %v", err)
	}
	if got, err := os.ReadFile(legacyPath); err != nil || string(got) != oldConfig {
		t.Fatalf("legacy config was modified: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".octo", "cli")); !os.IsNotExist(err) {
		t.Fatalf("profile resolution created the new profile directory: %v", err)
	}
}
