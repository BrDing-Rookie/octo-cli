package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

type unavailableKeychain struct{}

func (unavailableKeychain) Put(context.Context, string, string) error {
	return authstore.ErrUnavailable
}

func (unavailableKeychain) Get(context.Context, string) (string, error) {
	return "", authstore.ErrUnavailable
}

func (unavailableKeychain) Delete(context.Context, string) error {
	return authstore.ErrUnavailable
}

func testProfileFactory() *cmdutil.Factory {
	f := cmdutil.NewDefaultFactory()
	f.StoreFunc = func() (*authstore.Store, error) { return authstore.New(unavailableKeychain{}) }
	return f
}

func newAuthTestFactory() *cmdutil.TestFactory {
	test := cmdutil.NewTestFactory()
	f := testProfileFactory()
	f.IOStreams = test.IOStreams
	test.Factory = f
	return test
}

func dataOf(t *testing.T, out string) map[string]any {
	t.Helper()
	var envelope struct {
		OK   bool
		Data map[string]any
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil || !envelope.OK || envelope.Data == nil {
		t.Fatalf("invalid success envelope: %s (%v)", out, err)
	}
	return envelope.Data
}

func privateProfileFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeExternalProfile(t *testing.T, dir, name, origin string) string {
	t.Helper()
	t.Setenv(authstore.EnvConfigDir, dir)
	writeFixtureFile(t, filepath.Join(dir, "external-token"), "external-file-fixture\n")
	return writeProfileIndex(t, dir, authstore.Config{
		Version: 1, CurrentProfile: name,
		Profiles: map[string]authstore.Profile{
			name: {
				APIBaseURL: origin, SpaceID: "fixture-space",
				TokenSource: authstore.TokenSource{Type: authstore.TokenFile, Path: "external-token"},
			},
		},
	})
}

func writeProfileIndex(t *testing.T, dir string, index authstore.Config) string {
	t.Helper()
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	writeFixtureFile(t, path, string(raw))
	return path
}

func writeFixtureFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func unsetProfileEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// TestMain dispatches these invocations through the real root command with
// isolated encrypted storage. Each invocation gets a fresh Factory and process.
func runProfileTestProcess() int {
	f := testProfileFactory()
	root := NewRootCmd(f)
	root.SetArgs(os.Args[1:])
	err := root.ExecuteContext(context.Background())
	if err == nil {
		return 0
	}
	if !f.ErrorEmitted {
		f.EmitError(err)
	}
	return output.AsExitError(cmdutil.WrapCLIError(err)).ExitCode()
}

type profileProcessResult struct {
	out, stderr string
	code        int
	err         error
}

func runProfileProcess(t *testing.T, stdin string, args ...string) profileProcessResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		return profileProcessResult{err: err}
	}
	child := exec.CommandContext(ctx, executable, args...)
	child.Env = append(os.Environ(), "OCTO_PROFILE_TEST_PROCESS=1", "GORACE=atexit_sleep_ms=0")
	child.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	data, err := child.Output()
	result := profileProcessResult{out: string(data), stderr: stderr.String(), err: err}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.code = exit.ExitCode()
	}
	return result
}

func requireProfileSuccess(t *testing.T, result profileProcessResult) map[string]any {
	t.Helper()
	if result.err != nil {
		t.Fatalf("command failed: %v\n%s", result.err, result.stderr)
	}
	if strings.Contains(result.out+result.stderr, phaseOneToken) {
		t.Fatal("command exposed the raw Bearer")
	}
	return dataOf(t, result.out)
}

func TestAuthProfileLifecycleAcrossProcesses(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/records" && r.URL.Path != "/v1/restricted" {
			t.Errorf("profile management sent a network request to %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+phaseOneToken {
			t.Error("request did not use the imported Bearer")
		}
		if r.Header.Get("X-Space-Id") != "space-fixture" {
			t.Error("business request did not use the imported Space")
		}
		if r.URL.Path == "/v1/restricted" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, authRequiredFixture)
			return
		}
		io.WriteString(w, `{"records":[]}`)
	}))
	defer server.Close()

	dir := filepath.Join(t.TempDir(), "cli")
	t.Setenv(authstore.EnvConfigDir, dir)
	t.Setenv("OCTO_AUTH_CURRENT_URL", server.URL+"/obsolete-self-check")
	got := requireProfileSuccess(t, runProfileProcess(t, phaseOneToken+"\n",
		"--profile", "agent", "--space", "space-fixture", "auth", "login", "--api-base-url", server.URL, "--with-token"))
	want := map[string]string{"profile": "agent", "api_base_url": server.URL, "space_id": "space-fixture", "source": "managed_store"}
	if len(got) != len(want) {
		t.Fatalf("login returned fields beyond the saved profile: %v", got)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("login %s = %v, want %s", key, got[key], value)
		}
	}
	path := filepath.Join(dir, "config.json")
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(phaseOneToken)) || bytes.Contains(raw, []byte(`"verified"`)) {
		t.Fatalf("profile index contained a secret or obsolete verification metadata: %v", err)
	}

	got = requireProfileSuccess(t, runProfileProcess(t, "", "config", "show"))
	if got["profile"] != "agent" || got["source"] != "managed_store" || got["token_id"] != nil || got["owner_id"] != nil {
		t.Fatalf("config show = %v", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("login and config inspection sent %d network requests", got)
	}
	requireProfileSuccess(t, runProfileProcess(t, "", "api", "GET", "/v1/records"))
	denied := runProfileProcess(t, "", "api", "GET", "/v1/restricted")
	if denied.code != 3 || !strings.Contains(denied.stderr, `"code": "AUTH_REQUIRED"`) ||
		strings.Contains(denied.out+denied.stderr, phaseOneToken) {
		t.Fatalf("business request did not surface a safe authentication error (exit %d)", denied.code)
	}
	got = requireProfileSuccess(t, runProfileProcess(t, "", "auth", "logout"))
	if got["removed"] != "agent" || calls.Load() != 2 {
		t.Fatalf("logout = %v, total network requests = %d", got, calls.Load())
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index authstore.Config
	if err := json.Unmarshal(raw, &index); err != nil || index.CurrentProfile != "" || len(index.Profiles) != 0 {
		t.Fatalf("logout did not clear the profile index: %v", err)
	}
	if entries, err := filepath.Glob(filepath.Join(dir, "credential-*.enc")); err != nil || len(entries) != 0 {
		t.Fatalf("logout left encrypted credential entries: %v (%v)", entries, err)
	}
}

func TestAuthCommandsManageLocalProfiles(t *testing.T) {
	root := NewRootCmd(testProfileFactory())
	auth, _, err := root.Find([]string{"auth"})
	if err != nil || auth.Name() != "auth" {
		t.Fatalf("find auth command: %v", err)
	}
	var names []string
	for _, cmd := range auth.Commands() {
		names = append(names, cmd.Name())
	}
	if strings.Join(names, ",") != "list,login,logout" {
		t.Fatalf("auth commands = %v, want list, login, and logout", names)
	}
}

func TestAuthListUsesOnlyProfileIndex(t *testing.T) {
	dir := privateProfileFixtureDir(t)
	t.Setenv(authstore.EnvConfigDir, dir)
	t.Setenv(config.EnvProfile, "personal")
	t.Setenv(config.EnvToken, "unused-token")
	t.Setenv(config.EnvTokenFile, filepath.Join(dir, "absent-token"))
	writeProfileIndex(t, dir, authstore.Config{
		Version: 1, CurrentProfile: "work",
		Profiles: map[string]authstore.Profile{
			"work": {
				APIBaseURL: "https://work.example.test", SpaceID: "work-space",
				TokenSource: authstore.TokenSource{Type: authstore.ManagedStore, Backend: authstore.Keychain, Entry: "absent-entry"},
			},
			"personal": {
				APIBaseURL: "https://personal.example.test", SpaceID: "personal-space",
				TokenSource: authstore.TokenSource{Type: authstore.TokenFile, Path: "absent-token"},
			},
		},
	})
	out, _, err := execRoot(t, newAuthTestFactory(), "auth", "list")
	if err != nil {
		t.Fatalf("list should only need profile metadata: %v", err)
	}
	want := map[string]any{
		"current_profile": "work",
		"profiles": []any{
			map[string]any{"profile": "personal", "api_base_url": "https://personal.example.test", "space_id": "personal-space", "source": "token_file"},
			map[string]any{"profile": "work", "api_base_url": "https://work.example.test", "space_id": "work-space", "source": "managed_store", "backend": "keychain"},
		},
	}
	if got := dataOf(t, out); !reflect.DeepEqual(got, want) {
		t.Fatalf("auth list = %v, want %v", got, want)
	}
}

func TestAuthLoginRejectsStdinAndFile(t *testing.T) {
	const stdin = "candidate-from-stdin\n"
	file := filepath.Join(t.TempDir(), "token")
	writeFixtureFile(t, file, "candidate-from-file\n")
	for _, flag := range []string{"--token-file", "--credential-file"} {
		t.Run(flag, func(t *testing.T) {
			f := newAuthTestFactory()
			f.In.WriteString(stdin)
			f.StoreFunc = func() (*authstore.Store, error) {
				return nil, errors.New("conflicting inputs reached profile storage")
			}
			_, _, err := execRoot(t, f, "auth", "login", "--with-token", flag, file)
			if exit := output.AsExitError(err); exit == nil || exit.Code != "VALIDATION_ERROR" {
				t.Fatalf("expected token input validation before storage, got %v", err)
			}
			if f.In.String() != stdin {
				t.Fatal("conflicting inputs consumed stdin")
			}
		})
	}
}

func TestAuthRejectedImportPreservesProfile(t *testing.T) {
	const incumbent = "existing-fixture-token"
	const candidate = "new-fixture-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+incumbent {
			t.Error("rejected import replaced the active credential")
		}
		io.WriteString(w, `{"records":[]}`)
	}))
	defer server.Close()

	dir := filepath.Join(t.TempDir(), "cli")
	t.Setenv(authstore.EnvConfigDir, dir)
	file := filepath.Join(t.TempDir(), "input")
	writeFixtureFile(t, file, incumbent+"\r\n")
	login := func(origin, space string) (string, string, error) {
		return execRoot(t, newAuthTestFactory(), "--profile", "agent", "--space", space, "auth", "login",
			"--api-base-url", origin, "--token-file", file)
	}
	if _, _, err := login(server.URL, "space-a"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, token, origin, space, code string
	}{
		{"unsafe bearer", candidate + " extra", server.URL, "space-a", "UNAUTHORIZED"},
		{"invalid origin", candidate, server.URL + "/api", "space-a", "VALIDATION_ERROR"},
		{"invalid Space", candidate, server.URL, "space b", "VALIDATION_ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeFixtureFile(t, file, tc.token)
			out, stderr, err := login(tc.origin, tc.space)
			if exit := output.AsExitError(err); exit == nil || exit.Code != tc.code {
				t.Fatalf("login error = %v, want %s", err, tc.code)
			}
			if strings.Contains(out+stderr, candidate) {
				t.Fatal("rejected login exposed the candidate")
			}
			raw, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, before) {
				t.Fatalf("rejected import changed the profile index: %v", err)
			}
		})
	}
	if _, _, err := execRoot(t, newAuthTestFactory(), "api", "GET", "/v1/records"); err != nil {
		t.Fatalf("original credential became unusable: %v", err)
	}
}
