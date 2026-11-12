package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

func tokenSelf(id, space, status string, expired bool) string {
	return fmt.Sprintf(`{"data":{"token":{"token_id":%q,"owner_id":"owner-fixture","space_id":%q,"status":%q,"is_expired":%t},"permissions":[],"bot_bindings":[]}}`, id, space, status, expired)
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
	var verifierCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+phaseOneToken {
			t.Error("request did not use the imported Bearer")
		}
		switch r.URL.Path {
		case "/auth/v2/tokens/_current":
			verifierCalls.Add(1)
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodGet || r.Header.Get("X-Space-Id") != "" || len(body) != 0 || r.URL.RawQuery != "" {
				t.Error("self-check must send only the candidate Bearer")
			}
			io.WriteString(w, tokenSelf("token-fixture", "space-fixture", "active", false))
		case "/v1/records":
			if r.Header.Get("X-Space-Id") != "space-fixture" {
				t.Error("business request did not use the imported Space")
			}
			io.WriteString(w, `{"records":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	dir := filepath.Join(t.TempDir(), "cli")
	t.Setenv(authstore.EnvConfigDir, dir)
	t.Setenv(config.EnvAuthCurrentURL, server.URL+"/auth/v2/tokens/_current")
	got := requireProfileSuccess(t, runProfileProcess(t, phaseOneToken+"\n",
		"--profile", "agent", "--space", "space-fixture", "auth", "login", "--api-base-url", server.URL, "--with-token"))
	if got["state"] != "ready" {
		t.Fatalf("login state: %v", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil || bytes.Contains(raw, []byte(phaseOneToken)) || !bytes.Contains(raw, []byte(`"verified"`)) {
		t.Fatalf("profile metadata was not stored safely: %v", err)
	}

	// A subsequent process probes locally even with competing Token inputs.
	t.Setenv(config.EnvToken, "unused-probe-env")
	t.Setenv(config.EnvTokenFile, filepath.Join(dir, "not-present"))
	got = requireProfileSuccess(t, runProfileProcess(t, "", "--profile", "agent", "auth", "status"))
	want := map[string]string{"state": "ready", "profile": "agent", "api_base_url": server.URL, "space_id": "space-fixture",
		"token_id": "token-fixture", "owner_id": "owner-fixture", "source": "managed_store"}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("status %s = %v, want %s", key, got[key], value)
		}
	}
	unsetProfileEnv(t, config.EnvToken)
	unsetProfileEnv(t, config.EnvTokenFile)
	got = requireProfileSuccess(t, runProfileProcess(t, "", "config", "show"))
	if got["profile"] != "agent" || got["source"] != "managed_store" || got["token_id"] != "token-fixture" {
		t.Fatalf("config show = %v", got)
	}
	got = requireProfileSuccess(t, runProfileProcess(t, "", "auth", "list"))
	if got["current_profile"] != "agent" || len(got["profiles"].([]any)) != 1 {
		t.Fatalf("auth list = %v", got)
	}
	requireProfileSuccess(t, runProfileProcess(t, "", "api", "GET", "/v1/records"))
	requireProfileSuccess(t, runProfileProcess(t, "", "auth", "logout"))
	got = requireProfileSuccess(t, runProfileProcess(t, "", "--profile", "agent", "auth", "status"))
	if got["state"] != "missing" || verifierCalls.Load() != 1 {
		t.Fatalf("post-logout state = %v, verifier calls = %d", got, verifierCalls.Load())
	}
	if entries, err := filepath.Glob(filepath.Join(dir, "credential-*.enc")); err != nil || len(entries) != 0 {
		t.Fatalf("logout left encrypted credential entries: %v (%v)", entries, err)
	}
}

func TestAuthLoginRejectsVerifierFromAnotherOrigin(t *testing.T) {
	var calls atomic.Int32
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		io.WriteString(w, tokenSelf("old-environment", "shared-space", "active", false))
	}))
	defer verifier.Close()
	dir := filepath.Join(t.TempDir(), "cli")
	t.Setenv(authstore.EnvConfigDir, dir)
	t.Setenv(config.EnvAuthCurrentURL, verifier.URL+"/verify")

	f := newAuthTestFactory()
	f.In.WriteString("fixture-token\n")
	_, _, err := execRoot(t, f, "--profile", "agent", "--space", "shared-space", "auth", "login",
		"--api-base-url", "https://other-gateway.example.test", "--with-token")
	if exit := output.AsExitError(err); exit == nil || exit.Code != "PROFILE_SCOPE_MISMATCH" {
		t.Fatalf("expected an origin mismatch before verification, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a mismatched verifier received an authentication request")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("mismatched verifier created a profile directory: %v", err)
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
	const candidate = "rejected-fixture-candidate"
	const incumbent = "existing-fixture-token"
	dir := filepath.Join(t.TempDir(), "cli")
	t.Setenv(authstore.EnvConfigDir, dir)
	var verification atomic.Value
	type reply struct {
		status int
		body   string
	}
	verification.Store(reply{http.StatusOK, tokenSelf("old-id", "space-a", "active", false)})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/records" {
			if r.Header.Get("Authorization") != "Bearer "+incumbent {
				t.Error("rejected import replaced the active credential")
			}
			io.WriteString(w, `{"records":[]}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+incumbent && r.Header.Get("Authorization") != "Bearer "+candidate {
			t.Error("verification request did not use the supplied input")
		}
		value := verification.Load().(reply)
		w.WriteHeader(value.status)
		io.WriteString(w, value.body)
	}))
	defer server.Close()
	t.Setenv(config.EnvAuthCurrentURL, server.URL+"/verify")
	file := filepath.Join(t.TempDir(), "input")
	writeFixtureFile(t, file, incumbent+"\r\n")
	login := func() (string, string, error) {
		return execRoot(t, newAuthTestFactory(), "--profile", "agent", "--space", "space-a", "auth", "login",
			"--api-base-url", server.URL, "--token-file", file)
	}
	if _, _, err := login(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, file, candidate)
	for _, tc := range []struct {
		name, code string
		reply      reply
	}{
		{"remote 401", "AUTH_REQUIRED", reply{http.StatusUnauthorized, authRequiredFixture}},
		{"wrong Space", "PROFILE_SCOPE_MISMATCH", reply{http.StatusOK, tokenSelf("new-id", "space-b", "active", false)}},
		{"inactive", "UNAUTHORIZED", reply{http.StatusOK, tokenSelf("new-id", "space-a", "revoked", false)}},
		{"expired", "UNAUTHORIZED", reply{http.StatusOK, tokenSelf("new-id", "space-a", "active", true)}},
		{"missing expiry flag", "INVALID_RESPONSE", reply{http.StatusOK, strings.ReplaceAll(tokenSelf("new-id", "space-a", "active", false), `,"is_expired":false`, "")}},
		{"unexpected success status", "INVALID_RESPONSE", reply{http.StatusCreated, tokenSelf("new-id", "space-a", "active", false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verification.Store(tc.reply)
			out, stderr, err := login()
			ee := output.AsExitError(err)
			if ee == nil || ee.Code != tc.code {
				t.Fatalf("login error = %v, want %s", err, tc.code)
			}
			if tc.reply.status == http.StatusUnauthorized && (ee.HTTPStatus != 401 || !bytes.Contains(ee.Detail, []byte(`"details":{}`))) {
				t.Fatal("lost backend 401 or its details")
			}
			if strings.Contains(out+stderr, candidate) {
				t.Fatal("rejected login exposed the candidate")
			}
			raw, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(raw, before) {
				t.Fatal("rejected import changed the profile index")
			}
			if _, _, err := execRoot(t, newAuthTestFactory(), "api", "GET", "/v1/records"); err != nil {
				t.Fatalf("original credential became unusable: %v", err)
			}
		})
	}
}

func TestAuthConcurrentImportsKeepOneGeneration(t *testing.T) {
	arrived := make(chan string, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		arrived <- token
		<-release
		io.WriteString(w, tokenSelf("id-"+token[len(token)-1:], "space-a", "active", false))
	}))
	defer server.Close()
	t.Setenv(authstore.EnvConfigDir, filepath.Join(t.TempDir(), "cli"))
	t.Setenv(config.EnvAuthCurrentURL, server.URL+"/verify")

	results := make(chan profileProcessResult, 2)
	for _, token := range []string{"fixture-candidate-a", "fixture-candidate-b"} {
		go func() {
			results <- runProfileProcess(t, token, "--profile", "agent", "--space", "space-a", "auth", "login",
				"--api-base-url", server.URL, "--with-token")
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("both import processes did not reach the verifier")
		}
	}
	close(release)
	var winner string
	failures := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			winner = dataOf(t, result.out)["token_id"].(string)
		} else if result.code == 2 && strings.Contains(result.stderr, `"code": "PROFILE_CHANGED"`) {
			failures++
		} else {
			t.Fatalf("unexpected concurrent import failure: %v %s", result.err, result.stderr)
		}
	}
	state := requireProfileSuccess(t, runProfileProcess(t, "", "--profile", "agent", "auth", "status"))
	if failures != 1 || winner == "" || state["token_id"] != winner {
		t.Fatalf("concurrent import failures = %d, winner = %q, status = %v", failures, winner, state)
	}
}
