package cmd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestUnifiedAuthCurrentImportAndRead(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	old := authCurrentFixtureStoredToken
	reply := authCurrentFixtureSuccess("candidate-id", "owner", "new-space")
	reply.body = strings.Replace(reply.body, `"name":"fixture"`, `"name":"prefix`+candidate+`suffix"`, 1)
	reply.body = strings.Replace(reply.body, `"bot_name":"Fixture Bot"`,
		`"bot_name":"`+url.QueryEscape(candidate)+`","relation_id":9007199254740993,"token_hash":"private"`, 1)
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		old:       authCurrentFixtureSuccess("old-id", "owner", "old-space"),
		candidate: reply,
	})
	seedAuthCurrentProfile(t, store, "target", server.URL, "old-space", old)

	// Neither the stored bearer nor inherited environment overrides may be used for the import.
	t.Run("import", func(t *testing.T) {
		t.Setenv(config.EnvToken, "wrong-runtime-token")
		t.Setenv(config.EnvTokenFile, filepath.Join(dir, "does-not-exist"))
		t.Setenv(config.EnvAPIBaseURL, "https://unused.example.invalid")
		stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(candidate+"\n"),
			"--verbose", "--profile", "target", "--space", "new-space",
			"auth", "login", "--api-base-url", server.URL, "--owner-id", "owner", "--with-token")
		if err != nil || !strings.Contains(stdout, "managed_store") {
			t.Fatalf("import: %v (%s %s)", err, stdout, stderr)
		}
		assertAuthCurrentRedaction(t, candidate, stdout, stderr)
	})
	stored, err := store.Snapshot("target", true)
	if err != nil || !stored.Exists || stored.Profile.SpaceID != "new-space" ||
		stored.Profile.TokenSource == nil || stored.Profile.TokenSource.Backend != authstore.BackendEncryptedFile {
		t.Fatalf("managed profile = %+v, err=%v", stored, err)
	}
	configBytes, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertAuthCurrentRedaction(t, candidate, string(configBytes))

	stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader("unused-stdin"),
		"--verbose", "--profile", "target", "auth", "get")
	if err != nil {
		t.Fatalf("auth get: %v (%s %s)", err, stdout, stderr)
	}
	assertAuthCurrentRedaction(t, candidate, stdout, stderr)
	var result struct {
		OK   bool
		Data struct {
			Token struct {
				ID string `json:"token_id"`
			}
			Permissions []json.RawMessage
			BotBindings []json.RawMessage `json:"bot_bindings"`
			NestedData  json.RawMessage   `json:"data"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || !result.OK ||
		result.Data.Token.ID != "candidate-id" || len(result.Data.Permissions) != 1 ||
		len(result.Data.BotBindings) != 1 || result.Data.NestedData != nil {
		t.Fatalf("unexpected TokenSelf envelope: %s (%v)", stdout, err)
	}
	binding := string(result.Data.BotBindings[0])
	if !strings.Contains(binding, "9007199254740993") || strings.Contains(binding, "token_hash") {
		t.Fatalf("unexpected bot binding projection: %s", binding)
	}

	calls := requests()
	if len(calls) != 2 {
		t.Fatalf("expected two _current calls, got %+v", calls)
	}
	for _, call := range calls {
		want := authCurrentFixtureRequest{method: http.MethodGet, target: authCurrentFixturePath, authorization: "Bearer " + candidate, space: "new-space"}
		if call != want {
			t.Fatalf("request = %+v, want %+v", call, want)
		}
	}

	stdout, stderr, err = runUnifiedAuthCurrent(store, strings.NewReader(""),
		"--dry-run", "--profile", "target", "api", "GET", "/business-check")
	if err != nil || !strings.Contains(stdout, server.URL+"/business-check") || !strings.Contains(stdout, "new-space") {
		t.Fatalf("managed business resolution: %v (%s %s)", err, stdout, stderr)
	}
	assertAuthCurrentRedaction(t, candidate, stdout, stderr)
}

func TestUnifiedAuthCurrentCreatesProfile(t *testing.T) {
	dir := phaseOneEnv(t)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		candidate: authCurrentFixtureSuccess("id", "owner", "space"),
	})
	t.Setenv(config.EnvProfile, "new")
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvSpaceID, "space")
	stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(candidate), "auth", "login", "--with-token")
	if err != nil || len(requests()) != 1 {
		t.Fatalf("new profile import: %v (%s %s)", err, stdout, stderr)
	}
	assertAuthCurrentRedaction(t, candidate, stdout, stderr)
	current, err := store.Snapshot("", false)
	if err != nil || !current.Exists || current.Name != "new" {
		t.Fatalf("first import did not set the current profile: %+v (%v)", current, err)
	}
}

func TestUnifiedAuthCurrentRejectsConcurrentTargetChange(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	concurrent := "fixture-concurrent-token"
	var baseline authstore.ProfileSnapshot
	var target config.Profile
	replacement := make(chan error, 1)
	ready := make(chan struct{})
	reply := authCurrentFixtureSuccess("id", "owner", "space")
	reply.beforeReply = func() {
		<-ready
		_, err := store.Import(baseline, target, concurrent, authstore.BackendEncryptedFile)
		replacement <- err
	}
	server, _ := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{candidate: reply})
	target = config.Profile{APIBaseURL: server.URL, SpaceID: "space"}
	seedAuthCurrentProfile(t, store, "target", target.APIBaseURL, target.SpaceID, authCurrentFixtureStoredToken)
	var err error
	baseline, err = store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	close(ready)
	stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(candidate),
		"--timeout", "2s", "--no-retry", "--profile", "target", "auth", "login", "--with-token")
	exit := output.AsExitError(err)
	if exit == nil || exit.Code != "PROFILE_CONFLICT" {
		t.Fatalf("concurrent import was not recognized: %v (%s %s)", err, stdout, stderr)
	}
	if err := <-replacement; err != nil {
		t.Fatalf("concurrent writer failed: %v", err)
	}
	cfg, err := config.LoadProfileConfig()
	if err != nil {
		t.Fatal(err)
	}
	_, current, err := cfg.SelectProfile("target", true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authstore.ReadManagedToken(cfg, current.TokenSource)
	if err != nil || token != concurrent {
		t.Fatalf("the concurrent writer's token did not survive: %v", err)
	}
}

func TestUnifiedAuthCurrentImportFailurePreservesProfile(t *testing.T) {
	candidate := authCurrentFixtureCandidateToken
	active := authCurrentFixtureSuccess("candidate-id", "owner", "space")
	expired := active
	expired.body = strings.Replace(expired.body, `"is_expired":false`, `"is_expired":true`, 1)
	revoked := active
	revoked.body = strings.Replace(revoked.body, `"status":"active"`, `"status":"revoked"`, 1)
	for _, tc := range []struct {
		name, token, code, typ string
		reply                  authCurrentFixtureReply
		wantHTTP               bool
	}{
		{"unauthorized", candidate, "AUTH_REQUIRED", "auth_error", authCurrentFixtureError(401, "AUTH_REQUIRED", "revoked", candidate), true},
		{"forbidden", candidate, "FORBIDDEN", "permission", authCurrentFixtureError(403, "FORBIDDEN", "access_denied", candidate), true},
		{"timeout", candidate, "NETWORK_ERROR", "network", authCurrentFixtureReply{waitForCancellation: true}, true},
		{"malformed", candidate, "INVALID_TOKEN_SELF", "api_error", authCurrentFixtureReply{status: http.StatusOK, body: `{"data":` + candidate}, true},
		{"incomplete", candidate, "INVALID_TOKEN_SELF", "api_error", authCurrentFixtureReply{status: http.StatusOK, body: `{"data":{"token":"` + candidate + `"}}`}, true},
		{"space", candidate, "VALIDATION_ERROR", "validation", authCurrentFixtureSuccess("id", "owner", "other-space"), true},
		{"owner", candidate, "VALIDATION_ERROR", "validation", authCurrentFixtureSuccess("id", "other-owner", "space"), true},
		{"expired", candidate, "TOKEN_EXPIRED", "auth_error", expired, true},
		{"revoked", candidate, "TOKEN_REVOKED", "auth_error", revoked, true},
		{"legacy", "bf_fixture-old-token", "UNAUTHORIZED", "auth_error", active, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			store := authstore.NewManagedStore(dir, nil)
			server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{tc.token: tc.reply})
			before := seedAuthCurrentProfile(t, store, "target", server.URL, "space", authCurrentFixtureStoredToken)
			stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(tc.token), "--profile", "target",
				"--verbose", "--timeout", "250ms", "--no-retry", "auth", "login", "--owner-id", "owner", "--with-token")
			exit := output.AsExitError(err)
			if exit == nil || exit.Code != tc.code || exit.Type != tc.typ || stdout != "" {
				t.Fatalf("login error = %v, stdout = %q, stderr = %q, want %s/%s", err, stdout, stderr, tc.typ, tc.code)
			}
			assertAuthCurrentRedaction(t, tc.token, stdout, stderr, err.Error())
			if tc.name == "unauthorized" && !strings.Contains(stderr, "revoked") {
				t.Fatalf("401 lost the backend reason: %s", stderr)
			}
			if tc.name == "forbidden" && !strings.Contains(stderr, "access_denied") {
				t.Fatalf("403 lost the backend reason: %s", stderr)
			}
			if calls := requests(); (tc.wantHTTP && len(calls) != 1) || (!tc.wantHTTP && len(calls) != 0) {
				t.Fatalf("unexpected _current calls: %+v", calls)
			}
			after, err := store.Snapshot("target", true)
			if err != nil || after.Profile.TokenSource == nil || after.Profile.TokenSource.Entry != before {
				t.Fatalf("failed import modified Profile: %+v (%v)", after, err)
			}
			cfg, err := config.LoadProfileConfig()
			if err != nil {
				t.Fatal(err)
			}
			token, err := authstore.ReadManagedToken(cfg, after.Profile.TokenSource)
			if err != nil || token != authCurrentFixtureStoredToken {
				t.Fatalf("previous managed credential no longer readable: %v", err)
			}
		})
	}
}

func TestUnifiedAuthCurrentPreflight(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		candidate: authCurrentFixtureSuccess("id", "owner", "space"),
	})
	for _, tc := range []struct {
		flags   []string
		profile string
	}{
		{[]string{"--dry-run"}, "new"},
		{[]string{"--format", "invalid-format"}, "new"},
		{[]string{"--jq", "("}, "new"},
		{nil, " padded "},
	} {
		stdin := strings.NewReader(candidate)
		stdout, stderr, err := runUnifiedAuthCurrent(store, stdin, append(tc.flags,
			"--profile", tc.profile, "--space", "space", "auth", "login", "--api-base-url", server.URL, "--with-token")...)
		if err == nil || stdin.Len() != len(candidate) {
			t.Fatalf("invalid options read stdin or passed: flags %v, profile %q (%v)", tc.flags, tc.profile, err)
		}
		assertAuthCurrentRedaction(t, candidate, stdout, stderr, err.Error())
	}
	if calls := requests(); len(calls) != 0 {
		t.Fatalf("preflight called _current: %+v", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("preflight created or changed config: %v", err)
	}
}

func TestUnifiedAuthCurrentGetModeAndDryRun(t *testing.T) {
	_ = phaseOneEnv(t)
	candidate := authCurrentFixtureCandidateToken
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		candidate: authCurrentFixtureError(http.StatusForbidden, "FORBIDDEN", "access_denied", candidate),
	})
	t.Setenv(config.EnvToken, candidate)
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	stdout, stderr, err := runUnifiedAuthCurrent(nil, strings.NewReader(""), "auth", "get")
	if err == nil || !strings.Contains(err.Error(), "requires unified credentials") || len(requests()) != 0 {
		t.Fatalf("auth get resolved a legacy credential: %v (%s %s)", err, stdout, stderr)
	}

	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	stdout, stderr, err = runUnifiedAuthCurrent(nil, strings.NewReader(""), "--dry-run", "auth", "get")
	if err != nil || !strings.Contains(stdout, authCurrentFixturePath) || !strings.Contains(stdout, "Bearer ***") || len(requests()) != 0 {
		t.Fatalf("dry-run: %v (%s %s)", err, stdout, stderr)
	}
	assertAuthCurrentRedaction(t, candidate, stdout, stderr)

	stdout, stderr, err = runUnifiedAuthCurrent(nil, strings.NewReader(""), "--verbose", "auth", "get")
	exit := output.AsExitError(err)
	if exit == nil || exit.Type != "permission" || exit.Code != "FORBIDDEN" || len(requests()) != 1 {
		t.Fatalf("auth get refusal: %v (%s %s)", err, stdout, stderr)
	}
	assertAuthCurrentRedaction(t, candidate, stdout, stderr, err.Error())
}

func runUnifiedAuthCurrent(store *authstore.ManagedStore, stdin *strings.Reader, args ...string) (stdout, stderr string, err error) {
	f := cmdutil.NewDefaultFactory()
	streams, _, out, errOut := cmdutil.NewTestIOStreams()
	streams.In = stdin
	f.IOStreams = streams
	if store != nil {
		f.ManagedStoreFunc = func() (*authstore.ManagedStore, error) { return store, nil }
	}
	root := NewRootCmd(f)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

func seedAuthCurrentProfile(t *testing.T, store *authstore.ManagedStore, name, origin, space, token string) string {
	t.Helper()
	before, err := store.Snapshot(name, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(before, config.Profile{APIBaseURL: origin, SpaceID: space}, token, authstore.BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	after, err := store.Snapshot(name, true)
	if err != nil || after.Profile.TokenSource == nil {
		t.Fatalf("profile not seeded: %v", err)
	}
	return after.Profile.TokenSource.Entry
}

func assertAuthCurrentRedaction(t *testing.T, token string, diagnostics ...string) {
	t.Helper()
	for _, text := range diagnostics {
		if strings.Contains(text, token) || strings.Contains(text, url.QueryEscape(token)) {
			t.Fatal("CLI Token leaked in command output")
		}
	}
}
