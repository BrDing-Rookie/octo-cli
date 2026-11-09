package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	reply.body = strings.Replace(reply.body, `"version":1`, `"version":0`, 1)
	permissions := `[{"domain":"Loop.task-2","actions":["Loop.task-2:Read_1.v2","Loop.task-2:*"]},` +
		`{"domain":"*","actions":["*:read","*","*:*"]},{"domain":"task","actions":[]}]`
	reply.body = strings.Replace(reply.body, `[{"domain":"task","actions":["task:read"]}]`, permissions, 1)
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
				ID         string          `json:"token_id"`
				Version    *int64          `json:"version"`
				Remark     json.RawMessage `json:"remark"`
				ExpiresAt  json.RawMessage `json:"expires_at"`
				LastUsedAt json.RawMessage `json:"last_used_at"`
			}
			Permissions []authPermission
			BotBindings []json.RawMessage `json:"bot_bindings"`
			NestedData  json.RawMessage   `json:"data"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || !result.OK ||
		result.Data.Token.ID != "candidate-id" ||
		len(result.Data.BotBindings) != 1 || result.Data.NestedData != nil {
		t.Fatalf("unexpected TokenSelf envelope: %s (%v)", stdout, err)
	}
	meta := result.Data.Token
	if meta.Version == nil || *meta.Version != 0 || string(meta.Remark) != "null" ||
		string(meta.ExpiresAt) != "null" || string(meta.LastUsedAt) != "null" {
		t.Fatalf("expected version zero and nullable metadata in TokenSelf: %s", stdout)
	}
	var wantPermissions []authPermission
	if err := json.Unmarshal([]byte(permissions), &wantPermissions); err != nil ||
		!reflect.DeepEqual(result.Data.Permissions, wantPermissions) {
		t.Fatalf("expected the permission patterns unchanged: %s (%v)", stdout, err)
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

func TestUnifiedAuthCurrentRedactsMetadataScalars(t *testing.T) {
	for _, tc := range []struct {
		name, bearer, field string
		oldJSON, newJSON    string
	}{
		{"numeric version", "812759536786399237", "version", `"version":9007199254740993`, `"version":812759536786399237`},
		{"status", "active", "status", "", ""},
		{"expiration", "false", "is_expired", "", ""},
		{"timestamp", "2027-01-23T06:00:00Z", "expires_at", `"expires_at":null`, `"expires_at":"2027-01-23T06:00:00Z"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phaseOneEnv(t)
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			t.Setenv(config.EnvToken, tc.bearer)

			reply := authCurrentFixtureSuccess("token-id", "owner", "space")
			reply.body = strings.Replace(reply.body, `"version":1`, `"version":9007199254740993`, 1)
			if tc.oldJSON != "" {
				reply.body = strings.Replace(reply.body, tc.oldJSON, tc.newJSON, 1)
			}
			reply.body = strings.NewReplacer(
				`"remark":null`, `"remark":"fixture remark"`,
				`"expires_at":null`, `"expires_at":"2028-01-23T06:00:00Z"`,
				`"last_used_at":null`, `"last_used_at":"2026-11-04T06:01:00Z"`,
			).Replace(reply.body)
			reply.body = strings.Replace(reply.body, `"bot_name":"Fixture Bot"`, `"bot_name":"Fixture Bot","enabled":false`, 1)
			server, _ := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{tc.bearer: reply})
			t.Setenv(config.EnvAPIBaseURL, server.URL)

			stdout, stderr, err := runUnifiedAuthCurrent(nil, strings.NewReader(""), "--verbose", "auth", "get")
			if err != nil {
				t.Fatalf("auth get: %v (%s %s)", err, stdout, stderr)
			}
			assertAuthCurrentRedaction(t, tc.bearer, stdout, stderr)
			var result struct {
				Data struct {
					Token       map[string]json.RawMessage
					BotBindings []map[string]json.RawMessage `json:"bot_bindings"`
				}
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatal(err)
			}
			for field, want := range map[string]string{
				"version": "9007199254740993", "status": `"active"`, "is_expired": "false",
				"remark": `"fixture remark"`, "expires_at": `"2028-01-23T06:00:00Z"`, "last_used_at": `"2026-11-04T06:01:00Z"`,
			} {
				if field == tc.field {
					want = `"***REDACTED***"`
				}
				if got := string(result.Data.Token[field]); got != want {
					t.Errorf("%s = %s, want %s", field, got, want)
				}
			}
			wantEnabled := "false"
			if tc.field == "is_expired" {
				wantEnabled = `"***REDACTED***"`
			}
			if got := string(result.Data.BotBindings[0]["enabled"]); got != wantEnabled {
				t.Errorf("binding enabled = %s, want %s", got, wantEnabled)
			}
		})
	}
}

func TestUnifiedAuthCurrentCreatesProfile(t *testing.T) {
	dir := phaseOneEnv(t)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	reply := authCurrentFixtureSuccess("id", "owner", "space")
	reply.body = strings.Replace(reply.body, `[{"domain":"task","actions":["task:read"]}]`, `[]`, 1)
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{candidate: reply})
	t.Setenv(config.EnvProfile, "new")
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvSpaceID, "space")
	stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(candidate),
		"--jq", ".identity.profile, .data.token_source", "auth", "login", "--with-token")
	var projected []string
	if err != nil || len(requests()) != 1 || json.Unmarshal([]byte(stdout), &projected) != nil ||
		len(projected) != 2 || projected[0] != "new" || projected[1] != "managed_store" {
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
		"--timeout", "2s", "--no-retry", "--profile", "target", "--jq", ".data.profile", "auth", "login", "--with-token")
	exit := output.AsExitError(err)
	if exit == nil || exit.Code != "PROFILE_CONFLICT" || stdout != "" {
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
	missingMetadata := active
	missingMetadata.body = strings.NewReplacer(
		`,"version":1`, "",
		`"created_at":"2026-11-04T06:00:00Z"`, `"created_at":null`,
		`"updated_at":"2026-11-04T06:00:00Z"`, `"updated_at":null`,
	).Replace(missingMetadata.body)
	withoutNullableField := func(field string) authCurrentFixtureReply {
		reply := active
		reply.body = strings.Replace(reply.body, `,"`+field+`":null`, "", 1)
		return reply
	}
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
		{"null action", candidate, "INVALID_TOKEN_SELF", "api_error", active.withActions(`[null]`), true},
		{"empty action", candidate, "INVALID_TOKEN_SELF", "api_error", active.withActions(`[""]`), true},
		{"blank action", candidate, "INVALID_TOKEN_SELF", "api_error", active.withActions(`["   "]`), true},
		{"unqualified action", candidate, "INVALID_TOKEN_SELF", "api_error", active.withActions(`["read"]`), true},
		{"missing required metadata", candidate, "INVALID_TOKEN_SELF", "api_error", missingMetadata, true},
		{"missing remark", candidate, "INVALID_TOKEN_SELF", "api_error", withoutNullableField("remark"), true},
		{"missing expiration", candidate, "INVALID_TOKEN_SELF", "api_error", withoutNullableField("expires_at"), true},
		{"missing last use", candidate, "INVALID_TOKEN_SELF", "api_error", withoutNullableField("last_used_at"), true},
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

func TestUnifiedAuthCurrentJQFailurePreservesProfile(t *testing.T) {
	for _, tc := range []struct {
		name, query, typ, code string
		cancelEvaluation       bool
	}{
		{"runtime error", ".data.profile | tonumber", "validation", "JQ_RUNTIME_ERROR", false},
		{"cancel evaluation", "def spin: spin; .data.profile, spin", "network", "NETWORK_ERROR", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			store := authstore.NewManagedStore(dir, nil)
			candidate := authCurrentFixtureCandidateToken
			old := authCurrentFixtureStoredToken
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reply := authCurrentFixtureSuccess("candidate-id", "owner", "new-space")
			if tc.cancelEvaluation {
				reply.beforeReply = func() { time.AfterFunc(500*time.Millisecond, cancel) }
			}
			server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
				candidate: reply,
				old:       authCurrentFixtureSuccess("old-id", "owner", "old-space"),
			})
			seedAuthCurrentProfile(t, store, "target", server.URL, "old-space", old)
			configPath := filepath.Join(dir, "config.json")
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}

			type commandResult struct {
				stdout, stderr string
				err            error
			}
			done := make(chan commandResult, 1)
			go func() {
				stdout, stderr, err := runUnifiedAuthCurrentContext(ctx, store, strings.NewReader(candidate),
					"--profile", "target", "--space", "new-space", "--jq", tc.query, "auth", "login", "--with-token")
				done <- commandResult{stdout: stdout, stderr: stderr, err: err}
			}()
			select {
			case result := <-done:
				exit := output.AsExitError(result.err)
				if exit == nil || exit.Type != tc.typ || exit.Code != tc.code || result.stdout != "" {
					t.Fatalf("expected %s with no stdout: %v (%s %s)", tc.code, result.err, result.stdout, result.stderr)
				}
				if tc.cancelEvaluation && exit.Message != "CLI Token import was cancelled" {
					t.Fatalf("expected cancellation during import, got %v", exit)
				}
				assertAuthCurrentRedaction(t, candidate, result.stdout, result.stderr, result.err.Error())
			case <-time.After(5 * time.Second):
				t.Fatal("login did not exit while evaluating jq")
			}
			after, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("failed import changed the Profile configuration: %v", err)
			}

			stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(""),
				"--profile", "target", "--jq", ".data.token.token_id", "auth", "get")
			if err != nil || strings.TrimSpace(stdout) != `"old-id"` {
				t.Errorf("expected the previous Token to remain active: %v (%s %s)", err, stdout, stderr)
			}
			if calls := requests(); len(calls) != 2 || calls[0].authorization != "Bearer "+candidate ||
				calls[0].space != "new-space" || calls[1].authorization != "Bearer "+old || calls[1].space != "old-space" {
				t.Error("expected candidate verification followed by a request with the original Profile and Token")
			}
		})
	}
}

func TestUnifiedAuthCurrentCancelWhileReadingStdin(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	candidate, old := authCurrentFixtureCandidateToken, authCurrentFixtureStoredToken
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		candidate: authCurrentFixtureSuccess("candidate-id", "owner", "space"),
		old:       authCurrentFixtureSuccess("old-id", "owner", "space"),
	})
	seedAuthCurrentProfile(t, store, "target", server.URL, "space", old)
	configPath := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	stdin, writer := io.Pipe()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = writer.Close()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type commandResult struct {
		stdout, stderr string
		err            error
	}
	done := make(chan commandResult, 1)
	go func() {
		stdout, stderr, err := runUnifiedAuthCurrentContext(ctx, store, stdin, "--profile", "target", "auth", "login", "--with-token")
		done <- commandResult{stdout: stdout, stderr: stderr, err: err}
	}()
	wrote := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, candidate)
		wrote <- err
	}()
	// The synchronous pipe write confirms login has read from stdin. Keep the
	// writer open so there is no EOF to unblock the read before cancellation.
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case result := <-done:
		t.Fatalf("login exited before reading stdin: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("login did not read stdin")
	}
	cancel()
	select {
	case result := <-done:
		exit := output.AsExitError(result.err)
		if exit == nil || exit.Code != "NETWORK_ERROR" || result.stdout != "" {
			t.Fatalf("expected cancellation with empty stdout: %v (%s %s)", result.err, result.stdout, result.stderr)
		}
		assertAuthCurrentRedaction(t, candidate, result.stderr, result.err.Error())
	case <-time.After(5 * time.Second):
		t.Fatal("login waited for stdin to close after cancellation")
	}
	if len(requests()) != 0 {
		t.Fatal("cancelled login contacted the gateway")
	}
	after, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("cancelled login changed the Profile configuration: %v", err)
	}
	stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(""),
		"--profile", "target", "--jq", ".data.token.token_id", "auth", "get")
	if err != nil || strings.TrimSpace(stdout) != `"old-id"` {
		t.Fatalf("expected the original Token after cancellation: %v (%s %s)", err, stdout, stderr)
	}
}

func TestUnifiedAuthCurrentGetRejectsInvalidTokenSelf(t *testing.T) {
	for _, tc := range []struct {
		name, original, replacement string
	}{
		{"null action", `["task:read"]`, `[null]`},
		{"empty action", `["task:read"]`, `[""]`},
		{"blank action", `["task:read"]`, `["   "]`},
		{"unqualified action", `["task:read"]`, `["read"]`},
		{"empty action field", `["task:read"]`, `["task:"]`},
		{"padded action", `["task:read"]`, `["task:read "]`},
		{"extra separator", `["task:read"]`, `["task:read:extra"]`},
		{"partial wildcard", `["task:read"]`, `["task:r*"]`},
		{"mismatched domain", `["task:read"]`, `["doc:read"]`},
		{"global wildcard in concrete group", `["task:read"]`, `["*"]`},
		{"invalid group domain", `"domain":"task"`, `"domain":"ta*k"`},
		{"missing name", `"name":"fixture",`, ""},
		{"null name", `"name":"fixture"`, `"name":null`},
		{"missing version", `,"version":1`, ""},
		{"null version", `"version":1`, `"version":null`},
		{"fractional version", `"version":1`, `"version":1.5`},
		{"missing creation time", `"created_at":"2026-11-04T06:00:00Z",`, ""},
		{"null creation time", `"created_at":"2026-11-04T06:00:00Z"`, `"created_at":null`},
		{"missing update time", `"updated_at":"2026-11-04T06:00:00Z",`, ""},
		{"null update time", `"updated_at":"2026-11-04T06:00:00Z"`, `"updated_at":null`},
		{"missing remark", `,"remark":null`, ""},
		{"missing expiration", `,"expires_at":null`, ""},
		{"missing last use", `,"last_used_at":null`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			store := authstore.NewManagedStore(dir, nil)
			token := authCurrentFixtureStoredToken
			reply := authCurrentFixtureSuccess("stored-id", "owner", "space")
			reply.body = strings.Replace(reply.body, tc.original, tc.replacement, 1)
			server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{token: reply})
			seedAuthCurrentProfile(t, store, "target", server.URL, "space", token)

			stdout, stderr, err := runUnifiedAuthCurrent(store, strings.NewReader(""),
				"--profile", "target", "auth", "get")
			exit := output.AsExitError(err)
			if exit == nil || exit.Type != "api_error" || exit.Code != "INVALID_TOKEN_SELF" || stdout != "" || len(requests()) != 1 {
				t.Fatalf("expected INVALID_TOKEN_SELF from auth get: %v (%s %s)", err, stdout, stderr)
			}
			assertAuthCurrentRedaction(t, token, stdout, stderr, err.Error())
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

func runUnifiedAuthCurrent(store *authstore.ManagedStore, stdin io.Reader, args ...string) (stdout, stderr string, err error) {
	return runUnifiedAuthCurrentContext(context.Background(), store, stdin, args...)
}

func runUnifiedAuthCurrentContext(ctx context.Context, store *authstore.ManagedStore, stdin io.Reader, args ...string) (stdout, stderr string, err error) {
	f := cmdutil.NewDefaultFactory()
	streams, _, out, errOut := cmdutil.NewTestIOStreams()
	streams.In = stdin
	f.IOStreams = streams
	if store != nil {
		f.ManagedStoreFunc = func() (*authstore.ManagedStore, error) { return store, nil }
	}
	root := NewRootCmd(f)
	root.SetArgs(args)
	err = root.ExecuteContext(ctx)
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
