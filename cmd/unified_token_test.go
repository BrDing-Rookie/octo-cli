package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

const phaseOneToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno_-"
const authRequiredFixture = `{"error":{"code":"AUTH_REQUIRED","message":"Authentication required","details":{}}}`

func runPhaseOneCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return execRoot(t, newPhaseOneTestFactory(), args...)
}

func newPhaseOneTestFactory() *cmdutil.TestFactory {
	streams, in, out, errOut := cmdutil.NewTestIOStreams()
	f := cmdutil.NewDefaultFactory()
	f.IOStreams = streams
	f.RegistryFunc = testfixture.Registry
	return &cmdutil.TestFactory{Factory: f, In: in, Out: out, ErrOut: errOut}
}

func TestPhaseOneBusinessBearer(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/records" {
			t.Errorf("request = %s %s, want GET /v1/records", r.Method, r.URL.Path)
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + phaseOneToken:
			switch space := r.Header.Get("X-Space-Id"); space {
			case "fixture-space":
				io.WriteString(w, `{"records":[]}`)
			case "denied-space":
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"error":{"code":"SPACE_FORBIDDEN","message":"Space forbidden for `+phaseOneToken+`","details":{"space":"denied-space"}}}`)
			default:
				t.Errorf("unexpected X-Space-Id = %q", space)
			}
		case "Bearer uk_fixture_legacy":
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, authRequiredFixture)
		default:
			t.Error("request did not carry the selected bearer")
		}
	}))
	defer server.Close()
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvSpaceID, "fixture-space")
	t.Setenv(config.EnvBotToken, "app_ignored")

	for _, tc := range []struct {
		name, token, wantCode, wantDetails string
		wantStatus                         int
		args                               []string
	}{
		{"api", phaseOneToken, "", "", 0, []string{"api", "GET", "/v1/records"}},
		{"generated", phaseOneToken, "", "", 0, []string{"example", "record", "list"}},
		{"api legacy", "uk_fixture_legacy", "AUTH_REQUIRED", `{}`, http.StatusUnauthorized, []string{"api", "GET", "/v1/records"}},
		{"generated legacy", "uk_fixture_legacy", "AUTH_REQUIRED", `{}`, http.StatusUnauthorized, []string{"example", "record", "list"}},
		{"space forbidden", phaseOneToken, "SPACE_FORBIDDEN", `{"space":"denied-space"}`, http.StatusForbidden,
			[]string{"--space", "denied-space", "api", "GET", "/v1/records"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvToken, tc.token)
			before := calls.Load()
			out, stderr, err := runPhaseOneCommand(t, tc.args...)
			if tc.wantCode == "" {
				if err != nil || !strings.Contains(out, `"records"`) {
					t.Fatalf("expected a successful business response, got %v, stdout %q", err, out)
				}
			} else {
				ee := output.AsExitError(err)
				if ee == nil || ee.Code != tc.wantCode || ee.HTTPStatus != tc.wantStatus {
					t.Fatalf("expected HTTP %d and code %s, got %v", tc.wantStatus, tc.wantCode, err)
				}
				var wire struct {
					Error struct{ Details json.RawMessage }
				}
				if err := json.Unmarshal(ee.Detail, &wire); err != nil || string(wire.Error.Details) != tc.wantDetails {
					t.Error("expected backend details to be preserved")
				}
				if strings.Contains(stderr, tc.token) || strings.Contains(ee.Error(), tc.token) {
					t.Error("backend error exposed the bearer")
				}
			}
			if n := calls.Load() - before; n != 1 {
				t.Errorf("business requests = %d, want one", n)
			}
		})
	}
}

func TestPhaseOneBearerSources(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(authstore.EnvConfigDir, t.TempDir())
	store, err := authstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveProfile("stored", &authstore.ProfileMeta{APIBaseURL: server.URL}, "app_stored"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, token, alias string }{
		{"stored profile", "", ""},
		{"legacy environment", "", "app_old_env"},
		{"unsafe bearer", "opaque\n", "app_old_env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvToken, tc.token)
			t.Setenv(config.EnvBotToken, tc.alias)
			before := calls.Load()
			_, _, err := runPhaseOneCommand(t, "api", "GET", "/v1/records")
			ee := output.AsExitError(cmdutil.WrapCLIError(err))
			if ee == nil || ee.Type != "auth_error" || !strings.Contains(ee.Message, config.EnvToken) {
				t.Errorf("expected a local OCTO_TOKEN error, got %v", err)
			}
			if n := calls.Load() - before; n != 0 {
				t.Errorf("business requests = %d, want none", n)
			}
		})
	}
}

func TestPhaseOneBearerPreviewSource(t *testing.T) {
	t.Setenv(config.EnvAPIBaseURL, "https://api.example.invalid")
	t.Setenv(config.EnvToken, phaseOneToken)
	for _, args := range [][]string{
		{"api", "GET", "/v1/records"},
		{"example", "record", "list"},
	} {
		t.Run(args[0], func(t *testing.T) {
			out, _, err := runPhaseOneCommand(t, append([]string{"--dry-run", "--jq", ".identity.source"}, args...)...)
			if err != nil {
				t.Fatal(err)
			}
			var source string
			if err := json.Unmarshal([]byte(out), &source); err != nil || source != "env:"+config.EnvToken {
				t.Errorf("identity.source = %q, want env:%s", source, config.EnvToken)
			}
		})
	}
}

func TestPhaseOneUnsupportedSelectorsLeaveStdinUnread(t *testing.T) {
	server, calls := newOutputPreflightServer(t)
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvToken, phaseOneToken)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"api profile", []string{"api", "POST", "/v1/records", "--profile", "stored"}},
		{"generated bot id", []string{"example", "record", "create", "--bot-id", "stored"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPhaseOneTestFactory()
			f.In.WriteString(outputPreflightBody)
			_, _, err := execRoot(t, f, append(tc.args, "--data", "@-")...)
			ee := output.AsExitError(err)
			if ee == nil || ee.Type != "validation" ||
				!strings.Contains(ee.Message, "cannot select a credential for HTTP commands") {
				t.Errorf("expected a selector validation error, got %v", err)
			}
			if f.In.String() != outputPreflightBody {
				t.Error("command read stdin before rejecting the selector")
			}
		})
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("business requests = %d, want none", got)
	}
}

func TestPhaseOneBearerDiagnostics(t *testing.T) {
	var calls, followed atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Add(1)
	}))
	defer redirect.Close()
	encodedBearer := "%41" + phaseOneToken[1:]
	location := redirect.URL + "/?echo=" + encodedBearer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/echo" {
			io.WriteString(w, `{"echo":"\u0041`+phaseOneToken[1:]+`"}`)
			return
		}
		target := location
		if r.URL.Path == "/v1/malformed-redirect" {
			target += "#%"
		}
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	t.Setenv(config.EnvToken, phaseOneToken)
	t.Setenv(config.EnvAPIBaseURL, server.URL)

	params := `{"echo":"` + phaseOneToken + `"}`
	out, stderr, err := runPhaseOneCommand(t, "--dry-run", "api", "GET", "/v1/records", "--params", params)
	if err != nil || !strings.Contains(out, `"dry_run": true`) || strings.Contains(out+stderr, phaseOneToken) {
		t.Errorf("expected a redacted dry run, got error %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("dry run made %d requests", calls.Load())
	}
	for _, tc := range []struct{ method, path, wantCode string }{
		{http.MethodGet, "/v1/records", "HTTP_302"},
		{http.MethodPost, "/v1/malformed-redirect", "NETWORK_ERROR"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			before := calls.Load()
			_, stderr, err := runPhaseOneCommand(t, "--verbose", "api", tc.method, tc.path, "--params", params)
			ee := output.AsExitError(err)
			if ee == nil || ee.Code != tc.wantCode {
				t.Fatalf("redirect error code = %v, want %s", err, tc.wantCode)
			}
			diagnostics := stderr + ee.Error()
			if strings.Contains(diagnostics, phaseOneToken) ||
				strings.Contains(diagnostics, encodedBearer) ||
				strings.Contains(diagnostics, redirect.URL) {
				t.Error("redirect diagnostics exposed the Location or bearer")
			}
			if got := calls.Load() - before; got != 1 {
				t.Errorf("%s %s sent %d requests, want one", tc.method, tc.path, got)
			}
		})
	}
	if got := followed.Load(); got != 0 {
		t.Errorf("followed %d redirects, want none", got)
	}

	out, _, err = runPhaseOneCommand(t, "api", "GET", "/v1/echo")
	if err != nil || !strings.Contains(out, `"echo": "***REDACTED***"`) || strings.Contains(out, phaseOneToken) {
		t.Errorf("expected a redacted response echo, got error %v", err)
	}
}
