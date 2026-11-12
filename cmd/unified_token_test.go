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
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

const phaseOneToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno_-"
const authRequiredFixture = `{"error":{"code":"AUTH_REQUIRED","message":"Authentication required","details":{}}}`

func runPhaseOneCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	streams, in, out, errOut := cmdutil.NewTestIOStreams()
	f := cmdutil.NewDefaultFactory()
	f.IOStreams = streams
	f.RegistryFunc = func() *registry.Registry { return testfixture.Registry() }
	return execRoot(t, &cmdutil.TestFactory{Factory: f, In: in, Out: out, ErrOut: errOut}, args...)
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

func TestPhaseOneBearerDiagnostics(t *testing.T) {
	var calls, followed atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Add(1)
	}))
	defer redirect.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/echo" {
			io.WriteString(w, `{"echo":"\u0041`+phaseOneToken[1:]+`"}`)
			return
		}
		w.Header().Set("Location", redirect.URL+"/?echo="+phaseOneToken)
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
	_, stderr, err = runPhaseOneCommand(t, "--verbose", "api", "GET", "/v1/records", "--params", params)
	ee := output.AsExitError(err)
	if ee == nil || ee.Code != "HTTP_302" || strings.Contains(stderr, phaseOneToken) || strings.Contains(ee.Error(), phaseOneToken) {
		t.Error("expected a redacted redirect error and trace")
	}
	if calls.Load() != 1 || followed.Load() != 0 {
		t.Errorf("requests = %d, followed redirects = %d", calls.Load(), followed.Load())
	}

	out, _, err = runPhaseOneCommand(t, "api", "GET", "/v1/echo")
	if err != nil || !strings.Contains(out, `"echo": "***REDACTED***"`) || strings.Contains(out, phaseOneToken) {
		t.Errorf("expected a redacted response echo, got error %v", err)
	}
}
