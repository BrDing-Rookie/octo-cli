package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func runServerV2Command(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	streams, in, out, errOut := cmdutil.NewTestIOStreams()
	f := cmdutil.NewDefaultFactory()
	f.IOStreams = streams
	return execRoot(t, &cmdutil.TestFactory{Factory: f, In: in, Out: out, ErrOut: errOut}, args...)
}

func TestServerV2ReadCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantMethod := http.MethodGet
		if r.URL.Path == "/api/v2/cli/messages/_search_global_groups" {
			wantMethod = http.MethodPost
		}
		if r.Method != wantMethod || r.Header.Get("Authorization") != "Bearer "+phaseOneToken {
			t.Errorf("expected an authenticated %s", wantMethod)
		}
		if r.Header.Get("X-Space-Id") != "" {
			t.Error("Server v2 must use the Token's Space")
		}
		switch r.URL.Path {
		case "/api/v2/cli/identity":
			io.WriteString(w, `{"data":{"user_id":"fixture-user","user_name":"Fixture User","bot_id":"","space_id":"token-space"}}`)
		case "/api/v2/cli/groups":
			if r.URL.RawQuery != "page=2&page_size=10" {
				t.Errorf("group list query = %q", r.URL.RawQuery)
			}
			io.WriteString(w, `{"data":[],"pagination":{"total":10,"page":2,"page_size":10}}`)
		case "/api/v2/cli/messages/_search_global_groups":
			io.WriteString(w, `{"data":{"sequence":42,"groups":[],"total_groups":0,"total_groups_approx":true},"pagination":{"has_more":false,"next_cursor":""}}`)
		default:
			t.Errorf("unexpected v2 path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvToken, phaseOneToken)
	t.Setenv(config.EnvSpaceID, "profile-space")

	for _, tc := range []struct {
		name string
		args []string
		jq   string
		want string
	}{
		{"generated identity", []string{"server", "identity", "get"}, "[.data.space_id, .data.bot_id]", `["token-space",""]`},
		{"raw identity", []string{"api", "GET", "/api/v2/cli/identity"}, "[.data.space_id, .data.bot_id]", `["token-space",""]`},
		{"generated group list", []string{"server", "group", "list", "--page", "2", "--page-size", "10"},
			"[.data, ._pagination.page]", `[[],2]`},
		{"raw group list", []string{"api", "GET", "/api/v2/cli/groups", "--params", `{"page":2,"page_size":10}`},
			"[.data, ._pagination.page]", `[[],2]`},
		{"generated group aggregation", []string{"server", "message", "search-global-groups", "--keyword", "fixture"},
			"[.data.groups, .data.sequence, ._pagination.has_more]", `[[],42,false]`},
		{"raw group aggregation", []string{"api", "POST", "/api/v2/cli/messages/_search_global_groups", "--data", `{"keyword":"fixture"}`},
			"[.data.groups, .data.sequence, ._pagination.has_more]", `[[],42,false]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--jq", tc.jq}, tc.args...)
			stdout, _, err := runServerV2Command(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal([]byte(stdout), &value); err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(value)
			if err != nil || string(got) != tc.want {
				t.Fatalf("result = %s, want %s (error: %v)", got, tc.want, err)
			}
		})
	}
}

func TestServerV2MessageSendDoesNotReplayGatewayFailure(t *testing.T) {
	const body = `{"channel_id":"fixture-group","channel_type":2,"payload":{"content":"fixture-message","type":1}}`
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/cli/messages" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		actual, err := io.ReadAll(r.Body)
		if err != nil || string(actual) != body {
			t.Errorf("message send body = %s (error: %v)", actual, err)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, `{"data":{}}`)
	}))
	defer server.Close()
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvToken, phaseOneToken)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"generated", []string{"server", "message", "send", "--channel-id", "fixture-group",
			"--channel-type", "2", "--data", `{"payload":{"type":1,"content":"fixture-message"}}`}},
		{"raw", []string{"api", "POST", "/api/v2/cli/messages", "--data", body}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls.Store(0)
			_, _, err := runServerV2Command(t, tc.args...)
			if exit := output.AsExitError(err); exit == nil || exit.Code != "RESULT_UNKNOWN" {
				t.Errorf("expected RESULT_UNKNOWN, got %v", err)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("message send attempts = %d, want 1", got)
			}
		})
	}
}

func TestServerV2FileTransport(t *testing.T) {
	const fileContents = "fixture-upload-bytes"
	var requests atomic.Int32
	// Any attempt to follow Location would make a second request to this fixture.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/api/v2/cli/files":
			if r.Method != http.MethodPost {
				t.Errorf("upload method = %s", r.Method)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer file.Close()
			got, err := io.ReadAll(file)
			if err != nil || string(got) != fileContents || header.Filename != "fixture.txt" {
				t.Errorf("upload file = %q %q (error: %v)", header.Filename, got, err)
			}
			io.WriteString(w, `{"data":{"url":"/fixture.txt","name":"fixture.txt","size":20}}`)
		case "/api/v2/cli/files/_download":
			if r.Method != http.MethodGet || r.URL.Query().Get("path") != "chat/fixture.txt" {
				t.Errorf("unexpected download request %s %s", r.Method, r.URL)
			}
			w.Header().Set("Location", "/storage/fixture.txt?signature=fixture-signed-value")
			w.WriteHeader(http.StatusFound)
		default:
			t.Errorf("unexpected file request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv(config.EnvAPIBaseURL, server.URL)
	t.Setenv(config.EnvToken, phaseOneToken)
	filePath := filepath.Join(t.TempDir(), "fixture.txt")
	writeFixtureFile(t, filePath, fileContents)

	stdout, stderr, err := runServerV2Command(t, "server", "file", "upload", "--file", filePath, "--dry-run")
	if err != nil || requests.Load() != 0 || strings.Contains(stdout+stderr, fileContents) {
		t.Fatalf("expected a local preview without file contents, got %v", err)
	}
	stdout, stderr, err = runServerV2Command(t, "server", "file", "upload", "--file", filePath, "--verbose", "--jq", ".data.name")
	if err != nil || strings.TrimSpace(stdout) != `"fixture.txt"` || strings.Contains(stderr, fileContents) {
		t.Fatalf("expected multipart upload without file bytes in diagnostics, got %q, %v", stdout, err)
	}
	for _, args := range [][]string{
		{"server", "file", "download", "--path", "chat/fixture.txt"},
		{"api", "GET", "/api/v2/cli/files/_download", "--params", `{"path":"chat/fixture.txt"}`},
	} {
		stdout, stderr, err := runServerV2Command(t, append(args, "--verbose", "--jq", ".data.url")...)
		if err != nil || strings.TrimSpace(stdout) != `"/storage/fixture.txt?signature=fixture-signed-value"` ||
			strings.Contains(stderr, "fixture-signed-value") {
			t.Errorf("download %v must return Location on stdout only (error: %v)", args, err)
		}
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("file requests = %d, want 3", got)
	}
}
