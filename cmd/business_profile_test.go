package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func phaseOneEnv(t *testing.T) string {
	t.Helper()
	for _, key := range []string{"OCTO_PROFILE", "OCTO_TOKEN", "OCTO_TOKEN_FILE", "OCTO_BOT_TOKEN",
		"OCTO_BOT_ID", "OCTO_SPACE_ID", "OCTO_API_BASE_URL", "OCTO_CREDENTIAL_MODE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	t.Setenv("OCTO_CONFIG_DIR", dir)
	return dir
}

func phaseOneWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func phaseOneRun(args ...string) (string, error) {
	f := cmdutil.NewDefaultFactory()
	var out bytes.Buffer
	f.IOStreams.Out, f.IOStreams.ErrOut = &out, &out
	root := NewRootCmd(f)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func phaseOneTargets(t *testing.T, a, b string) (firstURL, secondURL string, received <-chan string) {
	t.Helper()
	calls := make(chan string, 8)
	server := func(name string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls <- fmt.Sprintf("%s %s %s %s", name, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Space-Id"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[]}`)
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	return server(a), server(b), calls
}

func phaseOneCheckRequest(t *testing.T, calls <-chan string, want string, args ...string) {
	t.Helper()
	out, err := phaseOneRun(args...)
	if err != nil {
		t.Fatalf("execute %v: %v (%s)", args, err, out)
	}
	select {
	case got := <-calls:
		if got != want {
			t.Fatalf("request = %q, want %q", got, want)
		}
		token := strings.Fields(got)[3]
		if strings.Contains(out, token) {
			t.Fatal("credential leaked in output")
		}
	default:
		t.Fatal("no request received")
	}
}

func TestPhaseOneBusinessProfileRequest(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	tokenA := filepath.Join(dir, "token-a")
	tokenB := filepath.Join(dir, "token-b")
	phaseOneWrite(t, tokenA, "unified-profile-a-secret\n")
	phaseOneWrite(t, tokenB, "unified-profile-b-secret\n")
	originA, originB, calls := phaseOneTargets(t, "a", "b")
	t.Setenv("OCTO_API_BASE_URL", "http://127.0.0.1:1")
	t.Setenv("OCTO_BOT_ID", "old-bot")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
		"version":1,"current_profile":"a","profiles":{
			"a":{"api_base_url":%q,"space_id":"space-a","token_source":{"type":"token_file","path":%q}},
			"b":{"api_base_url":%q,"space_id":"space-b","token_source":{"type":"token_file","path":%q}}
		}}`, originA, tokenA, originB, tokenB))

	override := filepath.Join(dir, "override")
	phaseOneWrite(t, override, "unified-flag-secret")
	for _, tc := range []struct {
		name, profile, token, want string
		flags                      []string
	}{
		{"default", "", "", "a /phase-one Bearer unified-profile-a-secret space-a", nil},
		{"profile env", "b", "", "b /phase-one Bearer unified-profile-b-secret space-b", nil},
		{"token env", "b", "unified-env-secret", "b /phase-one Bearer unified-env-secret space-b", nil},
		{"flags override env", "b", "unified-env-secret", "a /phase-one Bearer unified-flag-secret space-a", []string{"--profile", "a", "--credential-file", override}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.profile != "" {
				t.Setenv("OCTO_PROFILE", tc.profile)
			}
			if tc.token != "" {
				t.Setenv("OCTO_TOKEN", tc.token)
			}
			phaseOneCheckRequest(t, calls, tc.want, append(tc.flags, "api", "GET", "/phase-one")...)
		})
	}
}

func TestPhaseOneBusinessProfileIdentityRedaction(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "abc/1234")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{
		"version":1,"profiles":{
			"prefixabc/1234suffix":{"api_base_url":"https://literal.example.invalid"},
			"prefix%61bc%2f1234suffix":{"api_base_url":"https://encoded.example.invalid"},
			"ordinary":{"api_base_url":"https://ordinary.example.invalid"}
		}
	}`)
	for _, tc := range []struct{ name, profile, want, url string }{
		{"literal", "prefixabc/1234suffix", "prefix***REDACTED***suffix", "https://literal.example.invalid/check"},
		{"encoded", "prefix%61bc%2f1234suffix", "prefix***REDACTED***suffix", "https://encoded.example.invalid/check"},
		{"ordinary", "ordinary", "ordinary", "https://ordinary.example.invalid/check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := phaseOneRun("--dry-run", "--profile", tc.profile, "api", "GET", "/check")
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Identity struct{ Type, Source, Profile string }
				Data     struct{ URL string }
			}
			if err := json.Unmarshal([]byte(out), &envelope); err != nil {
				t.Fatal(err)
			}
			if id := envelope.Identity; id.Type != "token" || id.Source != "env:OCTO_TOKEN" || id.Profile != tc.want {
				t.Errorf("identity = %+v, want token from env:OCTO_TOKEN with profile %q", id, tc.want)
			}
			if envelope.Data.URL != tc.url {
				t.Errorf("URL = %q, want %q", envelope.Data.URL, tc.url)
			}
		})
	}
}

func TestPhaseOneBusinessProfileFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string) []string
		want  string
	}{
		{"conflicting env even with a file flag", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "unified-env-secret")
			t.Setenv("OCTO_TOKEN_FILE", filepath.Join(dir, "valid"))
			return []string{"--credential-file", filepath.Join(dir, "valid")}
		}, "OCTO_TOKEN and OCTO_TOKEN_FILE are both set"},
		{"missing explicit flag profile even with env Token", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "unified-env-secret")
			t.Setenv("OCTO_PROFILE", "a")
			return []string{"--profile", "missing"}
		}, "selected profile does not exist"},
		{"missing explicit env profile even with file flag", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_PROFILE", "missing")
			return []string{"--credential-file", filepath.Join(dir, "valid")}
		}, "selected profile does not exist"},
		{"new profile selection cannot fall back to a legacy profile", func(t *testing.T, dir string) []string {
			phaseOneWrite(t, filepath.Join(dir, "config.json"), `{"profiles":{"a":{"robot_id":"bot-a"}}}`)
			t.Setenv("OCTO_PROFILE", "other")
			return []string{"--profile", "a"}
		}, "selected profile does not exist"},
		{"missing file flag does not fall back", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "unified-env-secret")
			return []string{"--credential-file", filepath.Join(dir, "missing")}
		}, "cannot read credential from flag:--credential-file"},
		{"nonregular env file does not fall back", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN_FILE", dir)
			return nil
		}, "cannot read credential from env:OCTO_TOKEN_FILE"},
		{"unreadable profile file", func(t *testing.T, dir string) []string {
			if err := os.Chmod(filepath.Join(dir, "valid"), 0); err != nil {
				t.Fatal(err)
			}
			if f, err := os.Open(filepath.Join(dir, "valid")); err == nil {
				f.Close()
				t.Skip("running as a user that can bypass file permissions")
			}
			return nil
		}, "cannot read credential from profile:token_file"},
		{"empty environment token does not fall back", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "")
			return nil
		}, "invalid unified Token from env:OCTO_TOKEN"},
		{"invalid environment Token does not fall back", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "unified-env-secret with whitespace")
			return []string{"--profile", "a"}
		}, "invalid unified Token from env:OCTO_TOKEN"},
		{"Space mismatch", func(t *testing.T, dir string) []string {
			return []string{"--space", "space-b"}
		}, "requested Space does not match the selected profile"},
		{"unknown config version", func(t *testing.T, dir string) []string {
			phaseOneWrite(t, filepath.Join(dir, "config.json"), `{"version":2,"profiles":{}}`)
			return nil
		}, "unsupported config.json version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
			file := filepath.Join(dir, "valid")
			phaseOneWrite(t, file, "unified-file-secret")
			phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
				"version":1,"current_profile":"a","profiles":{
					"a":{"api_base_url":"https://phase-one.example","space_id":"space-a","token_source":{"type":"token_file","path":%q}}
				}}`, file))
			args := tc.setup(t, dir)
			args = append(args, "--dry-run", "api", "GET", "/phase-one")
			out, err := phaseOneRun(args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("execute: %v (%s), want %q", err, out, tc.want)
			}
			if strings.Contains(out+err.Error(), "unified-env-secret") || strings.Contains(out+err.Error(), "unified-file-secret") {
				t.Fatal("credential leaked in diagnostics")
			}
		})
	}
}

func TestPhaseOneStandaloneFileAndOfflineDiscovery(t *testing.T) {
	dir := phaseOneEnv(t)
	file := filepath.Join(dir, "token")
	phaseOneWrite(t, file, "standalone-secret")
	t.Setenv("OCTO_TOKEN_FILE", file)
	t.Setenv("OCTO_API_BASE_URL", "https://standalone.example")
	path := "/v1/bot/messages/_search"
	out, err := phaseOneRun("--dry-run", "api", "POST", path)
	if err != nil || !strings.Contains(out, "https://standalone.example"+path) ||
		!strings.Contains(out, "Bearer ***") || strings.Contains(out, "standalone-secret") {
		t.Fatalf("standalone dry run: %v (%s)", err, out)
	}

	// A named credential file that cannot be opened must not affect local commands.
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{
		"version":1,"current_profile":"a","profiles":{
			"a":{"space_id":"space-a","token_source":{"type":"token_file","path":"/missing"}}
		}}`)
	t.Setenv("OCTO_TOKEN_FILE", filepath.Join(dir, "missing"))
	t.Setenv("OCTO_TOKEN", "conflicting-secret")
	for _, args := range [][]string{{"help"}, {"schema", "group.list"}, {"auth", "list"}} {
		out, err := phaseOneRun(args...)
		if err != nil || strings.Contains(out, "conflicting-secret") {
			t.Fatalf("offline %v: %v (%s)", args, err, out)
		}
		if args[0] == "auth" && (!strings.Contains(out, "current_profile") || !strings.Contains(out, "space-a")) {
			t.Fatalf("missing Profile metadata: %s", out)
		}
	}
}

func TestPhaseOneExplicitBotID(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_TOKEN", "opaque-runtime-token")
	t.Setenv("OCTO_API_BASE_URL", "https://standalone.example")
	args := []string{"--bot-id", "missing", "--dry-run", "api", "GET", "/phase-one"}
	if out, err := phaseOneRun(args...); err == nil || !strings.Contains(err.Error(), "no profile found for bot id") {
		t.Fatalf("legacy selector: %v (%s), want missing bot error", err, out)
	}
	tokenPath := filepath.Join(dir, "token")
	phaseOneWrite(t, tokenPath, "file-token")
	args = append([]string{"--credential-file", tokenPath}, args...)
	if out, err := phaseOneRun(args...); err == nil || !strings.Contains(err.Error(), "--bot-id cannot be used with unified credentials") {
		t.Fatalf("unified selector: %v (%s), want incompatible bot flag error", err, out)
	}
}

func TestPhaseOneOfflineSchemaFormat(t *testing.T) {
	dir := phaseOneEnv(t)
	unavailable := filepath.Join(dir, "not-a-directory")
	phaseOneWrite(t, unavailable, "")
	t.Setenv("OCTO_CONFIG_DIR", unavailable)
	t.Setenv("OCTO_FORMAT", "table")
	for _, tc := range []struct {
		name, mode, format string
		wantJSON           bool
	}{
		{"legacy fallback", "", "", true},
		{"legacy explicit format", "", "table", false},
		{"unified runtime format", "unified", "", false},
		{"unified explicit format", "unified", "json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			args := []string{"--profile", "unavailable", "schema", "--list", "drive"}
			if tc.format != "" {
				args = append(args, "--format", tc.format)
			}
			out, err := phaseOneRun(args...)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.wantJSON {
				if json.Valid([]byte(out)) || !strings.HasPrefix(out, "operations") {
					t.Fatal("expected schema table")
				}
				return
			}
			var envelope struct {
				OK   bool
				Data struct{ Service string }
			}
			if err := json.Unmarshal([]byte(out), &envelope); err != nil || !envelope.OK || envelope.Data.Service != "drive" {
				t.Fatalf("expected the drive schema JSON envelope: %v", err)
			}
		})
	}
}

func TestPhaseOneLegacyEnvBypassesConfig(t *testing.T) {
	for _, tc := range []struct {
		name, contents, env, token, configError string
		unreadable                              bool
	}{
		{"malformed", "{", "OCTO_TOKEN", "bf_existing-bot-token", "invalid config.json", false},
		{"unreadable", `{"version":1,"profiles":{}}`, "OCTO_BOT_TOKEN", "opaque-legacy-alias", "cannot read config.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			configPath := filepath.Join(dir, "config.json")
			phaseOneWrite(t, configPath, tc.contents)
			if tc.unreadable {
				if err := os.Chmod(configPath, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := os.ReadFile(configPath); !os.IsPermission(err) {
					t.Skipf("cannot exercise permission denial: %v", err)
				}
			}
			t.Setenv(tc.env, tc.token)
			t.Setenv("OCTO_API_BASE_URL", "https://legacy.example")
			args := []string{"--dry-run", "api", "GET", "/phase-one"}
			if out, err := phaseOneRun(args...); err != nil || !strings.Contains(out, "https://legacy.example/phase-one") {
				t.Fatalf("legacy invocation: %v (%s), want dry-run request", err, out)
			}
			t.Setenv("OCTO_PROFILE", "selected")
			if out, err := phaseOneRun(args...); err == nil || !strings.Contains(err.Error(), tc.configError) {
				t.Fatalf("unified invocation: %v (%s), want %q", err, out, tc.configError)
			}
		})
	}
}

func TestPhaseOneKeepsSuccessfulResponseFields(t *testing.T) {
	phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "id")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer id" {
			t.Error("request did not use the unified bearer")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"document_id":"doc-1","folder_id":"folder-2"}`)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	out, err := phaseOneRun("api", "GET", "/phase-one")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data["document_id"] != "doc-1" || envelope.Data["folder_id"] != "folder-2" {
		t.Fatalf("business fields were rewritten: %s", out)
	}
}

func TestPhaseOneShortBearerDiagnostics(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc1234"
	const note = "prefix" + bearer + "suffix"
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", bearer)
	t.Setenv("OCTO_SPACE_ID", note)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("note") != note || r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("masking changed the outbound request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, note)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	args := []string{"api", "GET", "/check", "--params", `{"note":"` + note + `"}`}
	for _, flag := range []string{"--dry-run", "--verbose"} {
		t.Run(flag, func(t *testing.T) {
			out, err := phaseOneRun(append([]string{flag}, args...)...)
			if (err == nil) != (flag == "--dry-run") {
				t.Fatalf("unexpected result: %v", err)
			}
			if strings.Contains(out+fmt.Sprint(err), bearer) || !strings.Contains(out, "prefix***REDACTED***suffix") {
				t.Fatalf("Bearer must be masked inside diagnostic values: %s (%v)", out, err)
			}
		})
	}
}

func TestPhaseOneEncodedBearerURLDiagnostics(t *testing.T) {
	phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_API_BASE_URL", "https://example.invalid")
	for _, tc := range []struct {
		name, bearer, target, want string
	}{
		{"lowercase path", "abc/1234", "/prefixabc%2f1234suffix", "/prefix***REDACTED***suffix"},
		{"uppercase path", "abc/1234", "/prefixabc%2F1234suffix", "/prefix***REDACTED***suffix"},
		{"lowercase query", "abc/1234", "/check?note=prefixabc%2f1234suffix", "/check?note=prefix***REDACTED***suffix"},
		{"escaped path letters", "abc/1234", "/prefix%61bc%2f1234suffix%21", "/prefix***REDACTED***suffix%21"},
		{"escaped query letters", "abc/1234", "/check?note=prefix%61bc%2f1234suffix", "/check?note=prefix***REDACTED***suffix"},
		{"mixed escapes", "abc/?1234", "/prefixabc%2f%3F1234suffix", "/prefix***REDACTED***suffix"},
		{"literal token case", "abc/1234", "/prefixAbc%2f1234suffix", "/prefixAbc%2f1234suffix"},
		{"escaped token case", "abc/1234", "/prefix%41bc%2f1234suffix", "/prefix%41bc%2f1234suffix"},
		{"escaped literal percent", "abc%2f1234", "/prefixabc%252f1234suffix", "/prefix***REDACTED***suffix"},
		{"encoded literal percent", "abc%2f1234", "/prefixabc%252F1234suffix", "/prefixabc%252F1234suffix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_TOKEN", tc.bearer)
			out, err := phaseOneRun("--dry-run", "api", "GET", tc.target)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Data struct{ URL string }
			}
			if err := json.Unmarshal([]byte(out), &envelope); err != nil {
				t.Fatal(err)
			}
			if want := "https://example.invalid" + tc.want; envelope.Data.URL != want {
				t.Errorf("URL = %q, want %q", envelope.Data.URL, want)
			}
		})
	}
}

func TestPhaseOneEncodedBearerErrorDetail(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const target = "/prefix%61bc%2f1234suffix?note=prefix%61bc%2f1234suffix"
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", bearer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != target || r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("masking changed the outbound request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"REQUEST_FAILED","message":"invalid prefixabc%2f1234suffix","detail":{"credential":"prefixabc%2f1234suffix","attempt":9007199254740993}}`)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)

	stderr, err := phaseOneRun("api", "GET", target)
	exitErr := output.AsExitError(err)
	if exitErr == nil || exitErr.ExitCode() != 2 {
		t.Fatalf("expected validation exit code 2, got %v", err)
	}
	var envelope struct {
		Error struct {
			Code    string
			Message string
			Detail  struct {
				Code    string
				Message string
				Detail  struct {
					Credential string
					Attempt    int64
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
		t.Fatal(err)
	}
	got := envelope.Error
	const masked = "prefix***REDACTED***suffix"
	if got.Code != "HTTP_400" || !strings.Contains(got.Message, "invalid "+masked) ||
		got.Detail.Code != "REQUEST_FAILED" || got.Detail.Message != "invalid "+masked ||
		got.Detail.Detail.Credential != masked || got.Detail.Detail.Attempt != 9007199254740993 {
		t.Fatalf("unexpected structured error: %s", stderr)
	}
	if strings.Contains(stderr, "abc%2f1234") || strings.Contains(stderr, bearer) {
		t.Fatal("credential leaked in stderr")
	}
}

func TestPhaseOneEncodedBearerStructuredQueryError(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const params = `{"note":"prefix%61bc%2f1234suffix","prefix%61bc%2f1234suffix":"keep"}`
	const wireValue = "prefix%2561bc%252f1234suffix"
	const maskedValue = "prefix***REDACTED***suffix"
	const control = "prefix%2541bc%252f1234suffix"
	const wire = "/check?note=" + wireValue + "&" + wireValue + "=keep"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != wire || r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("masking changed the outbound request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":{"code":"bad_request","message":%q,"details":{"request_uri":%q,"query":{%q:%q},"control":%q,"attempt":9007199254740993}}}`,
			"invalid URI "+r.RequestURI, r.RequestURI, wireValue, wireValue, control)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	for _, tc := range []struct{ name, mode, tokenEnv, want string }{
		{"unified", "unified", "OCTO_TOKEN", maskedValue},
		{"legacy", "", "OCTO_BOT_TOKEN", wireValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			t.Setenv(tc.tokenEnv, bearer)
			stderr, err := phaseOneRun("api", "GET", "/check", "--params", params)
			exitErr := output.AsExitError(err)
			if exitErr == nil || exitErr.ExitCode() != 1 {
				t.Fatalf("expected API exit code 1, got %v", err)
			}
			var envelope struct {
				Error struct {
					Code, Type, Message string
					Detail              struct {
						Error struct {
							Code, Message string
							Details       struct {
								RequestURI string `json:"request_uri"`
								Query      map[string]string
								Control    string
								Attempt    int64
							}
						}
					}
				}
			}
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatal(err)
			}
			wantURI := strings.ReplaceAll(wire, wireValue, tc.want)
			got := envelope.Error
			detail := got.Detail.Error
			if got.Code != "bad_request" || got.Type != "api_error" || detail.Code != got.Code ||
				got.Message != "invalid URI "+wantURI || detail.Message != got.Message ||
				detail.Details.RequestURI != wantURI || len(detail.Details.Query) != 1 || detail.Details.Query[tc.want] != tc.want ||
				detail.Details.Control != control || detail.Details.Attempt != 9007199254740993 {
				t.Fatalf("unexpected structured error: %s", stderr)
			}
		})
	}
}

func TestPhaseOneEncodedBearerStructuredQueryDiagnostics(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const target = "/prefix%61bc%2f1234suffix?raw=prefix%61bc%2f1234suffix"
	const params = `{"note":"prefix%61bc%2f1234suffix","plain":"prefixabc/1234suffix","prefix%61bc%2f1234suffix":9007199254740993}`
	const wire = "/prefix%61bc%2f1234suffix?note=prefix%2561bc%252f1234suffix&plain=prefixabc%2F1234suffix&prefix%2561bc%252f1234suffix=9007199254740993&raw=prefixabc%2F1234suffix"
	const masked = "/prefix***REDACTED***suffix?note=prefix%2A%2A%2AREDACTED%2A%2A%2Asuffix&plain=prefix***REDACTED***suffix&prefix%2A%2A%2AREDACTED%2A%2A%2Asuffix=9007199254740993&raw=prefix***REDACTED***suffix"
	calls := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("request did not use the expected bearer")
		}
		calls <- r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	args := []string{"api", "GET", target, "--params", params}
	for _, tc := range []struct{ name, mode, want string }{
		{"unified", "unified", masked},
		{"legacy", "", wire},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			if tc.mode == "unified" {
				t.Setenv("OCTO_TOKEN", bearer)
			} else {
				t.Setenv("OCTO_BOT_TOKEN", bearer)
			}
			wantURL := server.URL + tc.want
			out, err := phaseOneRun(append([]string{"--dry-run"}, args...)...)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct{ Data struct{ URL string } }
			if err := json.Unmarshal([]byte(out), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Data.URL != wantURL {
				t.Errorf("dry-run URL = %q, want %q", envelope.Data.URL, wantURL)
			}
			if len(calls) != 0 {
				t.Fatal("dry-run sent an HTTP request")
			}
			out, err = phaseOneRun(append([]string{"--verbose"}, args...)...)
			if err != nil || !strings.Contains(out, "[octo] GET "+wantURL+"\n") {
				t.Errorf("unexpected verbose output: %s (%v)", out, err)
			}
			select {
			case uri := <-calls:
				if uri != wire {
					t.Errorf("sent URI = %q, want %q", uri, wire)
				}
			default:
				t.Fatal("no request received")
			}
		})
	}
}

func TestPhaseOneEncodedBearerRedirect(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const params = `{"note":"prefix%61bc%2f1234suffix","prefix%61bc%2f1234suffix":"keep"}`
	const wireValue = "prefix%2561bc%252f1234suffix"
	const rawQuery = "note=" + wireValue + "&" + wireValue + "=keep"
	const body = `{"operation":"example"}`
	for _, tc := range []struct {
		name, mode, tokenEnv, path, code, want string
		defaultPost                            bool
		wantCalls                              int
	}{
		{"unified", "unified", "OCTO_TOKEN", "/redirect/", "HTTP_307", "prefix***REDACTED***suffix", false, 1},
		{"unified malformed", "unified", "OCTO_TOKEN", "/redirect/%zz", "NETWORK_ERROR", "prefix***REDACTED***suffix", false, 1},
		{"unified malformed default POST", "unified", "OCTO_TOKEN", "/write/%zz", "NETWORK_ERROR", "prefix***REDACTED***suffix", true, 1},
		{"legacy", "", "OCTO_BOT_TOKEN", "/redirect/", "HTTP_307", wireValue, false, 1},
		{"legacy malformed", "", "OCTO_BOT_TOKEN", "/redirect/%zz", "NETWORK_ERROR", wireValue, false, 1},
		{"legacy malformed default POST", "", "OCTO_BOT_TOKEN", "/write/%zz", "NETWORK_ERROR", wireValue, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			t.Setenv(tc.tokenEnv, bearer)
			path, method := "/redirect", http.MethodGet
			args := []string{"--no-retry"}
			if tc.defaultPost {
				path, method = "/write", http.MethodPost
				args = nil
			}
			calls := make(chan struct{}, 16)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- struct{}{}
				if r.Method != method || r.RequestURI != path+"?"+rawQuery {
					t.Errorf("unexpected request: %s %s", r.Method, r.RequestURI)
				}
				if tc.defaultPost {
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != body {
						t.Errorf("unexpected POST body: %s (%v)", got, err)
					}
				}
				if r.Header.Get("Authorization") != "Bearer "+bearer {
					t.Error("request did not use the expected bearer")
				}
				w.Header().Set("Location", tc.path+"?"+r.URL.RawQuery)
				w.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer server.Close()
			t.Setenv("OCTO_API_BASE_URL", server.URL)
			args = append(args, "api", method, path, "--params", params)
			if tc.defaultPost {
				args = append(args, "--data", body)
			}
			stderr, err := phaseOneRun(args...)
			exitErr := output.AsExitError(err)
			if exitErr == nil || exitErr.ExitCode() != 1 {
				t.Fatalf("expected exit code 1, got %v", err)
			}
			var envelope struct {
				Error struct{ Code, Message string }
			}
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatal(err)
			}
			want := tc.path + "?" + strings.ReplaceAll(rawQuery, wireValue, tc.want)
			if envelope.Error.Code != tc.code || !strings.Contains(envelope.Error.Message, want) ||
				(tc.mode == "unified" && strings.Contains(envelope.Error.Message, wireValue)) {
				t.Errorf("unexpected structured error: %s", stderr)
			}
			if len(calls) != tc.wantCalls {
				t.Fatalf("got %d requests, want %d", len(calls), tc.wantCalls)
			}
		})
	}
}

func TestPhaseOneEncodedBearerNetworkError(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const params = `{"note":"prefix%61bc%2f1234suffix","prefix%61bc%2f1234suffix":"keep"}`
	const wire = "/check?note=prefix%2561bc%252f1234suffix&prefix%2561bc%252f1234suffix=keep"
	const masked = "/check?note=prefix%2A%2A%2AREDACTED%2A%2A%2Asuffix&prefix%2A%2A%2AREDACTED%2A%2A%2Asuffix=keep"
	calls := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.RequestURI
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("request did not use the expected bearer")
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack connection: %v", err)
			return
		}
		if err := conn.Close(); err != nil {
			t.Errorf("close connection: %v", err)
		}
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	for _, tc := range []struct{ name, mode, tokenEnv, want string }{
		{"unified", "unified", "OCTO_TOKEN", masked},
		{"legacy", "", "OCTO_BOT_TOKEN", wire},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			t.Setenv(tc.tokenEnv, bearer)
			stderr, err := phaseOneRun("--no-retry", "api", "GET", "/check", "--params", params)
			exitErr := output.AsExitError(err)
			if exitErr == nil || exitErr.ExitCode() != 1 {
				t.Fatalf("expected network exit code 1, got %v", err)
			}
			var envelope struct {
				Error struct{ Code, Type, Message, Hint string }
			}
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatal(err)
			}
			got := envelope.Error
			if got.Code != "NETWORK_ERROR" || got.Type != "network" || got.Hint != "transport error" ||
				!strings.HasPrefix(got.Message, fmt.Sprintf("Get %q: ", server.URL+tc.want)) {
				t.Fatalf("unexpected structured error: %s", stderr)
			}
			select {
			case uri := <-calls:
				if uri != wire {
					t.Errorf("sent URI = %q, want %q", uri, wire)
				}
			default:
				t.Fatal("no request received")
			}
		})
	}
}

func TestPhaseOneEncodedBearerRequestBodyDiagnostics(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc/1234"
	const data = `{"nested":[{"value":"prefixabc%2F1234suffix"}],"note":"prefix%61bc%2f1234suffix","prefix%61bc%2f1234suffix":9007199254740993}`
	const masked = `{"nested":[{"value":"prefix***REDACTED***suffix"}],"note":"prefix***REDACTED***suffix","prefix***REDACTED***suffix":9007199254740993}`
	calls := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("request did not use the expected bearer")
		}
		calls <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer server.Close()
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	args := []string{"api", "POST", "/check", "--data", data}

	for _, tc := range []struct{ name, mode, want string }{
		{"unified", "unified", masked},
		{"legacy", "", data},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			if tc.mode == "unified" {
				t.Setenv("OCTO_TOKEN", bearer)
			} else {
				t.Setenv("OCTO_BOT_TOKEN", bearer)
			}

			out, err := phaseOneRun(append([]string{"--dry-run"}, args...)...)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Data struct{ Body json.RawMessage }
			}
			if err := json.Unmarshal([]byte(out), &envelope); err != nil {
				t.Fatal(err)
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, envelope.Data.Body); err != nil {
				t.Fatal(err)
			}
			if compact.String() != tc.want {
				t.Errorf("dry-run body = %s, want %s", &compact, tc.want)
			}
			if len(calls) != 0 {
				t.Fatal("dry-run sent an HTTP request")
			}

			out, err = phaseOneRun(append([]string{"--verbose"}, args...)...)
			if err != nil || !strings.Contains(out, "request body: "+tc.want+"\n") {
				t.Errorf("unexpected verbose output: %s (%v)", out, err)
			}
			select {
			case body := <-calls:
				if body != data {
					t.Errorf("sent body = %s, want %s", body, data)
				}
			default:
				t.Fatal("no request received")
			}
		})
	}
}

func TestPhaseOneOutputPreflightMasksUnifiedBearer(t *testing.T) {
	phaseOneEnv(t)
	const bearer = "abc1234"
	const format = "prefix" + bearer + "suffix"
	t.Setenv("OCTO_TOKEN", bearer)
	t.Setenv("OCTO_API_BASE_URL", "https://example.invalid")
	for _, tc := range []struct{ name, mode, want string }{
		{"unified", "unified", "prefix***REDACTED***suffix"},
		{"legacy", "", format},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			_, err := phaseOneRun("--dry-run", "api", "GET", "/check", "--format", format)
			exit := output.AsExitError(cmdutil.WrapCLIError(err))
			if exit == nil || exit.Code != "CLI_ERROR" || !strings.Contains(exit.Message, tc.want) {
				t.Fatalf("unexpected output preflight error: %v", err)
			}
			if tc.mode == "unified" && strings.Contains(exit.Message, bearer) {
				t.Fatal("output preflight error disclosed the unified bearer")
			}
		})
	}
}

func TestPhaseOneOfflineOutputPreflight(t *testing.T) {
	dir := phaseOneEnv(t)
	const bearer = "abc/1234"
	const invalidFormat = "prefix" + bearer + "suffix"
	t.Setenv("OCTO_TOKEN", bearer)
	for _, mode := range []string{"", "unified"} {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", mode)
			_, err := phaseOneRun("--format", invalidFormat, "auth", "list")
			exit := output.AsExitError(cmdutil.WrapCLIError(err))
			if exit == nil || exit.Code != "CLI_ERROR" || exit.ExitCode() != 2 ||
				!strings.Contains(exit.Message, "expected json|table|csv|ndjson") {
				t.Fatalf("unexpected output preflight error: %v", err)
			}
			if strings.Contains(exit.Message, invalidFormat) != (mode == "") {
				t.Fatalf("unexpected format disclosure: %v", err)
			}
		})
	}
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN_FILE", filepath.Join(dir, "missing"))
	t.Setenv("OCTO_FORMAT", invalidFormat)
	out, err := phaseOneRun("--format", "json", "auth", "list")
	var envelope struct {
		OK   bool
		Data struct{ Profiles []json.RawMessage }
	}
	if err != nil || json.Unmarshal([]byte(out), &envelope) != nil || !envelope.OK || envelope.Data.Profiles == nil {
		t.Fatalf("explicit JSON format must work offline: %s (%v)", out, err)
	}
}

func TestPhaseOneMissingBodyFileDiagnostics(t *testing.T) {
	dir := phaseOneEnv(t)
	const bearer = "abc1234"
	const filename = "prefix" + bearer + "suffix"
	t.Setenv("OCTO_TOKEN", bearer)
	t.Setenv("OCTO_API_BASE_URL", "https://example.invalid")
	for _, tc := range []struct {
		name, mode, want string
	}{
		{"unified", "unified", "prefix***REDACTED***suffix"},
		{"legacy", "", filename},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			out, err := phaseOneRun("--dry-run", "api", "POST", "/check", "--data", "@"+filepath.Join(dir, filename))
			exit := output.AsExitError(err)
			if exit == nil || exit.Code != "VALIDATION_ERROR" {
				t.Fatalf("want VALIDATION_ERROR, got %v (%s)", err, out)
			}
			var envelope struct {
				Error struct{ Code, Message string }
			}
			if err := json.Unmarshal([]byte(out), &envelope); err != nil {
				t.Fatalf("decode error envelope: %v", err)
			}
			if envelope.Error.Code != exit.Code || envelope.Error.Message != exit.Message || !strings.Contains(exit.Message, tc.want) {
				t.Fatalf("unexpected file diagnostic: %s (%v)", out, err)
			}
			if tc.mode == "unified" && strings.Contains(out+err.Error(), bearer) {
				t.Fatal("file diagnostic disclosed the unified bearer")
			}
		})
	}
}

func TestPhaseOneUnifiedCredentialOnlyOnExplicitAPI(t *testing.T) {
	phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "opaque-unified-token")
	t.Setenv("OCTO_API_BASE_URL", "https://standalone.example")
	for _, args := range [][]string{
		{"--credential-file", filepath.Join(t.TempDir(), "missing"), "group", "list"},
		{"group", "list"},
		{"group", "create", "--data", `{"members":["fixture-member"]}`},
		{"mail", "me"},
		{"loop", "workspace", "list"},
		{"api", "GET", "/fleet/api/v1/workspaces", "--service", "loop"},
	} {
		out, err := phaseOneRun(append([]string{"--dry-run"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "unified credentials currently require api with the default service") {
			t.Errorf("%v: %v (%s), want unified API boundary error", args, err, out)
		}
	}
}

func TestPhaseOneExternalTokenTarget(t *testing.T) {
	dir := phaseOneEnv(t)
	tokenPath := filepath.Join(dir, "external")
	phaseOneWrite(t, tokenPath, "external-bearer")
	t.Setenv("OCTO_TOKEN_FILE", tokenPath)
	configOrigin, envOrigin, calls := phaseOneTargets(t, "profile", "env")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
		"version":1,"current_profile":"a","profiles":{
			"a":{"api_base_url":%q,"space_id":"space-a"},"null-profile":null,"empty-profile":{}
		}
	}`, configOrigin))
	t.Setenv("OCTO_API_BASE_URL", envOrigin)

	args := []string{"api", "GET", "/phase-one"}
	phaseOneCheckRequest(t, calls, "env /phase-one Bearer external-bearer ", args...)

	if err := os.Unsetenv("OCTO_TOKEN_FILE"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "external-bearer")
	phaseOneCheckRequest(t, calls, "env /phase-one Bearer external-bearer ", args...)
	phaseOneCheckRequest(t, calls, "profile /phase-one Bearer external-bearer space-a", append([]string{"--profile", "a"}, args...)...)
	phaseOneCheckRequest(t, calls, "env /phase-one Bearer external-bearer ", append([]string{"--profile", "empty-profile"}, args...)...)
	if out, err := phaseOneRun(append([]string{"--profile", "null-profile"}, args...)...); err == nil ||
		!strings.Contains(err.Error(), "selected profile is null") {
		t.Errorf("null Profile: %v (%s), want invalid Profile error", err, out)
	}
	select {
	case <-calls:
		t.Fatal("explicit null Profile sent an HTTP request")
	default:
	}

	t.Setenv("OCTO_SPACE_ID", "runtime-space")
	phaseOneCheckRequest(t, calls, "env /phase-one Bearer external-bearer runtime-space", append(args, "--service=default")...)
}

func TestPhaseOneExternalTokenDoesNotReadProfileConfig(t *testing.T) {
	calls := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, contents, profileError string
		unreadable                   bool
	}{
		{"malformed", "{", "invalid config.json", false},
		{"dangling default", `{"version":1,"current_profile":"missing","profiles":{}}`, "selected profile does not exist", false},
		{"unreadable", `{"version":1,"profiles":{}}`, "cannot read config.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			path := filepath.Join(dir, "config.json")
			phaseOneWrite(t, path, tc.contents)
			if tc.unreadable {
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := os.ReadFile(path); !os.IsPermission(err) {
					t.Skipf("cannot exercise permission denial: %v", err)
				}
			}
			t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
			t.Setenv("OCTO_TOKEN", "external-bearer")
			t.Setenv("OCTO_API_BASE_URL", server.URL)
			args := []string{"api", "GET", "/phase-one"}
			if out, err := phaseOneRun(args...); err != nil {
				t.Fatalf("standalone: %v (%s)", err, out)
			}
			select {
			case got := <-calls:
				if got != "Bearer external-bearer" {
					t.Fatal("request did not use the external credential")
				}
			default:
				t.Fatal("standalone request did not reach the runtime origin")
			}
			if out, err := phaseOneRun(append([]string{"--profile", "a"}, args...)...); err == nil ||
				!strings.Contains(err.Error(), tc.profileError) {
				t.Errorf("explicit profile: %v (%s), want %q", err, out, tc.profileError)
			}
			select {
			case <-calls:
				t.Fatal("explicit profile failure sent an HTTP request")
			default:
			}
		})
	}
}

func TestPhaseOneLegacyOpaqueTokenAliases(t *testing.T) {
	for _, key := range []string{"OCTO_TOKEN", "OCTO_BOT_TOKEN"} {
		t.Run(key, func(t *testing.T) {
			phaseOneEnv(t)
			t.Setenv(key, "opaque-legacy-bearer")
			t.Setenv("OCTO_API_BASE_URL", "https://legacy.example")
			for _, tc := range []struct {
				args []string
				path string
			}{
				{[]string{"group", "list"}, "/v1/bot/groups"},
				{[]string{"api", "POST", "/v1/bot/messages/_search"}, "/v1/bot/messages/_search_global_messages"},
			} {
				out, err := phaseOneRun(append([]string{"--dry-run"}, tc.args...)...)
				if err != nil || !strings.Contains(out, "https://legacy.example"+tc.path) {
					t.Errorf("%v: %v (%s), want legacy path %s", tc.args, err, out, tc.path)
				}
			}
		})
	}
}

func phaseOneStores(t *testing.T, profile, botID string) (legacy *authstore.Store, unifiedDir string) {
	t.Helper()
	home := phaseOneEnv(t)
	t.Setenv("OCTO_CONFIG_DIR", "")
	homeVar := "HOME"
	if runtime.GOOS == "windows" {
		homeVar = "USERPROFILE"
	}
	t.Setenv(homeVar, home)
	store, err := authstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveProfile(profile, &authstore.ProfileMeta{
		RobotID: botID, APIBaseURL: "https://legacy.example",
	}, "bf_legacy-fixture-bearer"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".octo", "cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return store, dir
}

func TestPhaseOneProfileStoresCoexist(t *testing.T) {
	_, dir := phaseOneStores(t, "legacy", "bot-id")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{
		"version":1,"current_profile":"new","profiles":{"new":{"token_source":{"type":"token_file","path":"missing"}},"null-profile":null}
	}`)

	checkList := func(want string) {
		t.Helper()
		out, err := phaseOneRun("auth", "list")
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Data struct {
				Profiles []struct {
					Profile string `json:"profile"`
				} `json:"profiles"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &envelope); err != nil {
			t.Fatal(err)
		}
		if profiles := envelope.Data.Profiles; len(profiles) != 1 || profiles[0].Profile != want {
			t.Fatalf("auth list: got %s, want only profile %q", out, want)
		}
	}
	checkList("legacy")
	out, err := phaseOneRun("--bot-id", "bot-id", "--dry-run", "group", "list")
	if err != nil || !strings.Contains(out, "https://legacy.example/v1/bot/groups") {
		t.Fatalf("legacy bot selection: %v (%s)", err, out)
	}
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	checkList("new")
}

func TestPhaseOneAuthDoesNotFallBackToLegacyCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, env, value string
		modeError        string
		flags            []string
	}{
		{name: "mode", env: "OCTO_CREDENTIAL_MODE", value: "unified"},
		{name: "profile", env: "OCTO_PROFILE", value: "shared"},
		{name: "token file env", env: "OCTO_TOKEN_FILE", value: "unused"},
		{name: "credential file flag", flags: []string{"--credential-file", "unused"}},
		{name: "unknown mode", env: "OCTO_CREDENTIAL_MODE", value: "unifed", modeError: `unsupported OCTO_CREDENTIAL_MODE "unifed"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, newDir := phaseOneStores(t, "shared", "legacy-bot")
			phaseOneWrite(t, filepath.Join(newDir, "config.json"), `{
				"version":1,"current_profile":"shared","profiles":{"shared":{"api_base_url":"https://unified.example"}}
			}`)
			snapshot := make(map[string][]byte)
			for _, path := range []string{
				filepath.Join(store.Dir(), "config.json"),
				filepath.Join(store.Dir(), "credentials.enc"),
				filepath.Join(newDir, "config.json"),
			} {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				snapshot[path] = raw
			}
			if tc.env != "" {
				t.Setenv(tc.env, tc.value)
			}
			t.Setenv("OCTO_TOKEN", "opaque-runtime-bearer")
			commands := [][]string{
				{"status"},
				{"login", "--with-token"},
				{"update", "--api-base-url", "https://other.example"},
				{"logout"},
			}
			if tc.modeError != "" {
				commands = append([][]string{{"list"}}, commands...)
			}
			for _, command := range commands {
				name := command[0]
				f := cmdutil.NewDefaultFactory()
				stdin := strings.NewReader("unused-stdin-bearer")
				initial := stdin.Len()
				var out bytes.Buffer
				f.IOStreams.In, f.IOStreams.Out, f.IOStreams.ErrOut = stdin, &out, &out
				root := NewRootCmd(f)
				args := append([]string{}, tc.flags...)
				if name != "status" && name != "list" {
					args = append(args, "--profile", "shared")
				}
				root.SetArgs(append(append(args, "auth"), command...))
				want := tc.modeError
				if want == "" {
					want = "auth " + name + " is unavailable for unified credentials"
				}
				if err := root.Execute(); err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("execute %s: %v (%s), want %q", name, err, &out, want)
				}
				if stdin.Len() != initial {
					t.Errorf("auth %s read stdin", name)
				}
				for path, before := range snapshot {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(after, before) {
						t.Errorf("auth %s modified %s: %v", name, path, err)
					}
				}
			}
			if tc.modeError != "" {
				phaseOneWrite(t, filepath.Join(store.Dir(), "config.json"), "{")
				if out, err := phaseOneRun("auth", "list"); err == nil || !strings.Contains(err.Error(), tc.modeError) {
					t.Errorf("mode validation must precede reading the legacy config: %v (%s)", err, out)
				}
			}
		})
	}
}

func TestPhaseOneStoredTokenRequiresProfileOrigin(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	phaseOneWrite(t, filepath.Join(dir, "token"), "stored-profile-bearer")
	calls := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCTO_API_BASE_URL", server.URL)
	phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
		"version":1,"current_profile":"missing-origin","profiles":{
			"missing-origin":{"token_source":{"type":"token_file","path":"token"}},
			"missing-host":{"api_base_url":%q,"token_source":{"type":"token_file","path":"token"}},
			"complete":{"api_base_url":%q,"token_source":{"type":"token_file","path":"token"}}
		}
	}`, "http://:"+origin.Port(), server.URL))

	args := []string{"api", "GET", "/phase-one"}
	if out, err := phaseOneRun(args...); err == nil || !strings.Contains(err.Error(), "profile token_source requires api_base_url") {
		t.Errorf("missing Profile origin: %v (%s), want missing origin error", err, out)
	}
	select {
	case got := <-calls:
		t.Fatalf("missing Profile origin sent a request with %q", got)
	default:
	}
	if out, err := phaseOneRun(append([]string{"--profile", "missing-host"}, args...)...); err == nil ||
		!strings.Contains(err.Error(), "invalid API base URL from profile") {
		t.Errorf("hostless Profile origin: %v (%s), want invalid origin error", err, out)
	}
	select {
	case <-calls:
		t.Fatal("hostless Profile origin sent an HTTP request")
	default:
	}
	check := func(profile, want string) {
		t.Helper()
		if out, err := phaseOneRun(append([]string{"--profile", profile}, args...)...); err != nil {
			t.Fatalf("execute profile %q: %v (%s)", profile, err, out)
		}
		select {
		case got := <-calls:
			if got != "Bearer "+want {
				t.Errorf("Authorization = %q, want selected bearer", got)
			}
		default:
			t.Fatal("no request received")
		}
	}
	check("complete", "stored-profile-bearer")
	t.Setenv("OCTO_TOKEN", "external-bearer")
	check("missing-origin", "external-bearer")
}

func TestPhaseOneRejectsLegacyTokensInUnifiedAPI(t *testing.T) {
	calls := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	args := []string{"api", "GET", "/phase-one"}
	for _, prefix := range []string{"bf_", "app_", "uk_", "octo_loop_", "omb_"} {
		for _, source := range []string{"env", "env-file", "flag", "profile"} {
			t.Run(prefix+source, func(t *testing.T) {
				dir := phaseOneEnv(t)
				t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
				t.Setenv("OCTO_API_BASE_URL", server.URL)
				token := prefix + "legacy-fixture-bearer"
				file := filepath.Join(dir, "token")
				var flags []string
				switch source {
				case "env":
					t.Setenv("OCTO_TOKEN", token)
				case "env-file":
					phaseOneWrite(t, file, token+"\n")
					t.Setenv("OCTO_TOKEN_FILE", file)
				case "flag":
					phaseOneWrite(t, file, token+"\n")
					flags = []string{"--credential-file", file}
				case "profile":
					phaseOneWrite(t, file, token+"\n")
					phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
						"version":1,"current_profile":"a","profiles":{
							"a":{"api_base_url":%q,"token_source":{"type":"token_file","path":"token"}}
						}
					}`, server.URL))
				}
				out, err := phaseOneRun(append(flags, args...)...)
				if err == nil || !strings.Contains(err.Error(), "cannot be used with unified credentials") {
					t.Errorf("execute: %v (%s), want local legacy Token rejection", err, out)
				} else if strings.Contains(out+err.Error(), token) {
					t.Error("diagnostic disclosed the credential")
				}
				select {
				case <-calls:
					t.Error("a legacy Token reached the HTTP fixture")
				default:
				}
			})
		}
	}
	for _, tc := range []struct{ mode, token string }{
		{"unified", "opaque-unified-fixture"},
		{"", "bf_legacy-fixture-bearer"},
	} {
		t.Run("accepted "+tc.token, func(t *testing.T) {
			phaseOneEnv(t)
			t.Setenv("OCTO_CREDENTIAL_MODE", tc.mode)
			t.Setenv("OCTO_API_BASE_URL", server.URL)
			t.Setenv("OCTO_TOKEN", tc.token)
			if out, err := phaseOneRun(args...); err != nil {
				t.Fatalf("execute: %v (%s)", err, out)
			}
			select {
			case got := <-calls:
				if got != "Bearer "+tc.token {
					t.Error("request did not use the selected credential")
				}
			default:
				t.Fatal("no request received")
			}
		})
	}
}

func TestPhaseOneConfigShowRejectsUnifiedMode(t *testing.T) {
	phaseOneEnv(t)
	t.Setenv("OCTO_API_BASE_URL", "https://legacy.example")
	t.Setenv("OCTO_TOKEN", "bf_legacy-fixture-bearer")
	t.Setenv("OCTO_PROFILE", "missing")
	if out, err := phaseOneRun("api", "GET", "/phase-one"); err == nil || !strings.Contains(err.Error(), "selected profile does not exist") {
		t.Fatalf("unified API: %v (%s), want missing Profile error", err, out)
	}
	if out, err := phaseOneRun("config", "show"); err == nil || !strings.Contains(err.Error(), "config show is unavailable for unified credentials") ||
		strings.Contains(out, `"ok": true`) {
		t.Errorf("unified config show: %v (%s), want explicit rejection", err, out)
	}
	if err := os.Unsetenv("OCTO_PROFILE"); err != nil {
		t.Fatal(err)
	}
	if out, err := phaseOneRun("config", "show"); err != nil || !strings.Contains(out, `"api_base_url": "https://legacy.example"`) ||
		strings.Contains(out, "bf_legacy-fixture-bearer") {
		t.Fatalf("legacy config show: %v (%s), want masked legacy diagnostic", err, out)
	}
}
