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

func TestPhaseOneBusinessProfileRequest(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	tokenA := filepath.Join(dir, "token-a")
	tokenB := filepath.Join(dir, "token-b")
	phaseOneWrite(t, tokenA, "unified-profile-a-secret\n")
	phaseOneWrite(t, tokenB, "unified-profile-b-secret\n")
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
	originA, originB := server("a"), server("b")
	t.Setenv("OCTO_API_BASE_URL", "http://127.0.0.1:1")
	t.Setenv("OCTO_BOT_ID", "old-bot")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
		"version":1,"current_profile":"a","profiles":{
			"a":{"api_base_url":%q,"space_id":"space-a","token_source":{"type":"token_file","path":%q}},
			"b":{"api_base_url":%q,"space_id":"space-b","token_source":{"type":"token_file","path":%q}}
		}}`, originA, tokenA, originB, tokenB))

	check := func(origin, path, token, space string, args ...string) {
		t.Helper()
		out, err := phaseOneRun(args...)
		if err != nil {
			t.Fatalf("execute %v: %v (%s)", args, err, out)
		}
		select {
		case got := <-calls:
			if want := fmt.Sprintf("%s %s Bearer %s %s", origin, path, token, space); got != want {
				t.Errorf("request = %q, want %q", got, want)
			}
		default:
			t.Fatal("no request received")
		}
		if strings.Contains(out, token) {
			t.Fatalf("credential leaked in output: %s", out)
		}
	}
	check("a", "/phase-one", "unified-profile-a-secret", "space-a", "api", "GET", "/phase-one")
	t.Setenv("OCTO_PROFILE", "b")
	check("b", "/phase-one", "unified-profile-b-secret", "space-b", "api", "GET", "/phase-one")
	t.Setenv("OCTO_TOKEN", "unified-env-secret")
	check("b", "/phase-one", "unified-env-secret", "space-b", "api", "GET", "/phase-one")
	override := filepath.Join(dir, "override")
	phaseOneWrite(t, override, "unified-flag-secret")
	check("a", "/phase-one", "unified-flag-secret", "space-a",
		"--profile", "a", "--credential-file", override, "api", "GET", "/phase-one")
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

func TestPhaseOneUnifiedCredentialOnlyOnExplicitAPI(t *testing.T) {
	phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "opaque-unified-token")
	t.Setenv("OCTO_API_BASE_URL", "https://standalone.example")
	for _, args := range [][]string{
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
	calls := make(chan string, 4)
	server := func(name string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls <- fmt.Sprintf("%s %s %s", name, r.Header.Get("Authorization"), r.Header.Get("X-Space-Id"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	configOrigin, envOrigin := server("profile"), server("env")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
		"version":1,"current_profile":"a","profiles":{
			"a":{"api_base_url":%q,"space_id":"space-a"},"null-profile":null,"empty-profile":{}
		}
	}`, configOrigin))
	t.Setenv("OCTO_API_BASE_URL", envOrigin)

	args := []string{"api", "GET", "/phase-one"}
	check := func(want string, args ...string) {
		t.Helper()
		if out, err := phaseOneRun(args...); err != nil {
			t.Fatalf("execute %v: %v (%s)", args, err, out)
		}
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("request = %q, want %q", got, want)
			}
		default:
			t.Fatal("no request received")
		}
	}
	check("env Bearer external-bearer ", args...)

	if err := os.Unsetenv("OCTO_TOKEN_FILE"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_TOKEN", "external-bearer")
	check("env Bearer external-bearer ", args...)
	check("profile Bearer external-bearer space-a", append([]string{"--profile", "a"}, args...)...)
	check("env Bearer external-bearer ", append([]string{"--profile", "empty-profile"}, args...)...)
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
	check("env Bearer external-bearer runtime-space", append(args, "--service=default")...)
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

func TestPhaseOneProfileStoresCoexist(t *testing.T) {
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
	if err := store.SaveProfile("legacy", &authstore.ProfileMeta{
		RobotID: "bot-id", APIBaseURL: "https://legacy.example",
	}, "bf_legacy-bearer"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".octo", "cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
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
			if err := store.SaveProfile("shared", &authstore.ProfileMeta{
				RobotID: "legacy-bot", APIBaseURL: "https://legacy.example",
			}, "bf_legacy-fixture-bearer"); err != nil {
				t.Fatal(err)
			}
			newDir := filepath.Join(home, ".octo", "cli")
			if err := os.MkdirAll(newDir, 0o700); err != nil {
				t.Fatal(err)
			}
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
