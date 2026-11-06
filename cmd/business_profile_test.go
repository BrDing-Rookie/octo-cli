package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	tokenPath := filepath.Join(dir, "token")
	phaseOneWrite(t, tokenPath, "unified-profile-secret\n")
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
		}}`, originA, tokenPath, originB, tokenPath))

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
	check("a", "/phase-one", "unified-profile-secret", "space-a", "api", "GET", "/phase-one")
	check("a", "/v1/bot/groups", "unified-profile-secret", "", "group", "list")
	t.Setenv("OCTO_PROFILE", "b")
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
		{"legacy token rejected by unified Profile", func(t *testing.T, dir string) []string {
			t.Setenv("OCTO_TOKEN", "bf_unified-env-secret")
			return nil
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
			file := filepath.Join(dir, "valid")
			phaseOneWrite(t, file, "unified-file-secret")
			phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
				"version":1,"current_profile":"a","profiles":{
					"a":{"space_id":"space-a","token_source":{"type":"token_file","path":%q}}
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
