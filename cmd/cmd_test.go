package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

// TestMain isolates the whole package from the developer's own OCTO_
// environment. Tests here build their fixtures with t.Setenv or an injected
// Config, and any ambient OCTO_ variable can outrank or redirect that fixture:
// OCTO_BOT_ID selects a stored credential profile, OCTO_TOKEN outranks
// OCTO_BOT_TOKEN, OCTO_FORMAT reshapes the output the assertions read.
//
// The sweep is by prefix rather than by name on purpose. Naming variables is
// what kept breaking: the clear list has been out of date three times
// (OCTO_TOKEN, then OCTO_FORMAT, then OCTO_BOT_ID), each time because a new
// variable was added without updating the tests. OCTO_MARKETPLACE_API_PREFIX
// (cmd/service/run.go) is read straight from the environment with no config
// constant behind it, so it is exactly the kind a by-name list misses.
//
// OCTO_CONFIG_DIR is re-set *after* the sweep: it must point at an empty temp
// dir rather than be absent, or authstore falls back to the real user config
// dir and a developer's stored profiles leak back in. Tests that need their own
// store still override it with t.Setenv.
//
// The proxy family is swept for the same reason and is the second family that was
// leaking in. An ambient https_proxy changes which machine the transfer transport
// connects to, which is the exact property the transfer guard tests assert — so
// those tests meant different things in different developers' shells, and one of
// them passed for the wrong reason under a loopback-addressed proxy. Tests that want
// a proxy now opt in with t.Setenv.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "octo-cmd-test")
	if err != nil {
		panic(err)
	}
	sweepOctoEnv()
	sweepProxyEnv()
	os.Setenv("OCTO_CONFIG_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// sweepOctoEnv unsets every OCTO_-prefixed variable in the process environment.
// os.Environ returns a snapshot, so unsetting while ranging over it is safe.
func sweepOctoEnv() {
	for _, kv := range os.Environ() {
		if name, _, found := strings.Cut(kv, "="); found && strings.HasPrefix(name, "OCTO_") {
			os.Unsetenv(name)
		}
	}
}

// sweepProxyEnv unsets every variable net/http consults to pick a proxy, in both
// the upper- and lower-case spellings ProxyFromEnvironment accepts.
func sweepProxyEnv() {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(name)
		os.Unsetenv(strings.ToLower(name))
	}
}

// newTestFactoryWithReg injects synthetic service definitions.
func newTestFactoryWithReg() *cmdutil.TestFactory {
	f := cmdutil.NewTestFactory()
	reg := testfixture.Registry()
	f.RegistryFunc = func() *registry.Registry { return reg }
	return f
}

// execRoot runs the root command with args, returning (stdout, stderr, error).
// args exclude the program name.
func execRoot(t *testing.T, f *cmdutil.TestFactory, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRootCmd(f.Factory)
	root.SetArgs(args)
	// Cobra writes its own framework errors to os.Stderr unless redirected;
	// the RunE emits envelopes to Factory.ErrOut so we don't care about cobra's.
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err = root.ExecuteContext(context.Background())
	return f.Out.String(), f.ErrOut.String(), err
}

func TestCmd_Version(t *testing.T) {
	f := newTestFactoryWithReg()
	// Unset token and ensure version still works (skipValidation path).
	f.SetConfig(&config.Config{Format: "json"})

	out, _, err := execRoot(t, f, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	var env map[string]any
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	if env["ok"] != true {
		t.Errorf("ok = %v", env["ok"])
	}
	data, _ := env["data"].(map[string]any)
	if _, ok := data["version"]; !ok {
		t.Errorf("version field missing: %v", data)
	}
}

func TestCmd_SchemaList(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{Format: "json"})

	out, _, err := execRoot(t, f, "schema", "--list")
	if err != nil {
		t.Fatalf("schema --list: %v", err)
	}
	var env map[string]any
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	data, _ := env["data"].(map[string]any)
	services, _ := data["services"].([]any)
	if len(services) == 0 {
		t.Errorf("expected at least one service, got %v", services)
	}
}

func TestCmd_SchemaListByDomain(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{Format: "json"})

	out, _, err := execRoot(t, f, "schema", "--list", "example")
	if err != nil {
		t.Fatalf("schema --list example: %v", err)
	}
	var env map[string]any
	_ = json.Unmarshal([]byte(out), &env)
	data, _ := env["data"].(map[string]any)
	if data["service"] != "example" {
		t.Errorf("service = %v", data["service"])
	}
}

func TestCmd_SchemaGetOperation(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{Format: "json"})

	out, _, err := execRoot(t, f, "schema", "example.record.list")
	if err != nil {
		t.Fatalf("schema example.record.list: %v", err)
	}
	var env map[string]any
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	if env["ok"] != true {
		t.Errorf("ok = %v", env["ok"])
	}
	data, _ := env["data"].(map[string]any)
	if data["id"] != "example.record.list" && data["operation_id"] != "example.record.list" {
		// Detail struct field name may vary; just ensure non-empty.
		if len(data) == 0 {
			t.Errorf("schema detail is empty: %v", env)
		}
	}
}

func TestCmd_SchemaUnknownOperation(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{Format: "json"})

	_, errOut, err := execRoot(t, f, "schema", "no.such.op")
	if err == nil {
		t.Fatal("expected error for unknown operation")
	}
	if !strings.Contains(errOut, "validation") {
		t.Errorf("error envelope missing validation type: %s", errOut)
	}
}

func TestCmd_ConfigShow(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{
		APIBaseURL:       "http://gateway.local",
		APIBaseURLSource: "profile",
		BotToken:         "app_abcdefgh12345",
		Format:           "json",
	})

	out, _, err := execRoot(t, f, "config", "show")
	if err != nil {
		t.Fatalf("config show: %v", err)
	}
	var env map[string]any
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	data, _ := env["data"].(map[string]any)
	if data["api_base_url"] != "http://gateway.local" {
		t.Errorf("api_base_url = %v", data["api_base_url"])
	}
	if data["api_base_url_source"] != "profile" {
		t.Errorf("api_base_url_source = %v", data["api_base_url_source"])
	}
	// Masked token: "app_abcd***".
	tok, _ := data["bot_token"].(string)
	if !strings.HasSuffix(tok, "***") {
		t.Errorf("bot_token not masked: %q", tok)
	}
	if strings.Contains(tok, "12345") {
		t.Errorf("bot_token leaks raw suffix: %q", tok)
	}
	if data["bot_kind"] != "app_bot" {
		t.Errorf("bot_kind = %v", data["bot_kind"])
	}
	if data["dmworkim_url"] != nil {
		t.Errorf("empty URL should be null, got %v", data["dmworkim_url"])
	}
}

func TestCmd_API_GET(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	f := newTestFactoryWithReg()
	cfg := &config.Config{APIBaseURL: srv.URL, BotToken: "app_test", Format: "json"}
	f.SetConfig(cfg)
	cred := &credential.BotCredential{Token: "app_test"}
	f.SetCredential(cred)
	cli := client.New(cfg, cred, client.Options{})
	f.SetClient(cli)

	out, _, err := execRoot(t, f, "api", "GET", "/test", "--params", `{"a":"1"}`)
	if err != nil {
		t.Fatalf("api GET: %v\n%s", err, f.ErrOut.String())
	}
	if gotMethod != "GET" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotPath != "/test" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "a=1") {
		t.Errorf("query = %q", gotQuery)
	}
	if !strings.Contains(out, "world") {
		t.Errorf("response missing body: %s", out)
	}
}

func TestCmd_API_POSTBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = buf[:n]
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	f := newTestFactoryWithReg()
	cfg := &config.Config{APIBaseURL: srv.URL, BotToken: "app_test", Format: "json"}
	f.SetConfig(cfg)
	f.SetCredential(&credential.BotCredential{Token: "app_test"})
	f.SetClient(client.New(cfg, &credential.BotCredential{Token: "app_test"}, client.Options{}))

	_, _, err := execRoot(t, f, "api", "POST", "/t", "--data", `{"key":"val"}`)
	if err != nil {
		t.Fatalf("api POST: %v\n%s", err, f.ErrOut.String())
	}
	if !strings.Contains(string(gotBody), `"key":"val"`) {
		t.Errorf("body sent = %q", gotBody)
	}
}

func TestCmd_API_PathMustStartWithSlash(t *testing.T) {
	f := newTestFactoryWithReg()
	_, errOut, err := execRoot(t, f, "api", "GET", "no-slash")
	if err == nil {
		t.Fatal("expected error for path without leading slash")
	}
	if !strings.Contains(errOut, "path must start with '/'") {
		t.Errorf("missing validation message: %s", errOut)
	}
}

func TestCmd_API_InvalidParamsJSON(t *testing.T) {
	f := newTestFactoryWithReg()
	_, errOut, err := execRoot(t, f, "api", "GET", "/t", "--params", `not json`)
	if err == nil {
		t.Fatal("expected error for invalid params")
	}
	if !strings.Contains(errOut, "--params") {
		t.Errorf("error should mention --params: %s", errOut)
	}
}

func TestCmd_API_InvalidDataJSON(t *testing.T) {
	f := newTestFactoryWithReg()
	_, errOut, err := execRoot(t, f, "api", "POST", "/t", "--data", `{bad`)
	if err == nil {
		t.Fatal("expected error for invalid data JSON")
	}
	if !strings.Contains(errOut, "--data") {
		t.Errorf("error should mention --data: %s", errOut)
	}
}

func TestCmd_DryRunNoServerCall(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
	}))
	defer srv.Close()

	f := newTestFactoryWithReg()
	cfg := &config.Config{APIBaseURL: srv.URL, BotToken: "app_test", Format: "json"}
	f.SetConfig(cfg)
	cred := &credential.BotCredential{Token: "app_test"}
	f.SetCredential(cred)
	// Dry-run goes through Client so we must build one with DryRun=true.
	cli := client.New(cfg, cred, client.Options{DryRun: true})
	f.SetClient(cli)

	out, _, err := execRoot(t, f, "api", "POST", "/x", "--data", `{"title":"hi"}`)
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, f.ErrOut.String())
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Errorf("dry-run should not hit the server")
	}
	if !strings.Contains(out, "dry_run") {
		t.Errorf("envelope missing dry_run marker: %s", out)
	}
}

func TestCmd_UnknownCommand(t *testing.T) {
	f := newTestFactoryWithReg()
	_, _, err := execRoot(t, f, "no-such-command")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	// Cobra returns the error to ExecuteContext; don't assert on envelope
	// because the root cmd leaves framework errors to main.go's wrapping.
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error = %v", err)
	}
}

// A config with no token should trip PersistentPreRunE on a service command,
// yielding an authentication error for that command.
func TestCmd_MissingTokenOnServiceCommand(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{APIBaseURL: "http://x", Format: "json"}) // no BotToken

	_, _, err := execRoot(t, f, "example", "record", "list")
	if err == nil {
		t.Fatal("expected PersistentPreRunE to reject missing token")
	}
	if !strings.Contains(err.Error(), config.EnvToken) || strings.Contains(err.Error(), config.EnvBotToken) {
		t.Errorf("error should reference only %s, got: %v", config.EnvToken, err)
	}
}

func TestParseParamsJSON_AllTypes(t *testing.T) {
	q, err := parseParamsJSON(`{"s":"x","n":42,"f":3.14,"b_true":true,"b_false":false,"arr":["a","b"],"null":null,"obj":{"k":"v"}}`)
	if err != nil {
		t.Fatalf("parseParamsJSON: %v", err)
	}
	if q.Get("s") != "x" {
		t.Errorf("string: %q", q.Get("s"))
	}
	if q.Get("n") != "42" {
		t.Errorf("int: %q", q.Get("n"))
	}
	if q.Get("f") != "3.14" {
		t.Errorf("float: %q", q.Get("f"))
	}
	if q.Get("b_true") != "true" || q.Get("b_false") != "false" {
		t.Errorf("bool: %q / %q", q.Get("b_true"), q.Get("b_false"))
	}
	if vs := q["arr"]; len(vs) != 2 || vs[0] != "a" || vs[1] != "b" {
		t.Errorf("array: %v", vs)
	}
	if _, ok := q["null"]; ok {
		t.Errorf("null should be skipped")
	}
	if !strings.Contains(q.Get("obj"), `"k":"v"`) {
		t.Errorf("nested obj: %q", q.Get("obj"))
	}
}

func TestParseParamsJSON_EmptyAndInvalid(t *testing.T) {
	if q, err := parseParamsJSON(""); err != nil || q != nil {
		t.Errorf("empty spec should return nil,nil; got %v, %v", q, err)
	}
	if _, err := parseParamsJSON(`["not", "object"]`); err == nil {
		t.Error("array spec should error")
	}
	if _, err := parseParamsJSON(`{bad json}`); err == nil {
		t.Error("malformed spec should error")
	}
}

func TestDefaultTokenSource(t *testing.T) {
	t.Setenv(config.EnvToken, "")
	t.Setenv(config.EnvBotToken, "")
	if got := defaultTokenSource(""); got != "" {
		t.Errorf("empty token → %q, want \"\"", got)
	}
	t.Setenv(config.EnvToken, "app_x")
	if got := defaultTokenSource("app_x"); got != "env:"+config.EnvToken {
		t.Errorf("source = %q, want env:%s", got, config.EnvToken)
	}
}

func TestNullableString(t *testing.T) {
	if got := nullableString(""); got != nil {
		t.Errorf("empty → %v, want nil", got)
	}
	if got := nullableString("x"); got != "x" {
		t.Errorf("non-empty → %v", got)
	}
}

func TestSkipValidation(t *testing.T) {
	root := NewRootCmd(newTestFactoryWithReg().Factory)

	// Find `version`, `schema`, `config show`, `completion bash` — all should skip.
	findCmd := func(names ...string) *cobra.Command {
		c := root
		for _, n := range names {
			var found *cobra.Command
			for _, sub := range c.Commands() {
				if sub.Name() == n {
					found = sub
					break
				}
			}
			if found == nil {
				t.Fatalf("couldn't find %v", names)
			}
			c = found
		}
		return c
	}

	if !skipValidation(findCmd("version")) {
		t.Error("version should skip validation")
	}
	if !skipValidation(findCmd("schema")) {
		t.Error("schema should skip validation")
	}
	if !skipValidation(findCmd("config")) {
		t.Error("config should skip validation")
	}
	// `config show` is a leaf — parent walk should still pick up `config`.
	if !skipValidation(findCmd("config", "show")) {
		t.Error("config show should skip via parent")
	}
	if !skipValidation(findCmd("auth")) {
		t.Error("top-level auth should skip validation")
	}
	// Pick a generated service leaf — should NOT skip.
	svcLeaf := findCmd("example", "record", "list")
	if skipValidation(svcLeaf) {
		t.Error("service leaf should NOT skip validation")
	}
}

func topLevelCmd(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func TestDisabledServiceWithheldFromCommandTree(t *testing.T) {
	root := NewRootCmd(newTestFactoryWithReg().Factory)
	if topLevelCmd(root, "disabled") != nil || topLevelCmd(root, "example") == nil {
		t.Fatal("expected the enabled fixture and no command for the disabled fixture")
	}
}

func TestDisabledServiceHiddenFromGlobalSchemaList(t *testing.T) {
	f := newTestFactoryWithReg()
	f.SetConfig(&config.Config{Format: "json"})

	out, _, err := execRoot(t, f, "schema", "--list")
	if err != nil {
		t.Fatalf("schema --list: %v", err)
	}
	var env map[string]any
	if jerr := json.Unmarshal([]byte(out), &env); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	data, _ := env["data"].(map[string]any)

	for _, s := range data["services"].([]any) {
		if s == "disabled" {
			t.Error("global schema --list must not list disabled service `disabled`")
		}
	}
	for _, op := range data["operations"].([]any) {
		m, _ := op.(map[string]any)
		if m["service"] == "disabled" {
			t.Errorf("global schema --list leaked a disabled op: %v", m["id"])
		}
	}
}

func TestDisabledServiceStillIntrospectable(t *testing.T) {
	for _, svc := range []string{"disabled"} {
		f := newTestFactoryWithReg()
		f.SetConfig(&config.Config{Format: "json"})

		// Explicit domain listing still resolves.
		out, _, err := execRoot(t, f, "schema", "--list", svc)
		if err != nil {
			t.Fatalf("schema --list %s: %v", svc, err)
		}
		var env map[string]any
		_ = json.Unmarshal([]byte(out), &env)
		data, _ := env["data"].(map[string]any)
		if ops, _ := data["operations"].([]any); len(ops) == 0 {
			t.Errorf("explicit `schema --list %s` must still return operations", svc)
		}

		// Explicit operation lookup still resolves.
		if _, _, err := execRoot(t, f, "schema", svc+".list"); err != nil {
			t.Errorf("explicit `schema %s.list` must still resolve: %v", svc, err)
		}
	}
}
