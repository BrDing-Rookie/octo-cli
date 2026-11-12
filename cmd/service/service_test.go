package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

// TestMain isolates fixture requests from the local Octo environment.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "octo-service-test")
	if err != nil {
		panic(err)
	}
	sweepOctoEnv()
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

// rootWithService builds a minimal cobra root wired to a real httptest server,
// a TestFactory, and a synthetic registry. The returned TestFactory lets
// the caller read emitted envelopes.
func rootWithService(t *testing.T, handler http.HandlerFunc) (*cobra.Command, *cmdutil.TestFactory, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	tf := cmdutil.NewTestFactory()
	cfg := &config.Config{
		APIBaseURL: srv.URL,
		Token:      "app_test",
		Format:     "json",
	}
	tf.SetConfig(cfg)
	cred := &credential.Credential{Token: "app_test", Source: "test"}
	tf.SetCredential(cred)
	cli := client.New(cfg, cred, client.Options{ErrOut: io.Discard})
	tf.SetClient(cli)
	tf.RegistryFunc = testfixture.Registry

	root := &cobra.Command{Use: "octo-cli", SilenceUsage: true, SilenceErrors: true}
	RegisterServiceCommands(root, tf.Factory)

	return root, tf, srv
}

func TestRegisterServiceCommands_TreeShape(t *testing.T) {
	root := &cobra.Command{Use: "octo-cli"}
	tf := cmdutil.NewTestFactory()
	tf.RegistryFunc = testfixture.Registry
	RegisterServiceCommands(root, tf.Factory)

	example := findChild(root, "example")
	if example == nil {
		t.Fatal("enabled service missing from the tree")
	}
	records := findChild(example, "record")
	if records == nil || findChild(records, "list") == nil || findChild(records, "create") == nil {
		t.Fatal("record operations missing from the generated group")
	}
	if findChild(root, "disabled") != nil {
		t.Error("disabled service registered a command")
	}
}

func TestGeneratedList_QueryParamsFromFlags(t *testing.T) {
	var gotQuery string
	root, tf, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"pagination":{"has_more":false,"next_cursor":""}}`))
	})
	root.SetArgs([]string{"example", "record", "list", "--status", "open", "--owner", "me", "--limit", "5"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "status=open") || !strings.Contains(gotQuery, "owner=me") || !strings.Contains(gotQuery, "limit=5") {
		t.Errorf("query mismatch: %q", gotQuery)
	}
	if !bytes.Contains(tf.Out.Bytes(), []byte(`"ok": true`)) {
		t.Errorf("expected success envelope, got %s", tf.Out.String())
	}
}

func TestGeneratedCreate_BodyAutoPromotion(t *testing.T) {
	var gotBody map[string]any
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m1","title":"Deploy"}`))
	})
	root.SetArgs([]string{
		"example", "record", "create",
		"--title", "Deploy",
		"--description", "prod push",
		"--tags", "u1,u2",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotBody["title"] != "Deploy" {
		t.Errorf("title = %v, want Deploy", gotBody["title"])
	}
	if gotBody["description"] != "prod push" {
		t.Errorf("description = %v", gotBody["description"])
	}
	arr, ok := gotBody["tags"].([]any)
	if !ok || len(arr) != 2 {
		t.Errorf("tags = %v", gotBody["tags"])
	}
}

func TestGeneratedCreate_DataThenFlagOverride(t *testing.T) {
	var gotBody map[string]any
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	})
	root.SetArgs([]string{
		"example", "record", "create",
		"--data", `{"title":"from-data","description":"base"}`,
		"--title", "override",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotBody["title"] != "override" {
		t.Errorf("individual --title should override --data; got %v", gotBody["title"])
	}
	if gotBody["description"] != "base" {
		t.Errorf("--data-only field should persist; got %v", gotBody["description"])
	}
}

func TestGeneratedDelete_ExecutesDirectly(t *testing.T) {
	called := false
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(204)
	})
	root.SetArgs([]string{"example", "record", "delete", "m1"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !called {
		t.Error("expected server call")
	}
}

func TestDryRun_NoRequest(t *testing.T) {
	root, tf, server := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("dry-run sent an HTTP request")
	})
	cfg := &config.Config{APIBaseURL: server.URL, Token: "app_test", Format: "json"}
	cred := &credential.Credential{Token: "app_test", Source: "test"}
	tf.Globals.DryRun = true
	tf.SetClient(client.New(cfg, cred, client.Options{DryRun: true, ErrOut: io.Discard}))

	root.SetArgs([]string{"example", "record", "list", "--status", "open"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := tf.Out.String()
	if !strings.Contains(out, "\"dry_run\": true") || !strings.Contains(out, "status=open") {
		t.Errorf("dry-run output missing fields: %s", out)
	}
}

func TestPagination_PageAllMergesAllPages(t *testing.T) {
	pages := []string{
		`{"data":[{"id":"1"},{"id":"2"}],"pagination":{"has_more":true,"next_cursor":"c2"}}`,
		`{"data":[{"id":"3"}],"pagination":{"has_more":true,"next_cursor":"c3"}}`,
		`{"data":[{"id":"4"}],"pagination":{"has_more":false,"next_cursor":""}}`,
	}
	var cursors []string
	idx := 0
	root, tf, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pages[idx]))
		idx++
	})
	root.SetArgs([]string{"example", "record", "list", "--page-all"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got, want := len(cursors), 3; got != want {
		t.Fatalf("wanted 3 requests, got %d (cursors=%v)", got, cursors)
	}
	if cursors[0] != "" || cursors[1] != "c2" || cursors[2] != "c3" {
		t.Errorf("cursor progression = %v", cursors)
	}

	var env struct {
		OK   bool `json:"ok"`
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(tf.Out.Bytes(), &env); err != nil {
		t.Fatalf("parse envelope: %v -- out=%s", err, tf.Out.String())
	}
	if !env.OK || len(env.Data) != 4 {
		t.Errorf("expected 4 merged items, got %+v", env)
	}
}

// TestPagination_BodyCursorEndpoint pins S1: for POST-body search endpoints the
// spec declares `cursor` as a body field (not a query param), so paging must
// inject the next cursor into the request BODY, never the URL query. A body
// clone per page must not mutate the previous page's body.
func TestPagination_BodyCursorEndpoint(t *testing.T) {
	pages := []string{
		`{"data":[{"id":"1"}],"pagination":{"has_more":true,"next_cursor":"c2"}}`,
		`{"data":[{"id":"2"}],"pagination":{"has_more":true,"next_cursor":"c3"}}`,
		`{"data":[{"id":"3"}],"pagination":{"has_more":false,"next_cursor":""}}`,
	}
	var bodyCursors []string
	var queryCursors []string
	idx := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCursors = append(queryCursors, r.URL.Query().Get("cursor"))
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		c, _ := body["cursor"].(string)
		bodyCursors = append(bodyCursors, c)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pages[idx]))
		idx++
	}))
	t.Cleanup(srv.Close)

	tf := cmdutil.NewTestFactory()
	cfg := &config.Config{APIBaseURL: srv.URL, Token: "app_test", Format: "json"}
	tf.SetConfig(cfg)
	cred := &credential.Credential{Token: "app_test", Source: "test"}
	tf.SetCredential(cred)
	tf.SetClient(client.New(cfg, cred, client.Options{ErrOut: io.Discard}))
	tf.RegistryFunc = testfixture.Registry

	root := &cobra.Command{Use: "octo-cli", SilenceUsage: true, SilenceErrors: true}
	RegisterServiceCommands(root, tf.Factory)
	root.SetArgs([]string{"example", "record", "search", "--keyword", "hi", "--page-all"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(bodyCursors) != 3 {
		t.Fatalf("wanted 3 requests, got %d (body cursors=%v)", len(bodyCursors), bodyCursors)
	}
	// Cursor progresses in the BODY, first page has none.
	if bodyCursors[0] != "" || bodyCursors[1] != "c2" || bodyCursors[2] != "c3" {
		t.Errorf("body cursor progression = %v, want ['' c2 c3]", bodyCursors)
	}
	// Cursor never leaks into the query string.
	for i, qc := range queryCursors {
		if qc != "" {
			t.Errorf("page %d: cursor leaked into query (%q); it must stay in the body", i, qc)
		}
	}
}

func TestPagination_PageLimitStops(t *testing.T) {
	calls := 0
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		page := fmt.Sprintf(`{"data":[{"id":"x"}],"pagination":{"has_more":true,"next_cursor":"c%d"}}`, calls)
		_, _ = w.Write([]byte(page))
	})
	root.SetArgs([]string{"example", "record", "list", "--page-all", "--page-limit", "5"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls != 5 {
		t.Errorf("expected 5 calls bounded by --page-limit, got %d", calls)
	}
}

func TestPagination_LegacyStableCursorStillUsesPageLimit(t *testing.T) {
	calls := 0
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":[{"id":"x"}],"pagination":{"has_more":true,"next_cursor":"stable"}}`))
	})
	root.SetArgs([]string{"example", "record", "list", "--page-all", "--page-limit", "5"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls != 5 {
		t.Errorf("stable cursor must remain valid for legacy operations: got %d calls, want 5", calls)
	}
}

func TestParsePage_CustomFieldPaths(t *testing.T) {
	items, cursor, hasMore, err := parsePage([]byte(`{
		"result":{"hits":[{"z":1,"a":"<b>hi</b>"}]},
		"paging":{"after":"c2","more":true}
	}`), &registry.PaginationInfo{
		ItemsField:   "result.hits",
		CursorField:  "paging.after",
		HasMoreField: "paging.more",
	})
	if err != nil {
		t.Fatalf("parsePage: %v", err)
	}
	if len(items) != 1 || string(items[0]) != `{"z":1,"a":"<b>hi</b>"}` || cursor != "c2" || !hasMore {
		t.Errorf("items=%s cursor=%q hasMore=%v", items, cursor, hasMore)
	}
}

func TestParsePage_InferHasMoreRequiresOptIn(t *testing.T) {
	body := []byte(`{"items":[],"nextCursor":"c2"}`)
	base := registry.PaginationInfo{ItemsField: "items", CursorField: "nextCursor"}
	_, _, hasMore, err := parsePage(body, &base)
	if err != nil {
		t.Fatalf("parsePage without inference: %v", err)
	}
	if hasMore {
		t.Fatal("cursor alone must not imply has-more without explicit opt-in")
	}
	base.InferHasMore = true
	_, _, hasMore, err = parsePage(body, &base)
	if err != nil {
		t.Fatalf("parsePage with inference: %v", err)
	}
	if !hasMore {
		t.Fatal("non-empty cursor must imply has-more with explicit opt-in")
	}
}

func TestParsePage_LegacyNullItemsAreEmpty(t *testing.T) {
	items, cursor, hasMore, err := parsePage([]byte(`{"data":null,"pagination":{"has_more":false,"next_cursor":null}}`), nil)
	if err != nil {
		t.Fatalf("parsePage: %v", err)
	}
	if items != nil || cursor != "" || hasMore {
		t.Errorf("items=%s cursor=%q hasMore=%v, want empty page", items, cursor, hasMore)
	}
}

func TestParsePage_RejectsInvalidFieldTypes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "items object", body: `{"data":{},"pagination":{"has_more":false,"next_cursor":null}}`},
		{name: "cursor object", body: `{"data":[],"pagination":{"has_more":true,"next_cursor":{}}}`},
		{name: "has-more string", body: `{"data":[],"pagination":{"has_more":"yes","next_cursor":"c2"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parsePage([]byte(tt.body), nil)
			if err == nil || err.Code != "PAGINATION_PARSE" {
				t.Fatalf("error = %#v, want PAGINATION_PARSE", err)
			}
		})
	}
}

// TestRunPaginated_RejectsOutputPathConflict pins the item-2 guard: pagination
// and binary output-to-disk are mutually exclusive (the page loop reuses the
// single OutputPath, so it would write every page over the same file). No spec
// op declares both today, so this cannot be reached through the command tree —
// it is a fail-loud guard called directly here to prove a future spec wiring
// the two together is rejected up front rather than silently corrupting output.
func TestRunPaginated_RejectsOutputPathConflict(t *testing.T) {
	tf := cmdutil.NewTestFactory()
	tf.SetConfig(&config.Config{APIBaseURL: "http://example.invalid", Format: "json"})

	dst := filepath.Join(t.TempDir(), "must-not-write.bin")
	err := runPaginated(context.Background(), tf.Factory, &operationRuntime{}, &client.Request{
		Method: "GET", Path: "/x", OutputPath: dst,
	})
	if err == nil {
		t.Fatal("expected an error for a paginated op carrying OutputPath, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should explain the conflict, got %q", err.Error())
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("guard must reject before any write; output file must not exist")
	}
}

// TestFileUpload_FlagRegistration confirms a multipart operation gets a --file
// flag and that it is marked required by cobra.
func TestFileUpload_FlagRegistration(t *testing.T) {
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {})

	upload := findChild(findChild(findChild(root, "example"), "artifact"), "upload")
	if upload == nil {
		t.Fatal("file upload command not registered")
	}
	f := upload.Flags().Lookup("file")
	if f == nil {
		t.Fatal("multipart operation missing --file flag")
	}
	required := upload.Flags().Lookup("file").Annotations[cobra.BashCompOneRequiredFlag]
	if len(required) == 0 || required[0] != "true" {
		t.Errorf("--file should be required; annotations=%v", required)
	}
}

// TestFileUpload_MissingFileReturnsError confirms running the upload command
// without --file fails before touching the network.
func TestFileUpload_MissingFileReturnsError(t *testing.T) {
	called := false
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	root.SetArgs([]string{"example", "artifact", "upload"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing --file")
	}
	if called {
		t.Error("server should not be called when --file is missing")
	}
}

// TestFileUpload_ContentTypeIsMultipart confirms the client sends multipart
// form-data and that the uploaded bytes land in the "file" form field.
func TestFileUpload_ContentTypeIsMultipart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	payload := []byte("hello multipart")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	var gotCT string
	var gotFileName string
	var gotFileBody []byte
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(gotCT)
		if err != nil {
			t.Fatalf("parse media type: %v", err)
		}
		if mediaType != "multipart/form-data" {
			t.Errorf("media type = %q", mediaType)
		}
		if params["boundary"] == "" {
			t.Error("missing boundary parameter")
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("parse multipart: %v", err)
		}
		fhs := r.MultipartForm.File["file"]
		if len(fhs) != 1 {
			t.Fatalf("expected 1 file part, got %d", len(fhs))
		}
		gotFileName = fhs[0].Filename
		f, err := fhs[0].Open()
		if err != nil {
			t.Fatalf("open part: %v", err)
		}
		defer f.Close()
		gotFileBody, _ = io.ReadAll(f)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"url":"cos://x","name":"hello.txt","size":15}`))
	})
	root.SetArgs([]string{"example", "artifact", "upload", "--file", path})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.HasPrefix(gotCT, "multipart/form-data") {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotFileName != "hello.txt" {
		t.Errorf("filename = %q", gotFileName)
	}
	if !bytes.Equal(gotFileBody, payload) {
		t.Errorf("body = %q want %q", gotFileBody, payload)
	}
}

// TestBuildMultipartBody_FormTextFields directly exercises buildMultipartBody
// to confirm non-binary body flags are emitted as form text fields alongside
// the binary part. The current registry has no multipart op with additional
// body properties, so this synthesises the runtime.
func TestBuildMultipartBody_FormTextFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("binary"), 0o644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	filePath := path
	label := "report"
	count := 7
	flag := true
	tags := []string{"a", "b"}
	rt := &operationRuntime{
		filePath: &filePath,
		bodyFlags: map[string]*bodyFlag{
			"label": {apiName: "label", kind: kindString, strVal: &label},
			"count": {apiName: "count", kind: kindInt, intVal: &count},
			"flag":  {apiName: "flag", kind: kindBool, boolVal: &flag},
			"tags":  {apiName: "tags", kind: kindStringSlice, strSlc: &tags},
		},
	}

	cmd := &cobra.Command{Use: "synth"}
	cmd.Flags().StringVar(&filePath, "file", filePath, "")
	cmd.Flags().StringVar(&label, "label", label, "")
	cmd.Flags().IntVar(&count, "count", count, "")
	cmd.Flags().BoolVar(&flag, "flag", flag, "")
	cmd.Flags().StringSliceVar(&tags, "tags", tags, "")
	if err := cmd.ParseFlags([]string{"--label", "report", "--count", "7", "--flag", "--tags", "a,b"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	raw, ct, err := buildMultipartBody(cmd, rt)
	if err != nil {
		t.Fatalf("buildMultipartBody: %v", err)
	}
	if !strings.HasPrefix(ct, "multipart/form-data") {
		t.Fatalf("content type = %q", ct)
	}

	_, params, _ := mime.ParseMediaType(ct)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(raw))
	req.Header.Set("Content-Type", ct)
	_ = params
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("parse multipart: %v", err)
	}

	if got := req.MultipartForm.Value["label"]; len(got) != 1 || got[0] != "report" {
		t.Errorf("label form field = %v", got)
	}
	if got := req.MultipartForm.Value["count"]; len(got) != 1 || got[0] != "7" {
		t.Errorf("count form field = %v", got)
	}
	if got := req.MultipartForm.Value["flag"]; len(got) != 1 || got[0] != "true" {
		t.Errorf("flag form field = %v", got)
	}
	if got := req.MultipartForm.Value["tags"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("tags form field = %v", got)
	}
	if len(req.MultipartForm.File["file"]) != 1 {
		t.Error("binary file part missing")
	}
}

func TestValidateRequiredBodyFields_SkipsMultipartBinaryProperty(t *testing.T) {
	rt := &operationRuntime{detail: &registry.OperationDetail{
		Multipart: true,
		RequestBody: &registry.SchemaInfo{
			Type:       "object",
			Required:   []string{"file", "label"},
			Properties: map[string]registry.SchemaInfo{"file": {Type: "string", Format: "binary"}, "label": {Type: "string"}},
		},
	}}
	if err := validateRequiredBodyFields(rt, map[string]any{"label": "report"}); err != nil {
		t.Fatalf("multipart validation must be handled by buildMultipartBody: %v", err)
	}
}

// TestBuildMultipartBody_MissingFile confirms the validation error surfaces
// when --file is empty.
func TestBuildMultipartBody_MissingFile(t *testing.T) {
	empty := ""
	rt := &operationRuntime{filePath: &empty}
	cmd := &cobra.Command{Use: "synth"}
	_, _, err := buildMultipartBody(cmd, rt)
	if err == nil {
		t.Fatal("expected error")
	}
	ee := output.AsExitError(err)
	if ee == nil || ee.Type != "validation" {
		t.Errorf("expected validation ExitError, got %T: %v", err, err)
	}
}

// fallback: a parent command with no RunE silently prints help and exits 0
// when given an unknown token, which can let automation treat a removed or
// mistyped command as a success. Regression test for the removal of
// thread.delete (where `octo-cli thread delete ...` previously printed help).
func TestParentCommand_RejectsUnknownSubcommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown service subcommand", []string{"example", "bogus"}},
		{"unknown resource verb", []string{"example", "record", "nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
				t.Fatalf("HTTP handler must not be called when subcommand is unknown")
			})
			root.SetArgs(tc.args)
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetErr(&buf)
			err := root.Execute()
			if err == nil {
				t.Fatalf("expected error for %v, got nil; output=%s", tc.args, buf.String())
			}
			if !strings.Contains(err.Error(), "unknown subcommand") {
				t.Errorf("error should mention 'unknown subcommand', got %q", err.Error())
			}
		})
	}
}
