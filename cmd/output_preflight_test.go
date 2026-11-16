package cmd

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

const outputPreflightBody = `{"title":"sample"}`

func newOutputPreflightServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"client_ref":"client-1","record_id":42,"revision":7}`)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func newOutputPreflightTestFactory(serverURL string) *cmdutil.TestFactory {
	f := newTestFactoryWithReg()
	cfg := &config.Config{APIBaseURL: serverURL, Token: "app_preflight", Format: output.FormatJSON}
	cred := &credential.Credential{Token: "app_preflight", Source: "test"}
	f.SetConfig(cfg)
	f.SetCredential(cred)
	f.SetClient(client.New(cfg, cred, client.Options{}))
	return f
}

func executeOutputPreflightRoot(t *testing.T, f *cmdutil.Factory, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	f.IOStreams.Out = &stdout
	f.IOStreams.ErrOut = &stderr
	root := NewRootCmd(f)
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	returnOutput := root.ExecuteContext(context.Background())
	return stdout.String(), returnOutput
}

func requireOutputConfigError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected output option error")
	}
	ee := output.AsExitError(cmdutil.WrapCLIError(err))
	if ee == nil {
		t.Fatalf("error did not retain the CLI error taxonomy: %T", err)
	}
	if ee.Type != "config" || ee.Code != "CLI_ERROR" {
		t.Fatalf("error type/code = %q/%q, want config/CLI_ERROR", ee.Type, ee.Code)
	}
}

func TestOutputPreflight_InvalidExplicitFormatDoesNotSendRequest(t *testing.T) {
	server, calls := newOutputPreflightServer(t)
	f := newOutputPreflightTestFactory(server.URL)

	_, err := executeOutputPreflightRoot(t, f.Factory,
		"--format", "unsupported",
		"api", "POST", "/v1/records", "--data", outputPreflightBody,
	)
	requireOutputConfigError(t, err)
	if got := calls.Load(); got != 0 {
		t.Fatalf("business HTTP requests = %d, want 0 before rejecting --format", got)
	}
}

func TestOutputPreflight_InvalidEnvironmentFormatWithProfileDoesNotSendRequest(t *testing.T) {
	server, calls := newOutputPreflightServer(t)
	writeExternalProfile(t, privateProfileFixtureDir(t), "agent", server.URL)
	t.Setenv(config.EnvFormat, "unsupported")

	f := cmdutil.NewDefaultFactory()
	_, err := executeOutputPreflightRoot(t, f, "--profile", "agent",
		"api", "POST", "/v1/records", "--data", outputPreflightBody,
	)
	requireOutputConfigError(t, err)
	if got := calls.Load(); got != 0 {
		t.Fatalf("business HTTP requests = %d, want 0 before rejecting OCTO_FORMAT", got)
	}
}

func TestOutputPreflight_InvalidJQDoesNotSendRequest(t *testing.T) {
	server, calls := newOutputPreflightServer(t)
	f := newOutputPreflightTestFactory(server.URL)

	_, err := executeOutputPreflightRoot(t, f.Factory,
		"--jq", ".[",
		"api", "POST", "/v1/records", "--data", outputPreflightBody,
	)
	requireOutputConfigError(t, err)
	if got := calls.Load(); got != 0 {
		t.Fatalf("business HTTP requests = %d, want 0 before rejecting --jq", got)
	}
}

func TestOutputPreflight_UncompilableJQDoesNotSendRequest(t *testing.T) {
	server, calls := newOutputPreflightServer(t)
	f := newOutputPreflightTestFactory(server.URL)

	_, err := executeOutputPreflightRoot(t, f.Factory,
		"--jq", "missing_audit_function",
		"api", "POST", "/v1/records", "--data", outputPreflightBody,
	)
	if got := calls.Load(); got != 0 {
		t.Fatalf("business HTTP requests = %d, want 0 before rejecting --jq that fails compilation", got)
	}
	requireOutputConfigError(t, err)
}

func TestOutputPreflight_CompletionCommandsIgnoreOutputControls(t *testing.T) {
	t.Setenv(config.EnvFormat, "unsupported")
	f := cmdutil.NewDefaultFactory()
	f.IOStreams.Out = io.Discard
	f.IOStreams.ErrOut = io.Discard
	var stdout bytes.Buffer
	root := NewRootCmd(f)
	root.SetArgs([]string{"--jq", ".[", "completion", "bash"})
	root.SetOut(&stdout)
	root.SetErr(io.Discard)

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("completion failed for output controls it does not consume: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("completion produced no shell output")
	}
}

func TestOutputPreflight_InvalidOptionsPreventProfileRemoval(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
	}{
		{name: "format", flags: []string{"--format", "unsupported"}},
		{name: "jq", flags: []string{"--jq", ".["}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeExternalProfile(t, privateProfileFixtureDir(t), "agent", "https://gateway.example.test")
			f := newTestFactoryWithReg()
			_, err := executeOutputPreflightRoot(t, f.Factory,
				append(tc.flags, "--profile", "agent", "auth", "logout")...,
			)
			requireOutputConfigError(t, err)
			if _, err := os.Stat(configPath); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(configPath)
			if err != nil || !strings.Contains(string(raw), `"agent"`) {
				t.Fatal("auth logout removed the profile before rejecting the output option")
			}
		})
	}
}

func TestOutputPreflight_LegitimateControlsRemainAvailable(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		check func(t *testing.T, stdout string)
	}{
		{
			name:  "json",
			flags: []string{"--format", "json"},
			check: func(t *testing.T, stdout string) {
				var got struct {
					OK   bool `json:"ok"`
					Data struct {
						ClientRef string `json:"client_ref"`
						RecordID  int64  `json:"record_id"`
						Revision  int64  `json:"revision"`
					} `json:"data"`
				}
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("decode JSON success result: %v", err)
				}
				if !got.OK || got.Data.ClientRef != "client-1" || got.Data.RecordID != 42 || got.Data.Revision != 7 {
					t.Fatalf("JSON success result = %+v, want the fixture response", got)
				}
			},
		},
		{
			name:  "table",
			flags: []string{"--format", "table"},
			check: func(t *testing.T, stdout string) {
				for _, want := range []string{"client-1", "record_id", "42", "7"} {
					if !strings.Contains(stdout, want) {
						t.Fatalf("table output lacks result field %q: %s", want, stdout)
					}
				}
			},
		},
		{
			name:  "csv",
			flags: []string{"--format", "csv"},
			check: func(t *testing.T, stdout string) {
				rows, err := csv.NewReader(strings.NewReader(stdout)).ReadAll()
				if err != nil {
					t.Fatalf("decode CSV result: %v", err)
				}
				if len(rows) != 2 || len(rows[0]) != len(rows[1]) {
					t.Fatalf("CSV rows = %#v, want one header and one result row", rows)
				}
				values := make(map[string]string, len(rows[0]))
				for i, header := range rows[0] {
					values[header] = rows[1][i]
				}
				if values["client_ref"] != "client-1" || values["record_id"] != "42" || values["revision"] != "7" {
					t.Fatalf("CSV result = %#v, want the fixture response", values)
				}
			},
		},
		{
			name:  "ndjson",
			flags: []string{"--format", "ndjson"},
			check: func(t *testing.T, stdout string) {
				var got struct {
					ClientRef string `json:"client_ref"`
					RecordID  int64  `json:"record_id"`
					Revision  int64  `json:"revision"`
				}
				decoder := json.NewDecoder(strings.NewReader(stdout))
				if err := decoder.Decode(&got); err != nil {
					t.Fatalf("decode NDJSON result: %v", err)
				}
				if got.ClientRef != "client-1" || got.RecordID != 42 || got.Revision != 7 {
					t.Fatalf("NDJSON result = %+v, want the fixture response", got)
				}
				if err := decoder.Decode(new(any)); err != io.EOF {
					t.Fatalf("NDJSON has extra records: %v", err)
				}
			},
		},
		{
			name:  "valid jq",
			flags: []string{"--jq", ".data.record_id"},
			check: func(t *testing.T, stdout string) {
				var got int64
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("decode jq result: %v", err)
				}
				if got != 42 {
					t.Fatalf("jq result = %d, want 42", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newOutputPreflightServer(t)
			f := newOutputPreflightTestFactory(server.URL)
			args := append(append([]string(nil), tc.flags...),
				"api", "POST", "/v1/records", "--data", outputPreflightBody,
			)
			stdout, err := executeOutputPreflightRoot(t, f.Factory, args...)
			if err != nil {
				t.Fatalf("command with supported output controls failed: %v", err)
			}
			tc.check(t, stdout)
		})
	}
}

func TestOutputPreflight_ServiceHelpIgnoresInvalidOutputControls(t *testing.T) {
	cases := []struct {
		name          string
		commandPath   []string
		outputControl string
	}{
		{name: "service parent with malformed jq", commandPath: []string{"example"}, outputControl: "jq"},
		{name: "service parent with invalid environment format", commandPath: []string{"example"}, outputControl: "format"},
		{name: "nested group with malformed jq", commandPath: []string{"example", "record"}, outputControl: "jq"},
		{name: "nested group with invalid environment format", commandPath: []string{"example", "record"}, outputControl: "format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvFormat, "")
			args := make([]string, 0, len(tc.commandPath)+2)
			switch tc.outputControl {
			case "jq":
				args = append(args, "--jq", ".[")
			case "format":
				t.Setenv(config.EnvFormat, "unsupported")
			default:
				t.Fatalf("unknown output control %q", tc.outputControl)
			}
			args = append(args, tc.commandPath...)

			f := newAuthTestFactory()
			f.RegistryFunc = testfixture.Registry
			root := NewRootCmd(f.Factory)
			helpCommand, _, err := root.Find(tc.commandPath)
			if err != nil {
				t.Fatalf("find help command: %v", err)
			}
			root.SetArgs(args)
			var stdout bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(io.Discard)

			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("help command rejected output controls it does not consume: %v", err)
			}
			if !strings.Contains(stdout.String(), helpCommand.CommandPath()) {
				t.Fatalf("help output does not identify requested command %q: %s", helpCommand.CommandPath(), stdout.String())
			}
		})
	}
}
