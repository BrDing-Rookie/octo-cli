package cmd

import (
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/testfixture"
)

func TestMCPRejectsInvalidCommandArguments(t *testing.T) {
	t.Setenv(config.EnvAPIBaseURL, "https://octo.example.invalid")
	reg := testfixture.Registry()
	defaults := &cmdutil.GlobalOptions{}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"extra version operand", []string{"version", "fixture-value"}, "accepts 0 arg(s)"},
		{"unknown config subcommand", []string{"config", "missing"}, "that is not a known command"},
		{"unknown help subcommand", []string{"help", "config", "missing"}, "unknown help topic"},
		{"hidden command", []string{"__complete", "version"}, "MCP calls require a public command"},
		{"raw HTTP command", []string{"api", "GET", "/v1/records", "--dry-run"}, "that is not a known command"},
		{"query value below minimum", []string{"example", "record", "list", "--limit", "0", "--dry-run"}, "outside its allowed numeric range"},
		{"query value above maximum", []string{"example", "record", "list", "--limit=101", "--dry-run"}, "outside its allowed numeric range"},
		{"wrong query type", []string{"example", "record", "list", "--limit", "bad", "--dry-run"}, "a flag value was rejected by its type"},
		{"missing pagination switch", []string{"example", "record", "list", "--page-limit", "5", "--dry-run"}, "--page-limit requires --page-all"},
		{"excess pagination", []string{"example", "record", "list", "--page-all", "--page-limit", "101", "--dry-run"}, "--page-limit must be between"},
		{"invalid timeout", []string{"example", "record", "list", "--timeout", "bad", "--dry-run"}, "--timeout must be a positive duration"},
		{"zero timeout", []string{"example", "record", "list", "--timeout=0s", "--dry-run"}, "--timeout must be a positive duration"},
		{"non-selector jq", []string{"version", "-q", ".data | length"}, "--jq accepts a field or array index path"},
		{"local file upload", []string{"example", "artifact", "upload", "--file=fixture.txt", "--dry-run"}, "local file operations are unavailable"},
		{"file-backed data", []string{"example", "record", "create", "--data=@fixture.json", "--dry-run"}, "MCP calls require inline request data"},
		{"caller selects credential file", []string{"example", "record", "list", "--credential-file", "fixture.txt", "--dry-run"}, "a flag in the command line was not recognised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runMCPCommand(t.Context(), defaults, reg, "fixture-bearer", tc.args)
			if result.ExitCode != 2 || result.Stdout != "" || !strings.Contains(result.Stderr, tc.want) {
				t.Fatalf("expected CLI validation result containing %q, got %+v", tc.want, result)
			}
		})
	}
}

func TestMCPPreservesValidCommandArguments(t *testing.T) {
	t.Setenv(config.EnvAPIBaseURL, "https://octo.example.invalid")
	t.Setenv(config.EnvToken, "fixture-stdio-bearer")
	reg := testfixture.Registry()
	defaults := &cmdutil.GlobalOptions{}
	for _, tc := range []struct {
		name   string
		bearer string
		args   []string
		want   string
	}{
		{"known help topic", "fixture-bearer", []string{"help", "config", "show"}, "Print the resolved target"},
		{"numeric query boundary", "fixture-bearer", []string{"example", "record", "list", "--limit=100", "--timeout", "10s", "--dry-run"}, "limit=100"},
		{"pagination controls", "fixture-bearer", []string{"example", "record", "list", "--page-all", "--page-limit=100", "--dry-run"}, "/v1/records"},
		{"inline JSON value", "fixture-bearer", []string{"example", "record", "create", "--data", `{"title":"A value with spaces and @literal"}`, "--dry-run"}, "A value with spaces and @literal"},
		{"field selector", "fixture-bearer", []string{"version", "-q", ".data.version"}, Version},
		{"array index selector", "fixture-bearer", []string{"schema", "--list", "--jq", ".data.services[0]"}, "example"},
		{"stdio raw API", "", []string{"api", "GET", "/v1/records", "--dry-run"}, "/v1/records"},
		{"stdio jq expression", "", []string{"version", "--jq", ".data | length"}, "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runMCPCommand(t.Context(), defaults, reg, tc.bearer, tc.args)
			if result.ExitCode != 0 || !strings.Contains(result.Stdout, tc.want) {
				t.Fatalf("expected success containing %q, got %+v", tc.want, result)
			}
		})
	}
}

func TestCLIAndMCPShareQueryRange(t *testing.T) {
	f := newTestFactoryWithReg()
	cfg, err := f.Config()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.Credential()
	if err != nil {
		t.Fatal(err)
	}
	f.SetClient(client.New(cfg, cred, client.Options{DryRun: true}))
	for _, limit := range []string{"0", "101"} {
		if _, _, err := execRoot(t, f, "example", "record", "list", "--limit", limit, "--dry-run"); err == nil ||
			!strings.Contains(err.Error(), "outside its allowed numeric range") {
			t.Errorf("limit %s should be rejected by the generated CLI, got %v", limit, err)
		}
	}
}
