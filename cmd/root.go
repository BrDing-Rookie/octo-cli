// Package cmd is the command tree. It wires cobra commands with the Factory DI
// container and holds root-level persistent flags. Service-domain commands are
// auto-registered from the embedded OpenAPI registry via cmd/service. Handwritten
// command leaves are `schema`, `version`, `upgrade`, `api` (generic passthrough),
// `config`, `skills`, `auth`, and `sheet-cell` (offline value→cell helper).
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/cmd/service"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

// NewRootCmd builds the top-level command tree.
func NewRootCmd(f *cmdutil.Factory) *cobra.Command {
	if f == nil {
		f = cmdutil.NewDefaultFactory()
	}

	root := &cobra.Command{
		Use:   "octo-cli",
		Short: "Octo CLI — command-line interface for the Octo ecosystem",
		Long:  "octo-cli is a CLI for AI Agent Bots to interact with Octo services.\nService commands are generated from the embedded OpenAPI registry.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			f.Globals.ProfileSet = cmd.Flags().Changed("profile")
			f.Globals.BotIDSet = cmd.Flags().Changed("bot-id")
			f.Globals.CredentialFileSet = cmd.Flags().Changed("credential-file")
			if err := validateTaskModeCommand(cmd); err != nil {
				return err
			}
			if skipValidation(cmd) {
				// Help and completion render their own text, not a Factory
				// success result. Other credential-free and local auth commands
				// read OCTO_FORMAT without resolving credentials: profiles do
				// not carry a format setting.
				if !skipOutputPreflight(cmd, args) {
					format := config.LoadRuntime().Format
					if f.Globals != nil && f.Globals.Format != "" {
						format = f.Globals.Format
					}
					if err := f.PreflightOutput(format); err != nil {
						return err
					}
				}
				return nil
			}
			unified, err := config.LoadRuntime().UsesUnifiedCredentials(f.Globals.CredentialFileSet || f.Globals.CredentialFile != "")
			if err != nil {
				return err
			}
			if unified {
				if err := validateUnifiedAPICommand(cmd); err != nil {
					return err
				}
				if _, err := f.BusinessCredential(); err != nil {
					return err
				}
				return preflightUnifiedOutput(f)
			}
			cfg, err := f.Config()
			if err != nil {
				return err
			}
			if err := f.PreflightOutput(f.Format()); err != nil {
				return err
			}
			return cfg.Validate()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&f.Globals.Format, "format", "", "output format: json (default) | table | csv | ndjson")
	pf.StringVarP(&f.Globals.JQ, "jq", "q", "", "filter output with a jq expression")
	pf.BoolVar(&f.Globals.DryRun, "dry-run", false, "print request without executing")
	pf.BoolVar(&f.Globals.Verbose, "verbose", false, "write request/response trace to stderr")
	pf.StringVar(&f.Globals.Timeout, "timeout", "", "per-request timeout (default 30s; invalid values warn and use 30s)")
	pf.BoolVar(&f.Globals.NoRetry, "no-retry", false, "disable retries, including multipart PUT, failure-triggered re-signing and completion; expired URLs may still be signed before the first PUT")
	pf.StringVar(&f.Globals.Space, "space", "", "space id (for platform-scoped bots)")
	pf.StringVar(&f.Globals.BotID, "bot-id", "", "select/assert the bot credential by robot id (env OCTO_BOT_ID)")
	pf.StringVar(&f.Globals.Profile, "profile", "", "select a profile by name (OCTO_CREDENTIAL_MODE=unified for versioned profiles; env OCTO_PROFILE)")
	pf.StringVar(&f.Globals.CredentialFile, "credential-file", "", "read the unified Token from a file (env OCTO_TOKEN_FILE)")

	root.AddCommand(newSchemaCmd(f))
	root.AddCommand(newUpgradeCmd(f))
	root.AddCommand(newVersionCmd(f))
	root.AddCommand(newAPICmd(f))
	root.AddCommand(newConfigCmd(f))
	root.AddCommand(newSkillsCmd(f))
	root.AddCommand(newAuthCmd(f))
	root.AddCommand(newSheetCellCmd(f))
	service.RegisterServiceCommands(root, f)
	attachMailAuthCmd(root, f)
	attachMailJMAPCommands(root, f)
	registerDocsImportCmd(root, f)
	registerDocsExportCmd(root, f)
	registerDocsExcalidrawExportCmd(root, f)
	registerDocsBoardCommentCmd(root, f)
	registerDriveCmds(root, f)
	withholdDisabledServices(root, f)

	return root
}

func preflightUnifiedOutput(f *cmdutil.Factory) error {
	err := f.PreflightOutput(f.Format())
	if err == nil {
		return nil
	}
	// Classify the original error before masking its message.
	exit := *output.AsExitError(cmdutil.WrapCLIError(err))
	exit.Message = f.RedactUnifiedBearer(exit.Message)
	return &exit
}

// CLI-01/02 use a caller-supplied API path. Named service behavior and
// generated operation routes are added when their CLI-07 contracts are ready.
func validateUnifiedAPICommand(cmd *cobra.Command) error {
	if cmd.Parent() == cmd.Root() && cmd.Name() == "api" {
		serviceName, err := cmd.Flags().GetString("service")
		if err != nil {
			return err
		}
		if serviceName == "" || serviceName == "default" {
			return nil
		}
	}
	return output.ErrWithHint("validation", "UNIFIED_API_ONLY",
		"unified credentials currently require api with the default service",
		"use api METHOD PATH with a route that accepts unified credentials")
}

// validateTaskModeCommand is defense in depth. It keeps daemon task processes
// on the Loop surface without duplicating Fleet's route/action policy in the
// CLI. Offline discovery commands remain available to agents.
func validateTaskModeCommand(cmd *cobra.Command) error {
	if strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvCredentialMode))) != config.CredentialModeTask {
		return nil
	}
	root := cmd.Root()
	current := cmd
	for current.Parent() != nil && current.Parent() != root {
		current = current.Parent()
	}
	if current == root {
		return nil
	}
	switch current.Name() {
	case "loop", "help", "version", "schema", "skills", "completion":
		return nil
	default:
		return fmt.Errorf("%s=task only allows Loop commands", config.EnvCredentialMode)
	}
}

// withholdDisabledServices removes the command subtree for any service whose
// spec sets x-octo-disabled (e.g. matter, whose backend API is not yet stable).
// The spec stays embedded, so `octo-cli schema` and the metadata-driven engine
// still see it — flip the flag in the spec to re-enable. Done here (after
// registration) rather than inside RegisterServiceCommands so the engine tests
// that drive it directly keep their full fixture coverage.
func withholdDisabledServices(root *cobra.Command, f *cmdutil.Factory) {
	reg := f.Registry()
	if reg == nil {
		return
	}
	for _, svc := range reg.ListServices() {
		if !reg.ServiceDisabled(svc) {
			continue
		}
		for _, c := range root.Commands() {
			if c.Name() == svc {
				root.RemoveCommand(c)
				break
			}
		}
	}
}

// skipValidation is true for commands that must run without a configured
// credential (e.g. `octo-cli version`, `octo-cli upgrade`, `octo-cli help`,
// `octo-cli schema`, `octo-cli config`, `octo-cli auth`, and cobra's generated
// `completion`). Walks the parent chain so leaves like `config show` match
// through their parent.
func skipValidation(cmd *cobra.Command) bool {
	// Per-command annotation, deliberately NOT inherited through the parent
	// chain: service parents (`octo-cli thread`, `octo-cli group`, …) opt out of the
	// auth gate so their help / unknown-subcommand path works without a token,
	// but their leaf operations (`octo-cli thread create …`) must still authenticate.
	if cmd.Annotations["skipValidation"] == "true" {
		return true
	}
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "version", "help", "schema", "config", "completion", "skills", "sheet-cell", "":
			return true
		case "auth":
			// Only the top-level `octo-cli auth` is credential-free. Nested
			// service auth flows such as `mail auth login` require the active
			// Bot credential and must pass the normal validation gate.
			if c.Parent() != nil && c.Parent().Parent() == nil {
				return true
			}
		}
	}
	return false
}

// skipOutputPreflight identifies commands whose output does not use the Factory
// formatter: built-in help/completion commands and annotated service parents
// or groups when they have no arguments and render help.
func skipOutputPreflight(cmd *cobra.Command, args []string) bool {
	if len(args) == 0 && cmd.HasSubCommands() && cmd.Annotations["skipValidation"] == "true" {
		return true
	}
	for current := cmd; current != nil; current = current.Parent() {
		switch current.Name() {
		case "help", "completion":
			return true
		}
	}
	return false
}
