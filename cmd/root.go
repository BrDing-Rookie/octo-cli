// Package cmd is the command tree. It wires cobra commands with the Factory DI
// container and holds root-level persistent flags. Service-domain commands are
// auto-registered from the embedded OpenAPI registry via cmd/service.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/cmd/service"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
)

// NewRootCmd builds the top-level command tree.
func NewRootCmd(f *cmdutil.Factory) *cobra.Command {
	if f == nil {
		f = cmdutil.NewDefaultFactory()
	}

	root := &cobra.Command{
		Use:   "octo-cli",
		Short: "Octo CLI — an OpenAPI-driven command-line framework",
		Long:  "octo-cli provides a generic HTTP client and generates service commands from embedded OpenAPI specs.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			f.Globals.ProfileSet = cmd.Flags().Changed("profile")
			f.Globals.CredentialFileSet = cmd.Flags().Changed("credential-file")
			if !skipOutputPreflight(cmd, args) {
				if err := f.PreflightOutput(f.Format()); err != nil {
					return err
				}
			}
			if skipValidation(cmd) {
				return nil
			}
			_, err := f.ValidatedRequestConfig(cmd.Context())
			return err
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
	pf.BoolVar(&f.Globals.NoRetry, "no-retry", false, "disable automatic HTTP retries")
	pf.StringVar(&f.Globals.Space, "space", "", "space context for API requests")
	pf.StringVar(&f.Globals.Profile, "profile", "", "select a local profile (env OCTO_PROFILE)")
	pf.StringVar(&f.Globals.CredentialFile, "credential-file", "", "read the Bearer from a file")

	root.AddCommand(newSchemaCmd(f))
	root.AddCommand(newUpgradeCmd(f))
	root.AddCommand(newVersionCmd(f))
	root.AddCommand(newAPICmd(f))
	root.AddCommand(newConfigCmd(f))
	root.AddCommand(newSkillsCmd(f))
	root.AddCommand(newAuthCmd(f))
	service.RegisterServiceCommands(root, f)

	return root
}

// skipValidation allows local framework commands and service help to run
// before a credential has been configured.
func skipValidation(cmd *cobra.Command) bool {
	// Service groups opt out for their own help and unknown-command paths.
	if cmd.Annotations["skipValidation"] == "true" {
		return true
	}
	for cmd.Parent() != nil && cmd.Parent().Parent() != nil {
		cmd = cmd.Parent()
	}
	switch cmd.Name() {
	case "octo-cli", "version", "help", "schema", "config", "completion", "skills", "auth":
		return true
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
