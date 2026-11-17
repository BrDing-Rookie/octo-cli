package cmd

import (
	"bytes"
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/mcp"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

func newMCPCmd(f *cmdutil.Factory) *cobra.Command {
	group := &cobra.Command{
		Use:         "mcp",
		Short:       "Manage the local Octo CLI MCP server",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"skipValidation": "true"},
		RunE:        func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	group.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Serve the Octo CLI MCP tool over stdio",
		Args:  cobra.NoArgs,
		Annotations: map[string]string{
			"skipValidation":      "true",
			"skipOutputPreflight": "true",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			defaults, reg := *f.Globals, f.Registry()
			return mcp.Serve(cmd.Context(), f.IOStreams.In, f.IOStreams.Out, Version,
				func(ctx context.Context, args []string) mcp.ExecResult {
					return runMCPCommand(ctx, &defaults, reg, args)
				})
		},
	})
	return group
}

func runMCPCommand(ctx context.Context, defaults *cmdutil.GlobalOptions, reg *registry.Registry, args []string) mcp.ExecResult {
	f := cmdutil.NewDefaultFactory()
	var stdout, stderr bytes.Buffer
	f.IOStreams = &cmdutil.IOStreams{In: strings.NewReader(""), Out: &stdout, ErrOut: &stderr}
	*f.Globals = *defaults
	f.RegistryFunc = func() *registry.Registry { return reg }

	root := newRootCmd(f, true)
	root.SetArgs(args)
	root.SetIn(f.IOStreams.In)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	code := f.ExitCode(root.ExecuteContext(ctx))
	return mcp.ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
}

// validateMCPFlags checks the parsed values before any command reads or writes
// a local file. Cobra resolves aliases, flag shorthands, and repeated flags.
func validateMCPFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	installsSkills := cmd.Parent() == cmd.Root() && cmd.Name() == "skills" && flags.Changed("install")
	if flags.Changed("file") || flags.Changed("output") || installsSkills {
		return output.ErrValidation("local file operations are unavailable in MCP calls", "run the command directly with octo-cli")
	}
	if data := flags.Lookup("data"); data != nil && data.Changed && strings.HasPrefix(data.Value.String(), "@") {
		return output.ErrValidation("MCP calls require inline request data", "pass inline JSON to --data")
	}
	return nil
}
