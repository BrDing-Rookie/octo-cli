package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/mcp"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

func newMCPCmd(f *cmdutil.Factory) *cobra.Command {
	group := &cobra.Command{
		Use:         "mcp",
		Short:       "Manage the Octo CLI MCP server",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"skipValidation": "true"},
		RunE:        func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var listen string
	var httpOptions mcp.HTTPOptions
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve the Octo CLI MCP tool over stdio or Streamable HTTP",
		Args:  cobra.NoArgs,
		Annotations: map[string]string{
			"skipValidation":      "true",
			"skipOutputPreflight": "true",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			defaults, reg := *f.Globals, f.Registry()
			execute := func(ctx context.Context, bearer string, args []string) mcp.ExecResult {
				return runMCPCommand(ctx, &defaults, reg, bearer, args)
			}
			if cmd.Flags().Changed("listen") {
				return serveMCPHTTP(cmd.Context(), f, listen, httpOptions, execute)
			}
			if cmd.Flags().Changed("drain-delay") || cmd.Flags().Changed("shutdown-timeout") {
				return output.ErrValidation("HTTP drain options require --listen", "set an HTTP listener address")
			}
			return mcp.Serve(cmd.Context(), f.IOStreams.In, f.IOStreams.Out, Version,
				func(ctx context.Context, args []string) mcp.ExecResult { return execute(ctx, "", args) })
		},
	}
	serve.Flags().StringVar(&listen, "listen", "", "serve Streamable HTTP at /mcp on host:port (for example 127.0.0.1:8765)")
	serve.Flags().DurationVar(&httpOptions.DrainDelay, "drain-delay", 0, "wait after readiness fails before closing the HTTP listener")
	serve.Flags().DurationVar(&httpOptions.ShutdownTimeout, "shutdown-timeout", mcp.DefaultHTTPShutdownTimeout, "maximum time to drain accepted HTTP requests")
	group.AddCommand(serve)
	return group
}

func serveMCPHTTP(ctx context.Context, f *cmdutil.Factory, address string, options mcp.HTTPOptions, execute func(context.Context, string, []string) mcp.ExecResult) error {
	if strings.TrimSpace(address) == "" {
		return output.ErrValidation("--listen requires an address", "pass host:port, for example 127.0.0.1:8765")
	}
	if options.DrainDelay < 0 || options.ShutdownTimeout <= 0 {
		return output.ErrValidation("invalid HTTP drain options", "pass a non-negative --drain-delay and a positive --shutdown-timeout")
	}
	var listenerConfig net.ListenConfig
	listener, err := listenerConfig.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("listen for MCP HTTP: %w", err)
	}
	_, _ = fmt.Fprintf(f.IOStreams.ErrOut, "Octo CLI MCP listening on http://%s/mcp\n", listener.Addr()) //nolint:errcheck // best-effort startup diagnostic
	return mcp.ServeHTTP(ctx, listener, Version, options, execute)
}

func runMCPCommand(ctx context.Context, defaults *cmdutil.GlobalOptions, reg *registry.Registry, bearer string, args []string) mcp.ExecResult {
	f := cmdutil.NewRequestFactory(ctx, bearer)
	var stdout, stderr bytes.Buffer
	f.IOStreams = &cmdutil.IOStreams{In: strings.NewReader(""), Out: &stdout, ErrOut: &stderr}
	*f.Globals = *defaults
	f.RegistryFunc = func() *registry.Registry { return reg }

	mode := mcpStdioMode
	if bearer != "" {
		mode = mcpHTTPMode
	}
	root := newRootCmd(f, mode)
	root.SetArgs(args)
	root.SetIn(f.IOStreams.In)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	code := f.ExitCode(root.ExecuteContext(ctx))
	return mcp.ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
}

func validateMCPCommand(cmd *cobra.Command, args []string, mode commandMode) error {
	if cmd.Hidden || cmd.DisableFlagParsing {
		return output.ErrValidation("MCP calls require a public command", "use schema --list or --help to discover commands")
	}
	if cmd.Name() == "help" && cmd.Parent() == cmd.Root() {
		target, remainder, err := cmd.Root().Find(args)
		if err != nil || target == nil || target.Hidden || len(remainder) != 0 {
			return output.ErrValidation("unknown help topic", "pass the name of a public command or command group")
		}
	}
	if err := validateMCPFlags(cmd); err != nil {
		return err
	}
	if mode == mcpHTTPMode {
		return validateMCPHTTPFlags(cmd)
	}
	return nil
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

const (
	maxMCPPageLimit = 100
	maxMCPJQLength  = 1024
)

func validateMCPHTTPFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	if timeout := flags.Lookup("timeout"); timeout != nil && timeout.Changed {
		if duration, err := time.ParseDuration(timeout.Value.String()); err != nil || duration <= 0 {
			return output.ErrValidation("--timeout must be a positive duration", "pass a Go duration such as 10s")
		}
	}
	if jq := flags.Lookup("jq"); jq != nil && jq.Changed && !validMCPQuery(jq.Value.String()) {
		return output.ErrValidation("HTTP MCP --jq accepts a field or array index path", "use a path such as .data.items[0].id or filter stdout in the client")
	}
	if flags.Changed("page-limit") {
		return validateMCPPagination(cmd)
	}
	return nil
}

func validateMCPPagination(cmd *cobra.Command) error {
	flags := cmd.Flags()
	all, err := flags.GetBool("page-all")
	if err != nil || !all {
		return output.ErrValidation("--page-limit requires --page-all", "enable --page-all or omit --page-limit")
	}
	limit, err := flags.GetInt("page-limit")
	if err != nil || limit < 1 || limit > maxMCPPageLimit {
		return output.ErrValidation(
			fmt.Sprintf("--page-limit must be between 1 and %d", maxMCPPageLimit),
			"use the returned cursor to request additional pages")
	}
	return nil
}

// A selector performs a single lookup per field or index. Bound the expression
// before handing it to the shared jq compiler.
func validMCPQuery(expr string) bool {
	if len(expr) > maxMCPJQLength {
		return false
	}
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "." {
		return true
	}
	const key = `[A-Za-z_][A-Za-z0-9_]*`
	const index = `\[-?[0-9]{1,10}\]`
	const path = `^\.(` + key + `|` + index + `)(\.` + key + `|` + index + `)*$`
	valid, err := regexp.MatchString(path, expr)
	return err == nil && valid
}
