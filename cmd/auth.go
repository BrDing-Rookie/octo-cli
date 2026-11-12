package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func newAuthCmd(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Add and remove local Token profiles"}
	cmd.AddCommand(newAuthLoginCmd(f), newAuthLogoutCmd(f))
	return cmd
}

func authMutationPreRun(f *cmdutil.Factory, hint string) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		if f.Globals.DryRun {
			return failErr(f, output.ErrValidation("--dry-run is not supported for this command", hint))
		}
		return nil
	}
}

func newAuthLoginCmd(f *cmdutil.Factory) *cobra.Command {
	var withToken bool
	var tokenFile, apiBaseURL string
	cmd := &cobra.Command{
		Use:     "login",
		Short:   "Import a Token into a local profile",
		Args:    cobra.NoArgs,
		PreRunE: authMutationPreRun(f, "remove --dry-run to import a token"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			token, err := loginTokenInput(cmd, f, withToken, tokenFile)
			if err != nil {
				return failErr(f, err)
			}
			return importProfile(cmd, f, apiBaseURL, token)
		},
	}
	cmd.Flags().BoolVar(&withToken, "with-token", false, "read the Token from stdin")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "import the Token from a file")
	cmd.Flags().StringVar(&apiBaseURL, "api-base-url", "", "API origin to bind to the profile")
	return cmd
}

func loginTokenInput(cmd *cobra.Command, f *cmdutil.Factory, withToken bool, path string) (string, error) {
	fileSet := cmd.Flags().Changed("token-file")
	if f.Globals.CredentialFileSet {
		if fileSet {
			return "", output.ErrValidation("use either --token-file or --credential-file", "")
		}
		path, fileSet = f.Globals.CredentialFile, true
	}
	if withToken && fileSet {
		return "", output.ErrValidation("--with-token cannot be combined with a token file flag",
			"use --with-token for stdin or one of --token-file and --credential-file for a file")
	}
	if !fileSet && !withToken {
		return "", output.ErrValidation("a token input is required", "pass --with-token for stdin or --token-file for a file")
	}

	var token string
	var err error
	switch {
	case fileSet:
		token, err = credential.ReadFile(path)
	case isTerminal(f.IOStreams.In):
		input := f.IOStreams.In.(*os.File)
		fmt.Fprint(f.IOStreams.ErrOut, "Token: ") //nolint:errcheck // best-effort prompt
		var data []byte
		data, err = term.ReadPassword(int(input.Fd()))
		fmt.Fprintln(f.IOStreams.ErrOut) //nolint:errcheck // best-effort prompt
		if err != nil {
			return "", output.ErrValidation("could not read token from the terminal", "")
		}
		token = string(data)
		err = credential.ValidateBearer(token)
	default:
		token, err = credential.Read(f.IOStreams.In)
	}
	if err != nil {
		return "", output.ErrAuth(err.Error(), "check the supplied token")
	}
	return token, nil
}

func isTerminal(reader any) bool {
	file, ok := reader.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func newAuthLogoutCmd(f *cmdutil.Factory) *cobra.Command {
	return &cobra.Command{
		Use:     "logout",
		Short:   "Remove a local profile",
		Args:    cobra.NoArgs,
		PreRunE: authMutationPreRun(f, "remove --dry-run to remove the profile"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := f.ProfileSelector()
			if err != nil {
				return failErr(f, err)
			}
			store, err := f.AuthStore()
			if err != nil {
				return failErr(f, err)
			}
			removed, warning, err := store.Logout(cmd.Context(), name, func(p *authstore.Profile) error {
				_, err := cmdutil.ApplyProfileScope(f.RuntimeConfig(), p)
				return err
			})
			if err != nil {
				return failErr(f, err)
			}
			writeStoreWarning(f, warning)
			return emitJSON(f, map[string]string{"removed": removed})
		},
	}
}

func writeStoreWarning(f *cmdutil.Factory, warning string) {
	if warning != "" {
		fmt.Fprintln(f.IOStreams.ErrOut, "warning: "+warning) //nolint:errcheck // best-effort post-commit diagnostic
	}
}

func emitJSON(f *cmdutil.Factory, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return failErr(f, err)
	}
	return f.EmitSuccess(raw)
}

// failErr emits the structured error while returning it for the exit code.
func failErr(f *cmdutil.Factory, err error) error {
	_ = f.EmitError(err) //nolint:errcheck // envelope write is best-effort
	return err
}
