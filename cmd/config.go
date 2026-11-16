package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
)

// newConfigCmd exposes diagnostic settings without publishing secrets.
func newConfigCmd(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect CLI configuration"}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the resolved target and credential source",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := f.RequestConfig(cmd.Context())
			if err != nil {
				return failErr(f, err)
			}
			cred, err := f.Credential()
			if err != nil {
				return failErr(f, err)
			}
			payload := map[string]string{
				"api_base_url": cfg.APIBaseURL, "api_base_url_source": cfg.APIBaseURLSource,
				"space_id": cfg.SpaceID, "format": f.Format(),
			}
			if cred != nil && cred.Token != "" {
				payload["source"] = cred.Source
				if cred.Profile != "" {
					payload["profile"] = cred.Profile
				}
			}
			return emitJSON(f, payload)
		},
	})
	return cmd
}
