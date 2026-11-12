package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func importProfile(cmd *cobra.Command, f *cmdutil.Factory, originFlag, token string) error {
	selector, err := f.ProfileSelector()
	if err != nil {
		return failErr(f, err)
	}
	store, err := f.AuthStore()
	if err != nil {
		return failErr(f, err)
	}
	var snapshot *authstore.Config
	err = store.View(cmd.Context(), func(cfg *authstore.Config) error {
		snapshot = cfg
		return nil
	})
	if err != nil {
		return failErr(f, err)
	}

	name := selector
	if name == "" {
		name = snapshot.CurrentProfile
		if name == "" {
			name = authstore.DefaultProfile
		}
	}
	previous := snapshot.Profiles[name]
	target, err := importTarget(cmd, f, &previous, originFlag)
	if err != nil {
		return failErr(f, err)
	}
	warning, err := store.Import(cmd.Context(), name, snapshot, selector == "", &target, token)
	if err != nil {
		return failErr(f, err)
	}
	writeStoreWarning(f, warning)
	return emitJSON(f, map[string]string{
		"profile": name, "api_base_url": target.APIBaseURL, "space_id": target.SpaceID, "source": authstore.ManagedStore,
	})
}

func importTarget(cmd *cobra.Command, f *cmdutil.Factory, previous *authstore.Profile, originFlag string) (authstore.Profile, error) {
	cfg := f.RuntimeConfig()
	origin := cfg.APIBaseURL
	if cmd.Flags().Changed("api-base-url") {
		origin = originFlag
	} else if cfg.APIBaseURLSource == "default" && previous.APIBaseURL != "" {
		origin = previous.APIBaseURL
	}
	origin, err := config.NormalizeAPIBaseURL(origin)
	if err != nil {
		return authstore.Profile{}, output.ErrValidation(err.Error(), "use the business gateway origin")
	}
	space := cfg.SpaceID
	if space == "" {
		space = previous.SpaceID
	}
	if err := authstore.ValidateSpace(space); err != nil {
		return authstore.Profile{}, err
	}
	return authstore.Profile{APIBaseURL: origin, SpaceID: space}, nil
}
