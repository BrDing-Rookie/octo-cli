package cmd

import (
	"errors"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func authProfileMutationMode(f *cmdutil.Factory, command string) (bool, error) {
	unified, err := f.UsesUnifiedCredentials()
	if err != nil {
		return false, err
	}
	if f.Globals.DryRun {
		return false, output.ErrValidation(
			"--dry-run is not supported for auth "+command,
			"omit --dry-run to modify the stored profile",
		)
	}
	return unified, nil
}

func managedProfileForMutation(f *cmdutil.Factory) (*authstore.ManagedStore, authstore.ProfileSnapshot, error) {
	g := f.Globals
	if g.BotIDSet || g.BotID != "" || g.CredentialFileSet || g.CredentialFile != "" || g.Space != "" {
		return nil, authstore.ProfileSnapshot{}, output.ErrValidation(
			"only --profile is supported for selecting a unified profile to modify",
			"remove --bot-id, --credential-file and --space",
		)
	}
	name, selector := config.ProfileSelector(g.Profile, g.ProfileSet)
	if selector != "" && name == "" {
		return nil, authstore.ProfileSnapshot{}, output.ErrValidation(selector+" is empty", "select an existing profile")
	}
	store, err := authstore.OpenManaged()
	if err != nil {
		return nil, authstore.ProfileSnapshot{}, credential.ProfileConfigError(err)
	}
	snap, err := store.Snapshot(name, selector != "")
	if err != nil {
		return nil, authstore.ProfileSnapshot{}, credential.ProfileConfigError(err)
	}
	if !snap.Exists {
		return nil, authstore.ProfileSnapshot{}, output.ErrAuth("no matching unified profile", "check octo-cli auth list")
	}
	return store, snap, nil
}

func confirmUnifiedProfileTarget(f *cmdutil.Factory, apiBaseURL string) error {
	store, snap, err := managedProfileForMutation(f)
	if err != nil {
		return failErr(f, err)
	}
	if apiBaseURL == "" || apiBaseURL != snap.Profile.APIBaseURL {
		return failErr(f, output.ErrValidation(
			"cannot change the API origin of a unified profile with auth update",
			"re-import a Token verified for the target API origin",
		))
	}
	if err := store.ConfirmTarget(snap, apiBaseURL); err != nil {
		return failErr(f, managedProfileMutationError(err))
	}
	return emitJSON(f, map[string]any{"profile": snap.Name, "api_base_url": apiBaseURL})
}

func logoutUnifiedProfile(f *cmdutil.Factory) error {
	store, snap, err := managedProfileForMutation(f)
	if err != nil {
		return failErr(f, err)
	}
	result, err := store.Remove(snap)
	if err != nil {
		return failErr(f, managedProfileMutationError(err))
	}
	payload := map[string]any{"removed": snap.Name}
	putIfSet(payload, "cleanup_warning", result.CleanupWarning)
	return emitJSON(f, payload)
}

func managedProfileMutationError(err error) error {
	if errors.Is(err, authstore.ErrProfileConflict) {
		return output.ErrWithHint("validation", "PROFILE_CONFLICT", "the selected profile changed", "read the profile again and retry")
	}
	return output.ErrValidation("cannot modify the unified profile", "check the configuration directory and its permissions")
}
