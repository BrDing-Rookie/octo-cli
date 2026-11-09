package cmd

import (
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func runUnifiedAuthStatus(f *cmdutil.Factory) error {
	if f.Globals.BotIDSet || f.Globals.BotID != "" {
		return failErr(f, output.ErrValidation("--bot-id cannot be used with unified credentials", "select a Profile with --profile or OCTO_PROFILE"))
	}
	name, profiles, profile, err := selectUnifiedStatusProfile(f)
	if err != nil {
		return failErr(f, err)
	}
	var target config.Profile
	if profile != nil {
		if profile.APIBaseURL == "" {
			return failErr(f, output.ErrValidation("profile token_source requires api_base_url", "set the API origin in the selected profile"))
		}
		target = *profile
	}
	runtime := config.LoadRuntime()
	if err := runtime.ApplyProfile(target, f.Globals.Space); err != nil {
		return failErr(f, output.ErrValidation(err.Error(), "check the profile, OCTO_API_BASE_URL and Space settings"))
	}

	status := "missing"
	var source, token string
	if profile != nil {
		// Read only the selected reference. Runtime credentials cannot establish
		// that a stored Profile is usable.
		source, token, err = credential.ReadProfileToken(profiles, profile.TokenSource)
		if err != nil {
			return failErr(f, err)
		}
		status = "readable"
	}

	payload := map[string]any{
		"status":              status,
		"profile":             client.RedactBearer(name, token),
		"api_base_url":        client.RedactBearer(runtime.APIBaseURL, token),
		"api_base_url_source": runtime.APIBaseURLSource,
	}
	putIfSet(payload, "space_id", client.RedactBearer(runtime.SpaceID, token))
	putIfSet(payload, "source", source)
	return emitJSON(f, payload)
}

func selectUnifiedStatusProfile(f *cmdutil.Factory) (string, *config.ProfileConfig, *config.Profile, error) {
	name, selector := config.ProfileSelector(f.Globals.Profile, f.Globals.ProfileSet)
	if selector != "" && (name == "" || strings.TrimSpace(name) != name) {
		return "", nil, nil, output.ErrValidation("invalid profile selector", "select a Profile with --profile or OCTO_PROFILE")
	}
	profiles, err := config.LoadProfileConfig()
	if err != nil {
		return "", nil, nil, credential.ProfileConfigError(err)
	}
	if selector == "" {
		if profiles == nil || profiles.CurrentProfile == "" {
			return "", nil, nil, output.ErrValidation("no target profile selected", "pass --profile or set OCTO_PROFILE")
		}
		name = profiles.CurrentProfile
	}
	if profiles == nil {
		return name, nil, nil, nil
	}
	if profile, exists := profiles.Profiles[name]; exists {
		if profile == nil {
			return "", nil, nil, output.ErrValidation("selected profile is null", "check the CLI profile directory and config.json")
		}
		return name, profiles, profile, nil
	}
	if profiles.CurrentProfile == name {
		return "", nil, nil, output.ErrValidation("current_profile does not exist", "check the CLI profile directory and config.json")
	}
	return name, profiles, nil, nil
}
