package cmd

import (
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func runUnifiedAuthStatus(f *cmdutil.Factory, readToken func(*config.ProfileConfig, *config.TokenSource) (string, string, error)) error {
	if f.Globals.BotIDSet || f.Globals.BotID != "" {
		return failErr(f, output.ErrValidation("--bot-id cannot be used with unified credentials", "select a Profile with --profile or OCTO_PROFILE"))
	}
	name, profiles, profile, err := selectUnifiedStatusProfile(f)
	if err != nil {
		return failErr(f, err)
	}
	var runtime *config.Config
	status := "missing"
	var source, token string
	const maxAttempts = 3
	for attempt := 1; ; attempt++ {
		var target config.Profile
		if profile != nil {
			if profile.APIBaseURL == "" {
				return failErr(f, output.ErrValidation("profile token_source requires api_base_url", "set the API origin in the selected profile"))
			}
			target = *profile
		}
		runtime = config.LoadRuntime()
		if err := runtime.ApplyProfile(target, f.Globals.Space); err != nil {
			return failErr(f, output.ErrValidation(err.Error(), "check the profile, OCTO_API_BASE_URL and Space settings"))
		}
		if profile == nil {
			break
		}

		// Read only the selected reference. Runtime credentials cannot establish
		// that a stored Profile is usable.
		ref := profile.TokenSource
		source, token, err = readToken(profiles, ref)
		if err == nil {
			status = "readable"
			break
		}
		if attempt == maxAttempts {
			return failErr(f, err)
		}
		profiles, profile, err = reloadUnifiedStatusProfile(f, name, ref, err)
		if err != nil {
			return failErr(f, err)
		}
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

func reloadUnifiedStatusProfile(f *cmdutil.Factory, name string, ref *config.TokenSource, readErr error) (*config.ProfileConfig, *config.Profile, error) {
	if ref == nil || ref.Type != "managed_store" {
		return nil, nil, readErr
	}
	// Replacement publishes the new reference before removing the old entry.
	// Retry from the new snapshot only if the same Profile has a new reference.
	nextName, profiles, profile, err := selectUnifiedStatusProfile(f)
	if err != nil {
		return nil, nil, err
	}
	if nextName != name || profile == nil || profile.TokenSource == nil || *profile.TokenSource == *ref {
		return nil, nil, readErr
	}
	return profiles, profile, nil
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
	if current := profiles.CurrentProfile; current != "" && profiles.Profiles[current] == nil {
		return "", nil, nil, output.ErrValidation("current_profile must reference an existing, non-null profile", "check the CLI profile directory and config.json")
	}
	return name, profiles, nil, nil
}
