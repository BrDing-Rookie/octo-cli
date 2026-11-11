package credential

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

var errManagedCredentialMissing = errors.New("managed credential entry is missing")

// BusinessContext is the unified bearer and its target for one invocation.
// It does not encode a Bot identity or infer an execution principal.
type BusinessContext struct {
	Token      string
	Source     string
	Profile    string
	APIBaseURL string
	SpaceID    string
}

// BusinessOptions contains explicit command-line selectors.
type BusinessOptions struct {
	Profile, File, Space string
	ProfileSet, FileSet  bool
	BotIDSet             bool
}

// ResolveBusiness reads the profile and bearer once for an opted-in command.
// A nil result leaves credential selection to the legacy command path.
func ResolveBusiness(runtime *config.Config, opts BusinessOptions) (*BusinessContext, error) {
	unified, err := runtime.UsesUnifiedCredentials(opts.FileSet)
	if err != nil || !unified {
		return nil, err
	}
	if opts.BotIDSet {
		return nil, output.ErrValidation("--bot-id cannot be used with unified credentials", "select a Profile or remove --bot-id")
	}
	token, tokenSet := os.LookupEnv(config.EnvToken)
	tokenFile, tokenFileSet := os.LookupEnv(config.EnvTokenFile)
	if tokenSet && tokenFileSet {
		return nil, output.ErrValidation("OCTO_TOKEN and OCTO_TOKEN_FILE are both set", "set only one of these environment variables")
	}

	external := opts.FileSet || tokenSet || tokenFileSet
	profiles, name, p, err := selectBusinessProfile(opts, external)
	if err != nil {
		return nil, err
	}
	target := *runtime
	if err := applyBusinessProfile(&target, opts, p, external); err != nil {
		return nil, err
	}

	source, token, err := resolveBusinessToken(opts, token, tokenSet, tokenFile, tokenFileSet, profiles, p.TokenSource)
	if errors.Is(err, errManagedCredentialMissing) {
		return resolveRotatedBusinessProfile(runtime, opts, name, p.TokenSource, err)
	}
	if err != nil {
		return nil, err
	}

	*runtime = target
	return &BusinessContext{
		Token: token, Source: source, Profile: name, SpaceID: runtime.SpaceID,
		APIBaseURL: runtime.APIBaseURL,
	}, nil
}

func applyBusinessProfile(runtime *config.Config, opts BusinessOptions, p config.Profile, external bool) error {
	if !external && p.TokenSource != nil && p.APIBaseURL == "" {
		return output.ErrValidation("profile token_source requires api_base_url", "set the API origin in the selected profile")
	}
	if err := runtime.ApplyProfile(p, opts.Space); err != nil {
		return output.ErrValidation(err.Error(), "check the profile, OCTO_API_BASE_URL and Space settings")
	}
	return nil
}

func resolveRotatedBusinessProfile(runtime *config.Config, opts BusinessOptions, name string, old *config.TokenSource, readErr error) (*BusinessContext, error) {
	// The writer can delete the old entry between our metadata and secret
	// reads. Retry once, only for a new managed reference on the same profile.
	profiles, selected, p, err := selectBusinessProfile(opts, false)
	if err != nil || selected != name || p.TokenSource == nil || p.TokenSource.Type != "managed_store" || *p.TokenSource == *old {
		return nil, readErr
	}
	target := *runtime
	if err := applyBusinessProfile(&target, opts, p, false); err != nil {
		return nil, err
	}
	source, token, err := ReadProfileToken(profiles, p.TokenSource)
	if err != nil {
		return nil, err
	}
	*runtime = target
	return &BusinessContext{
		Token: token, Source: source, Profile: name, SpaceID: target.SpaceID,
		APIBaseURL: target.APIBaseURL,
	}, nil
}

func selectBusinessProfile(opts BusinessOptions, external bool) (profiles *config.ProfileConfig, name string, profile config.Profile, err error) {
	selected, selector := config.ProfileSelector(opts.Profile, opts.ProfileSet)
	// Standalone credentials use only the runtime target.
	if external && selector == "" {
		return nil, "", config.Profile{}, nil
	}
	if selector != "" && selected == "" {
		return nil, "", config.Profile{}, output.ErrValidation(selector+" is empty", "select an existing profile name")
	}
	profiles, err = config.LoadProfileConfig()
	if err != nil {
		return nil, "", config.Profile{}, ProfileConfigError(err)
	}
	name, profile, err = profiles.SelectProfile(selected, selector != "")
	if err != nil {
		return nil, "", config.Profile{}, output.ErrValidation(err.Error(), "check octo-cli auth list and the profile selector")
	}
	return profiles, name, profile, nil
}

func resolveBusinessToken(opts BusinessOptions, envToken string, tokenSet bool, tokenFile string, tokenFileSet bool, profiles *config.ProfileConfig, ref *config.TokenSource) (source, token string, err error) {
	source, token = "env:"+config.EnvToken, envToken
	switch {
	case opts.FileSet:
		source, token, err = fileToken("flag:--credential-file", opts.File)
	case tokenSet:
	case tokenFileSet:
		source, token, err = fileToken("env:"+config.EnvTokenFile, tokenFile)
	default:
		return ReadProfileToken(profiles, ref)
	}
	if err != nil {
		return "", "", err
	}
	token = strings.TrimSpace(token)
	if err := ValidateBusinessToken(token, source); err != nil {
		return "", "", err
	}
	return source, token, nil
}

// ValidateBusinessToken applies the unified credential format guard to an
// already-trimmed token. Source must be a fixed diagnostic label.
func ValidateBusinessToken(token, source string) error {
	if !validBusinessToken(token) {
		return output.ErrAuth("invalid unified Token from "+source, "provide a non-empty Token without whitespace")
	}
	// Legacy formats are rejected after selecting unified mode and its source.
	if TokenKind(token) != "unknown" || strings.HasPrefix(token, "omb_") {
		return output.ErrAuth("legacy Token from "+source+" cannot be used with unified credentials", "provide a unified Token or use the legacy credential mode")
	}
	return nil
}

// ProfileConfigError reports a metadata error without echoing file contents.
func ProfileConfigError(err error) error {
	message := "cannot read config.json"
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		message = err.Error()
	} else if filepath.Base(pathErr.Path) == config.ManagedProfileFile {
		message = "cannot read " + config.ManagedProfileFile
	}
	return output.ErrValidation(message, "check profiles.json or the original v1 config.json in the CLI profile directory")
}

// ReadProfileToken reads and validates the Profile source without applying
// environment or flag overrides. A broken configured reference is an error.
func ReadProfileToken(profiles *config.ProfileConfig, ref *config.TokenSource) (source, token string, err error) {
	switch {
	case ref == nil:
		return "", "", output.ErrAuth("no unified credential configured", "set OCTO_TOKEN or OCTO_TOKEN_FILE, or select a configured profile")
	case ref.Type == "token_file" && ref.Backend == "" && ref.Entry == "":
		source, token, err = fileToken("profile:token_file", profiles.TokenFilePath(ref.Path))
	case ref.Type == "managed_store":
		source = "profile:managed_store"
		token, err = authstore.ReadManagedToken(profiles, ref)
		if err != nil {
			authErr := output.ErrAuth("cannot read credential from "+source, "check the selected profile and managed credential store")
			if errors.Is(err, os.ErrNotExist) {
				return "", "", errors.Join(authErr, errManagedCredentialMissing)
			}
			return "", "", authErr
		}
	default:
		return "", "", output.ErrValidation("invalid profile token_source", "check the type and reference in the selected profile")
	}
	if err != nil {
		return "", "", err
	}
	token = strings.TrimSpace(token)
	if err := ValidateBusinessToken(token, source); err != nil {
		return "", "", err
	}
	return source, token, nil
}

func fileToken(source, path string) (selectedSource, token string, err error) {
	token, err = readBusinessTokenFile(path)
	if err != nil {
		return "", "", output.ErrAuth("cannot read credential from "+source, "check that the selected credential file exists, is a regular file, and is readable")
	}
	return source, token, nil
}

func validBusinessToken(token string) bool {
	return token != "" && !strings.ContainsFunc(token, func(r rune) bool { return r < '!' || r > '~' })
}

func readBusinessTokenFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	const limit = 64 * 1024
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("invalid credential file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if len(raw) > limit {
		return "", errors.New("credential file exceeds size limit")
	}
	return string(raw), errors.Join(readErr, closeErr)
}
