package credential

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

// BusinessContext is the unified bearer and its target for one invocation.
// It does not encode a Bot identity or infer an execution principal.
type BusinessContext struct {
	Token            string
	Source           string
	Profile          string
	APIBaseURL       string
	APIBaseURLSource string
	SpaceID          string
}

// BusinessOptions contains explicit command-line selectors.
type BusinessOptions struct {
	Profile, File, Space string
	ProfileSet, FileSet  bool
}

// ResolveBusiness reads the profile and bearer once. A nil result leaves
// existing, unversioned Bot installations on their legacy path until the
// unified business routes are released.
func ResolveBusiness(runtime *config.Config, opts BusinessOptions) (*BusinessContext, error) {
	if runtime.CredentialMode != "" {
		return nil, nil
	}
	token, tokenSet := os.LookupEnv(config.EnvToken)
	tokenFile, tokenFileSet := os.LookupEnv(config.EnvTokenFile)
	profileName, selector, profileEnvSet := config.ProfileSelector(opts.Profile, opts.ProfileSet)
	if selector != "" && profileName == "" {
		return nil, output.ErrValidation(selector+" is empty", "select an existing profile name")
	}
	newSelector := opts.FileSet || tokenFileSet || profileEnvSet
	unified := newSelector || TokenKind(strings.TrimSpace(token)) == "unknown"
	if tokenSet && tokenFileSet {
		return nil, output.ErrValidation("OCTO_TOKEN and OCTO_TOKEN_FILE are both set", "set only one of these environment variables")
	}

	profiles, err := loadBusinessProfiles(unified, selector != "")
	if err != nil {
		return nil, err
	}
	if profiles == nil && !unified {
		return nil, nil
	}
	name, p, err := profiles.SelectProfile(profileName, selector != "")
	if err != nil {
		return nil, output.ErrValidation(err.Error(), "check octo-cli auth list and the profile selector")
	}
	if err := runtime.ApplyProfile(p, opts.Space); err != nil {
		return nil, output.ErrValidation(err.Error(), "check the profile, OCTO_API_BASE_URL and Space settings")
	}

	source, token, err := resolveBusinessToken(opts, token, tokenSet, tokenFile, tokenFileSet, profiles, p.TokenSource)
	if err != nil {
		return nil, err
	}

	return &BusinessContext{
		Token: token, Source: source, Profile: name, SpaceID: runtime.SpaceID,
		APIBaseURL: runtime.APIBaseURL, APIBaseURLSource: runtime.APIBaseURLSource,
	}, nil
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
		source, token, err = profileToken(profiles, ref)
	}
	if err != nil {
		return "", "", err
	}
	token = strings.TrimSpace(token)
	if !validBusinessToken(token) {
		return "", "", output.ErrAuth("invalid unified Token from "+source, "provide a non-empty unified Token without whitespace; legacy credentials are not accepted")
	}
	return source, token, nil
}

func loadBusinessProfiles(unified, explicitProfile bool) (*config.ProfileConfig, error) {
	profiles, err := config.LoadProfileConfig()
	if err == nil {
		return profiles, nil
	}
	// Legacy environment credentials can run without a local profile directory.
	if !unified && !explicitProfile && errors.Is(err, syscall.ENOTDIR) && config.ResolveEnvToken().Token != "" {
		return nil, nil
	}
	return nil, ProfileConfigError(err)
}

// ProfileConfigError reports a metadata error without echoing file contents.
func ProfileConfigError(err error) error {
	message := "cannot read config.json"
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		message = err.Error()
	}
	return output.ErrValidation(message, "check the CLI profile directory and config.json")
}

func profileToken(profiles *config.ProfileConfig, ref *config.TokenSource) (source, token string, err error) {
	switch {
	case ref == nil:
		return "", "", output.ErrAuth("no unified credential configured", "set OCTO_TOKEN or OCTO_TOKEN_FILE, or select a configured profile")
	case ref.Type == "token_file" && ref.Backend == "" && ref.Entry == "":
		return fileToken("profile:token_file", profiles.TokenFilePath(ref.Path))
	case ref.Type == "managed_store" && ref.Path == "" && ref.Entry != "" &&
		(ref.Backend == "keychain" || ref.Backend == "encrypted_file"):
		return "", "", output.ErrAuth("managed credential storage is unavailable", "use an external Token file or environment credential")
	default:
		return "", "", output.ErrValidation("invalid profile token_source", "check the type and reference in config.json")
	}
}

func fileToken(source, path string) (selectedSource, token string, err error) {
	token, err = readBusinessTokenFile(path)
	if err != nil {
		return "", "", output.ErrAuth("cannot read credential from "+source, "check that the selected credential file exists, is a regular file, and is readable")
	}
	return source, token, nil
}

func validBusinessToken(token string) bool {
	return TokenKind(token) == "unknown" && !strings.ContainsFunc(token, func(r rune) bool { return r < '!' || r > '~' })
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
