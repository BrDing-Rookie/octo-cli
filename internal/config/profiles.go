package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Environment variables for versioned profile and file selection.
const (
	EnvConfigDir = "OCTO_CONFIG_DIR"
	EnvProfile   = "OCTO_PROFILE"
	EnvTokenFile = "OCTO_TOKEN_FILE"

	// ManagedProfileFile holds unified profiles, separate from the legacy Bot store.
	ManagedProfileFile  = "profiles.json"
	profileCollisionDir = ".octo-unified"
	oldProfileFile      = "config.json"
)

var errLegacyProfileConfig = errors.New("unsupported config.json version (expected 1)")

// ProfileConfig is the versioned, non-secret business configuration.
type ProfileConfig struct {
	Version        json.RawMessage     `json:"version"`
	CurrentProfile string              `json:"current_profile"`
	Profiles       map[string]*Profile `json:"profiles"`
	V1Retirement   *V1Retirement       `json:"v1_retirement,omitempty"`
	dir            string
	file           string
	fileInfo       os.FileInfo
	v1Digest       [sha256.Size]byte
}

// V1Retirement identifies the backup created by a published migration.
type V1Retirement struct {
	Backup string            `json:"backup"`
	Digest [sha256.Size]byte `json:"sha256"`
}

// Profile binds a request target to a credential reference.
type Profile struct {
	APIBaseURL  string       `json:"api_base_url"`
	SpaceID     string       `json:"space_id"`
	TokenSource *TokenSource `json:"token_source"`
}

// TokenSource references a file or a managed entry without storing a Token.
type TokenSource struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Backend string `json:"backend"`
	Entry   string `json:"entry"`
}

// LoadProfileConfig reads metadata only. An unversioned config in an
// explicitly supplied directory may belong to the legacy Bot CLI.
func LoadProfileConfig() (*ProfileConfig, error) {
	dir, override, err := ProfileDirectory()
	if err != nil {
		return nil, err
	}
	return LoadProfileConfigIn(dir, override)
}

// ProfileDirectory resolves the same configuration directory for reads and writes.
func ProfileDirectory() (dir string, override bool, err error) {
	dir = os.Getenv(EnvConfigDir)
	override = dir != ""
	if !override {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("resolve home directory: %w", err)
		}
		dir = filepath.Join(home, ".octo", "cli")
	}
	dir, err = filepath.Abs(dir)
	return dir, override, err
}

// LoadProfileConfigIn prefers the dedicated file and falls back to the original
// v1 location only before migration. A dedicated file is authoritative even if empty.
func LoadProfileConfigIn(dir string, allowLegacy bool) (*ProfileConfig, error) {
	return loadProfileConfigIn(dir, allowLegacy, false)
}

// LoadWritableProfileConfigIn rejects symlinked configuration before a mutation.
func LoadWritableProfileConfigIn(dir string, allowLegacy bool) (*ProfileConfig, error) {
	return loadProfileConfigIn(dir, allowLegacy, true)
}

func loadProfileConfigFile(dir, name string, allowLegacy, writable bool) (*ProfileConfig, error) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if writable {
			return nil, fmt.Errorf("cannot modify a symlinked profile configuration (%s)", name)
		}
		info, err = os.Stat(path)
		if err != nil {
			return nil, err
		}
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeProfileConfig(name, raw, allowLegacy)
	if cfg == nil || err != nil {
		return cfg, err
	}
	cfg.dir = dir
	cfg.file = name
	cfg.fileInfo = info
	if name == oldProfileFile {
		cfg.v1Digest = sha256.Sum256(raw)
	}
	return cfg, nil
}

func decodeProfileConfig(name string, raw []byte, allowLegacy bool) (*ProfileConfig, error) {
	var cfg *ProfileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
		return nil, fmt.Errorf("invalid %s", name)
	}
	if name == oldProfileFile && isLegacyProfileConfig(raw) {
		if allowLegacy {
			return nil, nil
		}
		return nil, errLegacyProfileConfig
	}
	if string(cfg.Version) != "1" {
		return nil, fmt.Errorf("unsupported %s version (expected 1)", name)
	}
	if cfg.Profiles == nil {
		return nil, fmt.Errorf("%s must contain a profiles object", name)
	}
	return cfg, nil
}

// Directory returns the directory from which this profile config was loaded.
func (c *ProfileConfig) Directory() string {
	return c.dir
}

// NeedsMigration reports whether this v1 configuration came from config.json.
func (c *ProfileConfig) NeedsMigration() bool { return c.file == oldProfileFile }

// MatchesV1Source verifies that a migration still has the v1 file it loaded.
func (c *ProfileConfig) MatchesV1Source(info os.FileInfo, raw []byte) bool {
	return c.NeedsMigration() && c.fileInfo != nil &&
		os.SameFile(c.fileInfo, info) && c.v1Digest == sha256.Sum256(raw)
}

// WriteFile returns the loaded metadata path relative to the store.
func (c *ProfileConfig) WriteFile() string { return c.file }

// IsPublished reports whether this configuration has an owned location.
func (c *ProfileConfig) IsPublished() bool {
	return strings.HasPrefix(filepath.Dir(c.file), OwnedProfileDirPrefix)
}

// SetPublishedFile records a newly published metadata path for this mutation.
func (c *ProfileConfig) SetPublishedFile(name string) { c.file = name }

// ReferencesTokenFile checks direct paths, file aliases and missing symlink
// targets. Previous profiles can be included when checking mutation cleanup.
func (c *ProfileConfig) ReferencesTokenFile(path string, previous ...*Profile) (bool, error) {
	const unknownAlias = "cannot determine whether a Token file aliases the managed configuration"
	target, targetErr := os.Stat(path)
	var unresolved error
	profiles := slices.AppendSeq(slices.Clone(previous), maps.Values(c.Profiles))
	for _, p := range profiles {
		if p == nil || p.TokenSource == nil || p.TokenSource.Type != "token_file" || p.TokenSource.Path == "" {
			continue
		}
		candidate := c.TokenFilePath(p.TokenSource.Path)
		if filepath.Clean(candidate) == filepath.Clean(path) {
			return true, nil
		}
		if info, err := os.Stat(candidate); err == nil && targetErr == nil {
			if os.SameFile(target, info) {
				return true, nil
			}
			continue
		}
		if strings.Contains(filepath.ToSlash(candidate)+"/", "/../") {
			unresolved = errors.New(unknownAlias)
			continue
		}
		resolved, err := resolveMissingTokenPath(candidate)
		destination, destinationErr := resolveMissingTokenPath(path)
		if err != nil || destinationErr != nil {
			unresolved = errors.New(unknownAlias)
			continue
		}
		// Be conservative on case-insensitive volumes when an inode is missing.
		if strings.EqualFold(resolved, destination) {
			return true, nil
		}
	}
	return false, unresolved
}

// resolveMissingTokenPath follows the nearest existing prefix when the final
// target is missing. Lstat can still find and follow a dangling link itself.
func resolveMissingTokenPath(path string) (string, error) {
	for range 40 {
		prefix, tail, link, err := tokenPathPrefix(path)
		if err != nil || !link {
			return filepath.Join(prefix, tail), err
		}
		path = filepath.Join(prefix, tail)
	}
	return "", errors.New("too many Token file symlinks")
}

func tokenPathPrefix(path string) (resolved, tail string, link bool, err error) {
	for prefix := path; ; prefix = filepath.Dir(prefix) {
		info, err := os.Lstat(prefix)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(prefix)
			if err != nil {
				return "", "", false, err
			}
			// Leading .. components are relative to the real parent. A ..
			// after another component could cross a link we cannot resolve.
			rest := filepath.ToSlash(target)
			for strings.HasPrefix(rest, "../") {
				rest = strings.TrimPrefix(rest, "../")
			}
			if strings.Contains(rest+"/", "/../") {
				return "", "", false, errors.New("ambiguous parent in Token file symlink")
			}
			if !filepath.IsAbs(target) {
				parent, err := filepath.EvalSymlinks(filepath.Dir(prefix))
				if err != nil {
					return "", "", false, err
				}
				target = filepath.Join(parent, target)
			}
			return target, tail, true, nil
		}
		if err == nil {
			resolved, err := filepath.EvalSymlinks(prefix)
			return resolved, tail, false, err
		}
		if !os.IsNotExist(err) || filepath.Dir(prefix) == prefix {
			return "", "", false, err
		}
		tail = filepath.Join(filepath.Base(prefix), tail)
	}
}

func isLegacyProfileConfig(raw []byte) bool {
	// Recognize the fields written by the Bot store. A malformed unversioned
	// versioned-store file must not be interpreted as an absent credential.
	var legacy struct {
		Profiles map[string]*struct {
			APIBaseURL string `json:"api_base_url"`
			SpaceID    string `json:"space_id"`
			RobotID    string `json:"robot_id"`
			BotKind    string `json:"bot_kind"`
			CreatedAt  string `json:"created_at"`
		} `json:"profiles"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&legacy); err != nil || legacy.Profiles == nil {
		return false
	}
	for _, p := range legacy.Profiles {
		if p == nil || (p.RobotID == "" && p.BotKind == "" && p.CreatedAt == "") {
			return false
		}
	}
	return true
}

// UsesUnifiedCredentials checks the mode before selecting a credential store.
func (c *Config) UsesUnifiedCredentials(credentialFileSet bool) (bool, error) {
	switch c.CredentialMode {
	case CredentialModeUnified:
		return true, nil
	case CredentialModeTask:
		return false, nil
	case "":
		_, profileSet := os.LookupEnv(EnvProfile)
		_, tokenFileSet := os.LookupEnv(EnvTokenFile)
		return credentialFileSet || profileSet || tokenFileSet, nil
	default:
		return false, fmt.Errorf("unsupported %s %q", EnvCredentialMode, c.CredentialMode)
	}
}

// ProfileSelector resolves the explicit selector independently of credentials.
func ProfileSelector(name string, flagSet bool) (selected, source string) {
	if flagSet || name != "" {
		return name, "--profile"
	}
	if envName, ok := os.LookupEnv(EnvProfile); ok {
		return envName, EnvProfile
	}
	return "", ""
}

// SelectProfile returns the requested profile or the configured default.
func (c *ProfileConfig) SelectProfile(name string, explicit bool) (string, Profile, error) {
	if !explicit && c != nil {
		name = c.CurrentProfile
	}
	if name == "" && !explicit {
		return "", Profile{}, nil
	}
	if c != nil && name != "" {
		if p, ok := c.Profiles[name]; ok {
			if p == nil {
				return "", Profile{}, fmt.Errorf("selected profile is null")
			}
			return name, *p, nil
		}
	}
	return "", Profile{}, fmt.Errorf("selected profile does not exist")
}

// TokenFilePath resolves profile file references relative to the config directory.
func (c *ProfileConfig) TokenFilePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.dir, path)
}

// ApplyProfile validates the request target without inspecting any token.
func (c *Config) ApplyProfile(p Profile, spaceFlag string) error {
	if p.APIBaseURL != "" {
		c.APIBaseURL = p.APIBaseURL
		c.APIBaseURLSource = "profile"
	}
	origin, err := NormalizeAPIBaseURL(c.APIBaseURL)
	if err != nil {
		return fmt.Errorf("invalid API base URL from %s; expected an HTTP(S) origin", c.APIBaseURLSource)
	}
	c.APIBaseURL = origin
	if spaceFlag != "" {
		c.SpaceID = spaceFlag
	}
	if p.SpaceID != "" {
		if c.SpaceID != "" && c.SpaceID != p.SpaceID {
			return fmt.Errorf("requested Space does not match the selected profile")
		}
		c.SpaceID = p.SpaceID
	}
	for _, ch := range c.SpaceID {
		if ch < '!' || ch > '~' {
			return fmt.Errorf("invalid Space ID")
		}
	}
	return nil
}
