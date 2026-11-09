package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// ProfileConfig is the versioned, non-secret business configuration.
type ProfileConfig struct {
	Version        json.RawMessage     `json:"version"`
	CurrentProfile string              `json:"current_profile"`
	Profiles       map[string]*Profile `json:"profiles"`
	dir            string
	file           string
	writeFile      string
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

func loadProfileConfigIn(dir string, allowLegacy, writable bool) (*ProfileConfig, error) {
	cfg, err, alternate := loadDedicatedProfileConfig(dir, writable)
	if cfg != nil || alternate {
		return cfg, err
	}
	old, oldErr := loadProfileConfigFile(dir, oldProfileFile, allowLegacy, writable)
	// A migration may publish the dedicated file while we read config.json.
	cfg, err, alternate = loadDedicatedProfileConfig(dir, writable)
	if cfg != nil || alternate {
		return cfg, err
	}
	primary := filepath.Join(dir, ManagedProfileFile)
	if old != nil && old.ReferencesTokenFile(primary) && (err == nil || isOpaqueProfileTokenFile(primary)) {
		// This path is an input to the v1 configuration. Keep it reserved
		// even if the external file is missing or is replaced later.
		old.writeFile = filepath.Join(profileCollisionDir, ManagedProfileFile)
		return old, nil
	}
	if err != nil {
		return nil, err
	}
	return old, oldErr
}

func isOpaqueProfileTokenFile(path string) bool {
	const limit = 64 * 1024
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > limit {
		return false
	}
	token := bytes.TrimSpace(raw)
	// A partial or unsupported JSON config remains a configuration error
	// even when the old metadata happens to reference its pathname.
	return len(token) != 0 && token[0] != '{' && token[0] != '[' &&
		bytes.IndexFunc(token, func(r rune) bool { return r < '!' || r > '~' }) < 0
}

func loadDedicatedProfileConfig(dir string, writable bool) (cfg *ProfileConfig, err error, alternate bool) {
	// A token can also occupy the alternate directory's name. Only a real
	// directory can contain a dedicated profile configuration there.
	info, err := os.Lstat(filepath.Join(dir, profileCollisionDir))
	if err == nil && info.IsDir() {
		name := filepath.Join(profileCollisionDir, ManagedProfileFile)
		cfg, err := loadProfileConfigFile(dir, name, false, writable)
		if cfg != nil || err != nil {
			return cfg, err, true
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err, true
	}
	cfg, err = loadProfileConfigFile(dir, ManagedProfileFile, false, writable)
	return cfg, err, false
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

	var cfg *ProfileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
		return nil, fmt.Errorf("invalid %s", name)
	}
	if allowLegacy && isLegacyProfileConfig(raw) {
		return nil, nil
	}
	if string(cfg.Version) != "1" {
		return nil, fmt.Errorf("unsupported %s version (expected 1)", name)
	}
	if cfg.Profiles == nil {
		return nil, fmt.Errorf("%s must contain a profiles object", name)
	}
	cfg.dir = dir
	cfg.file = name
	cfg.writeFile = name
	return cfg, nil
}

// Directory returns the directory from which this profile config was loaded.
func (c *ProfileConfig) Directory() string {
	return c.dir
}

// NeedsMigration reports whether this v1 configuration came from config.json.
func (c *ProfileConfig) NeedsMigration() bool { return c.file == oldProfileFile }

// WriteFile returns the dedicated path relative to the profile directory.
func (c *ProfileConfig) WriteFile() string {
	if c.writeFile == oldProfileFile || c.writeFile == "" {
		return ManagedProfileFile
	}
	return c.writeFile
}

// ReferencesTokenFile checks both direct paths and aliases of an existing file.
func (c *ProfileConfig) ReferencesTokenFile(path string) bool {
	target, targetErr := os.Stat(path)
	for _, p := range c.Profiles {
		if p == nil || p.TokenSource == nil || p.TokenSource.Type != "token_file" || p.TokenSource.Path == "" {
			continue
		}
		candidate := filepath.Clean(c.TokenFilePath(p.TokenSource.Path))
		if candidate == path {
			return true
		}
		if targetErr == nil {
			if info, err := os.Stat(candidate); err == nil && os.SameFile(target, info) {
				return true
			}
		}
	}
	return false
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
