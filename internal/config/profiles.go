package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Environment variables for versioned profile and file selection.
const (
	EnvConfigDir = "OCTO_CONFIG_DIR"
	EnvProfile   = "OCTO_PROFILE"
	EnvTokenFile = "OCTO_TOKEN_FILE"
)

// ProfileConfig is the versioned, non-secret business configuration.
type ProfileConfig struct {
	Version        json.RawMessage    `json:"version"`
	CurrentProfile string             `json:"current_profile"`
	Profiles       map[string]Profile `json:"profiles"`
	dir            string
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
	dir := os.Getenv(EnvConfigDir)
	override := dir != ""
	if !override {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		dir = filepath.Join(home, ".octo", "cli")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var cfg *ProfileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
		return nil, fmt.Errorf("invalid config.json")
	}
	if override && cfg.isLegacy() {
		return nil, nil
	}
	if string(cfg.Version) != "1" {
		return nil, fmt.Errorf("unsupported config.json version (expected 1)")
	}
	if cfg.Profiles == nil {
		return nil, fmt.Errorf("config.json must contain a profiles object")
	}
	cfg.dir = dir
	return cfg, nil
}

func (c *ProfileConfig) isLegacy() bool {
	if len(c.Version) != 0 || c.CurrentProfile != "" || c.Profiles == nil {
		return false
	}
	for _, p := range c.Profiles {
		if p.TokenSource != nil {
			return false
		}
	}
	return true
}

// ProfileSelector resolves the explicit selector independently of credentials.
func ProfileSelector(name string, flagSet bool) (selected, source string, envSet bool) {
	envName, envSet := os.LookupEnv(EnvProfile)
	if flagSet || name != "" {
		return name, "--profile", envSet
	}
	if envSet {
		return envName, EnvProfile, true
	}
	return "", "", false
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
			return name, p, nil
		}
	}
	return "", Profile{}, fmt.Errorf("selected profile does not exist")
}

// TokenFilePath resolves profile file references relative to config.json.
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
