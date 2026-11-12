// Package config loads CLI configuration from environment variables.
// All backend services are accessed through a single API base URL
// (OCTO_API_BASE_URL).
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Environment variable names. Centralised for testability and discoverability.
const (
	EnvAPIBaseURL = "OCTO_API_BASE_URL"
	// EnvToken supplies the bearer for HTTP commands.
	EnvToken    = "OCTO_TOKEN"
	EnvBotToken = "OCTO_BOT_TOKEN"
	EnvSpaceID  = "OCTO_SPACE_ID"
	EnvFormat   = "OCTO_FORMAT"
	// DefaultAPIBaseURL is the production Octo gateway. Service operations
	// append their registered paths.
	DefaultAPIBaseURL = "https://im.deepminer.com.cn"
	// EnvBotID is the env form of --bot-id: a robot id that selects a stored
	// credential profile. It is a selector, not a secret (cf. EnvBotToken).
	EnvBotID = "OCTO_BOT_ID"
)

// Config holds settings for API requests and local profile inspection.
type Config struct {
	// APIBaseURL is the unified base URL for all backend services.
	// Set via OCTO_API_BASE_URL or the active profile's stored origin.
	APIBaseURL string
	// APIBaseURLSource reports where APIBaseURL came from: "profile", "env",
	// or "default". It makes the precedence rule observable in diagnostics.
	APIBaseURLSource string
	// BotToken is the active bearer credential.
	BotToken string
	// SpaceID is the platform-bot space context (OCTO_SPACE_ID). Optional for space-scoped bots.
	SpaceID string
	// Format is the default output format.
	Format string
}

// ResolvedEnvToken is the canonical credential value resolved at the process
// environment boundary. Callers use Token and Source without knowing which
// compatibility alias supplied it.
type ResolvedEnvToken struct {
	Token  string
	Source string
}

// Load reads configuration for local commands that still inspect bot profiles.
func Load() *Config {
	cfg := LoadRequest()
	cfg.BotToken = ResolveEnvToken().Token
	return cfg
}

// LoadRequest reads the gateway, output settings, and opaque bearer for HTTP commands.
func LoadRequest() *Config {
	apiBaseURL := os.Getenv(EnvAPIBaseURL)
	apiBaseURLSource := "env"
	if apiBaseURL == "" {
		apiBaseURL = DefaultAPIBaseURL
		apiBaseURLSource = "default"
	}
	return &Config{
		APIBaseURL:       apiBaseURL,
		APIBaseURLSource: apiBaseURLSource,
		BotToken:         os.Getenv(EnvToken),
		SpaceID:          os.Getenv(EnvSpaceID),
		Format:           envOrDefault(EnvFormat, "json"),
	}
}

// ResolveEnvToken selects the first nonempty token from the environment.
func ResolveEnvToken() ResolvedEnvToken {
	if v := strings.TrimSpace(os.Getenv(EnvToken)); v != "" {
		return ResolvedEnvToken{Token: v, Source: "env:" + EnvToken}
	}
	if v := strings.TrimSpace(os.Getenv(EnvBotToken)); v != "" {
		return ResolvedEnvToken{Token: v, Source: "env:" + EnvBotToken}
	}
	return ResolvedEnvToken{}
}

// Validate checks the bearer credential and normalizes the configured origin.
func (c *Config) Validate() error {
	if c.BotToken == "" {
		return fmt.Errorf("%s is required", EnvToken)
	}
	for i := 0; i < len(c.BotToken); i++ {
		if c.BotToken[i] <= ' ' || c.BotToken[i] == 0x7f {
			return fmt.Errorf("%s contains whitespace or control characters unsafe for a Bearer header", EnvToken)
		}
	}
	if c.APIBaseURL != "" {
		baseURL, err := NormalizeAPIBaseURL(c.APIBaseURL)
		if err != nil {
			return err
		}
		c.APIBaseURL = baseURL
	}
	return nil
}

// NormalizeAPIBaseURL validates the unified Octo gateway base URL. The CLI
// stores only the origin and appends module-qualified paths per operation.
func NormalizeAPIBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid %s", EnvAPIBaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s must use http or https", EnvAPIBaseURL)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%s must be an absolute base URL without credentials, query parameters, or fragments", EnvAPIBaseURL)
	}
	if strings.TrimRight(u.Path, "/") != "" {
		return "", fmt.Errorf("%s must not include a service or API path", EnvAPIBaseURL)
	}
	u.Path = ""
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
