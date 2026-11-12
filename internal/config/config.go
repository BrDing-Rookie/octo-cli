// Package config loads runtime settings and validates API origins.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
)

// Environment variable names and the default business gateway.
const (
	EnvAPIBaseURL     = "OCTO_API_BASE_URL"
	EnvToken          = "OCTO_TOKEN"
	EnvTokenFile      = "OCTO_TOKEN_FILE"
	EnvProfile        = "OCTO_PROFILE"
	EnvSpaceID        = "OCTO_SPACE_ID"
	EnvFormat         = "OCTO_FORMAT"
	EnvAuthCurrentURL = "OCTO_AUTH_CURRENT_URL"
	DefaultAPIBaseURL = "https://im.deepminer.com.cn"
)

// Config holds the resolved business target, credential, and output format.
type Config struct {
	APIBaseURL       string
	APIBaseURLSource string
	Token            string
	SpaceID          string
	Format           string
}

// LoadRequest reads settings that are independent of credential selection.
func LoadRequest() *Config {
	apiBaseURL := os.Getenv(EnvAPIBaseURL)
	source := "env"
	if apiBaseURL == "" {
		apiBaseURL = DefaultAPIBaseURL
		source = "default"
	}
	return &Config{
		APIBaseURL:       apiBaseURL,
		APIBaseURLSource: source,
		SpaceID:          strings.TrimSpace(os.Getenv(EnvSpaceID)),
		Format:           DefaultFormat(),
	}
}

// DefaultFormat reads the output format without resolving a profile.
func DefaultFormat() string {
	if format := os.Getenv(EnvFormat); format != "" {
		return format
	}
	return "json"
}

// Validate checks the Bearer and normalizes the configured origin.
func (c *Config) Validate() error {
	if err := credential.ValidateBearer(c.Token); err != nil {
		return fmt.Errorf("%s: %w", EnvToken, err)
	}
	baseURL, err := NormalizeAPIBaseURL(c.APIBaseURL)
	if err != nil {
		return err
	}
	c.APIBaseURL = baseURL
	return nil
}

// NormalizeAPIBaseURL validates the gateway URL and returns its origin.
func NormalizeAPIBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid %s", EnvAPIBaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s must use http or https", EnvAPIBaseURL)
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", fmt.Errorf("%s must be an absolute base URL without credentials, query parameters, or fragments", EnvAPIBaseURL)
	}
	if strings.TrimRight(u.Path, "/") != "" {
		return "", fmt.Errorf("%s must not include a service or API path", EnvAPIBaseURL)
	}

	return (&url.URL{Scheme: u.Scheme, Host: canonicalHost(u)}).String(), nil
}

func canonicalHost(u *url.URL) string {
	host, zone, hasZone := strings.Cut(u.Hostname(), "%")
	host = strings.ToLower(host)
	if hasZone {
		host += "%" + zone
	}
	port := u.Port()
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host
}
