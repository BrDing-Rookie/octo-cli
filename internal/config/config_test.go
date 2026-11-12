package config

import (
	"strings"
	"testing"
)

func TestValidate_MissingToken(t *testing.T) {
	c := &Config{APIBaseURL: "http://localhost", BotToken: ""}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing environment credential")
	}
}

func TestValidate_OK(t *testing.T) {
	c := &Config{APIBaseURL: "http://localhost/", BotToken: "app_xxx"}
	if err := c.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if c.APIBaseURL != "http://localhost" {
		t.Fatalf("APIBaseURL = %q", c.APIBaseURL)
	}
}

func TestValidate_RejectsServicePathAsBaseURL(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.invalid/service",
		"https://api.example.invalid/v1/records",
		"https://im-test.deepminer.com.cn?",
		"ws://im-test.deepminer.com.cn",
	} {
		c := &Config{APIBaseURL: raw, BotToken: "app_xxx"}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted %q", raw)
		}
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvBotToken, "")
	t.Setenv(EnvAPIBaseURL, "")
	t.Setenv(EnvFormat, "")
	t.Setenv(EnvSpaceID, "")

	cfg := Load()
	if cfg.APIBaseURL != DefaultAPIBaseURL {
		t.Errorf("APIBaseURL = %q, want default", cfg.APIBaseURL)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
}

func TestLoad_ReadsAllEnvVars(t *testing.T) {
	t.Setenv(EnvAPIBaseURL, "http://api.example")
	// EnvToken outranks EnvBotToken, so it must be cleared for this case to
	// exercise the EnvBotToken path rather than an exported real token.
	t.Setenv(EnvToken, "")
	t.Setenv(EnvBotToken, "app_xxx")
	t.Setenv(EnvSpaceID, "space-1")
	t.Setenv(EnvFormat, "table")

	cfg := Load()
	if cfg.APIBaseURL != "http://api.example" {
		t.Errorf("APIBaseURL = %q", cfg.APIBaseURL)
	}
	if cfg.BotToken != "app_xxx" {
		t.Errorf("BotToken = %q", cfg.BotToken)
	}
	if cfg.SpaceID != "space-1" {
		t.Errorf("SpaceID = %q", cfg.SpaceID)
	}
	if cfg.Format != "table" {
		t.Errorf("Format = %q", cfg.Format)
	}
}

// OCTO_TOKEN is the canonical high-priority alias. Both aliases accept the same
// credential kinds; only their precedence and reported source differ.
func TestResolveEnvTokenPrecedence(t *testing.T) {
	cases := []struct {
		name, octoToken, botToken, want, wantSource string
	}{
		{"only the legacy variable", "", "bf_bot", "bf_bot", "env:" + EnvBotToken},
		{"only the canonical variable", "uk_person", "", "uk_person", "env:" + EnvToken},
		{"both set: canonical wins", "uk_person", "bf_bot", "uk_person", "env:" + EnvToken},
		{"a blank canonical variable does not shadow", "   ", "bf_bot", "bf_bot", "env:" + EnvBotToken},
		{"neither set", "", "", "", ""},
		// Both variables are trimmed, symmetrically. An untrimmed OCTO_BOT_TOKEN
		// holding only whitespace used to pass Validate here and then resolve to no
		// credential in credential.EnvProvider, which trims both — an auth failure
		// two layers away from its cause.
		{"a whitespace-only legacy variable is no credential", "", "   ", "", ""},
		{"a whitespace-only legacy variable with a tab", "", "\t\n", "", ""},
		{"surrounding whitespace is stripped from the legacy variable", "", "  bf_bot\n", "bf_bot", "env:" + EnvBotToken},
		{"surrounding whitespace is stripped from the canonical variable", "  uk_person\n", "", "uk_person", "env:" + EnvToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvToken, tc.octoToken)
			t.Setenv(EnvBotToken, tc.botToken)
			got := ResolveEnvToken()
			if got.Token != tc.want || got.Source != tc.wantSource {
				t.Errorf("ResolveEnvToken() = %+v, want token %q source %q", got, tc.want, tc.wantSource)
			}
		})
	}
}

func TestValidate_MessageNamesRequestToken(t *testing.T) {
	err := (&Config{}).Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), EnvToken) || strings.Contains(err.Error(), EnvBotToken) {
		t.Errorf("Validate message %q should name only %s", err.Error(), EnvToken)
	}
}

func TestLoad_TokenPrecedence(t *testing.T) {
	cases := []struct {
		name, octoToken, botToken, want string
	}{
		{"only the legacy variable", "", "bf_bot", "bf_bot"},
		{"only the new variable", "uk_person", "", "uk_person"},
		{"both set: the new one wins", "uk_person", "bf_bot", "uk_person"},
		{"a blank new variable does not shadow", "   ", "bf_bot", "bf_bot"},
		{"neither set", "", "", ""},
		// Both variables are trimmed, symmetrically. An untrimmed OCTO_BOT_TOKEN
		// holding only whitespace used to pass Validate here and then resolve to no
		// credential in credential.EnvProvider, which trims both — an auth failure
		// two layers away from its cause.
		{"a whitespace-only legacy variable is no credential", "", "   ", ""},
		{"a whitespace-only legacy variable with a tab", "", "\t\n", ""},
		{"surrounding whitespace is stripped from the legacy variable", "", "  bf_bot\n", "bf_bot"},
		{"surrounding whitespace is stripped from the new variable", "  uk_person\n", "", "uk_person"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvToken, tc.octoToken)
			t.Setenv(EnvBotToken, tc.botToken)
			if got := Load().BotToken; got != tc.want {
				t.Errorf("BotToken = %q, want %q", got, tc.want)
			}
		})
	}
}
