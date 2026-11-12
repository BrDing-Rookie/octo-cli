package config

import (
	"strings"
	"testing"
)

func TestValidate_MissingToken(t *testing.T) {
	c := &Config{APIBaseURL: "http://localhost", Token: ""}
	if err := c.Validate(); err == nil {
		t.Error("expected error for missing environment credential")
	}
}

func TestValidate_OK(t *testing.T) {
	c := &Config{APIBaseURL: "http://localhost/", Token: "app_xxx"}
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
		c := &Config{APIBaseURL: raw, Token: "app_xxx"}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted %q", raw)
		}
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv(EnvAPIBaseURL, "")
	t.Setenv(EnvFormat, "")
	t.Setenv(EnvSpaceID, "")

	cfg := LoadRequest()
	if cfg.APIBaseURL != DefaultAPIBaseURL {
		t.Errorf("APIBaseURL = %q, want default", cfg.APIBaseURL)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
}

func TestLoad_ReadsAllEnvVars(t *testing.T) {
	t.Setenv(EnvAPIBaseURL, "http://api.example")
	t.Setenv(EnvSpaceID, "space-1")
	t.Setenv(EnvFormat, "table")

	cfg := LoadRequest()
	if cfg.APIBaseURL != "http://api.example" {
		t.Errorf("APIBaseURL = %q", cfg.APIBaseURL)
	}
	if cfg.SpaceID != "space-1" {
		t.Errorf("SpaceID = %q", cfg.SpaceID)
	}
	if cfg.Format != "table" {
		t.Errorf("Format = %q", cfg.Format)
	}
}

func TestValidate_MessageNamesRequestToken(t *testing.T) {
	err := (&Config{}).Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), EnvToken) || strings.Contains(err.Error(), "OCTO_BOT_TOKEN") {
		t.Errorf("Validate message %q should name only %s", err.Error(), EnvToken)
	}
}
