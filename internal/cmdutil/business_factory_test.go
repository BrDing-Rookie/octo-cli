package cmdutil

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
)

func TestFactory_ClientResolvesUnifiedCredentialLazily(t *testing.T) {
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	t.Setenv(config.EnvToken, "unified-lazy-bearer")
	t.Setenv(config.EnvAPIBaseURL, "https://unified.example")
	t.Setenv(config.EnvSpaceID, "unified-space")
	f := NewDefaultFactory()
	f.Globals.DryRun = true

	cli, err := f.Client()
	if err != nil {
		t.Fatalf("Client must resolve unified credentials without a root pre-run: %v", err)
	}
	raw, err := cli.Do(context.Background(), &client.Request{Method: http.MethodGet, Path: "/check"})
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request.URL != "https://unified.example/check" || request.Headers["X-Space-Id"] != "unified-space" {
		t.Fatalf("request target = %+v, want the unified origin and Space", request)
	}
	if got := f.RedactUnifiedBearer("value=unified-lazy-bearer"); got != "value=***REDACTED***" {
		t.Fatalf("resolved bearer was not available to diagnostics: %q", got)
	}
}

func TestFactory_BusinessCredentialInjectionUpdatesDiagnostics(t *testing.T) {
	f := NewDefaultFactory()
	want := &credential.BusinessContext{
		Token: "injected-bearer", Source: "test-provider", Profile: "injected-profile",
		APIBaseURL: "https://injected.example", SpaceID: "injected-space",
	}
	f.BusinessCredentialFunc = func() (*credential.BusinessContext, error) { return want, nil }
	got, err := f.BusinessCredential()
	if err != nil || got != want {
		t.Fatalf("BusinessCredential = %v, %v; want injected context", got, err)
	}
	id, ok := f.identityValue().(map[string]any)
	if !ok || id["type"] != "token" || id["source"] != want.Source || id["profile"] != want.Profile {
		t.Fatalf("identity = %v, want injected unified identity", f.identityValue())
	}
	if got := f.RedactUnifiedBearer("value=injected-bearer"); got != "value=***REDACTED***" {
		t.Fatalf("injected bearer was not available to diagnostics: %q", got)
	}
}

func TestFactory_ClientReturnsUnifiedProviderError(t *testing.T) {
	f := NewDefaultFactory()
	want := errors.New("selected unified credential is unavailable")
	f.BusinessCredentialFunc = func() (*credential.BusinessContext, error) { return nil, want }
	f.ConfigFunc = func() (*config.Config, error) {
		t.Fatal("unified provider failure must not fall back to legacy configuration")
		return nil, nil
	}
	if _, err := f.Client(); !errors.Is(err, want) {
		t.Fatalf("Client error = %v, want the selected provider error", err)
	}
}
