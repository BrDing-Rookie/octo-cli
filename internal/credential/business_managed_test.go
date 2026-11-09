package credential

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

func TestBusinessOriginUsesPublishedProfileDespiteExternalJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv(config.EnvToken, "environment-test-bearer")
	t.Setenv(config.EnvTokenFile, "")
	if err := os.Unsetenv(config.EnvTokenFile); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(external, []byte(`{"version":1,"profiles":{"work":{"api_base_url":"https://untrusted.example","space_id":"S1"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, config.ManagedProfileFile)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create Windows Token symlink: %v", err)
		}
		t.Fatal(err)
	}
	previous := filepath.Join(dir, ".octo-unified", config.ManagedProfileFile)
	if err := os.MkdirAll(filepath.Dir(previous), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, []byte(`{"version":1,"profiles":{"work":{"api_base_url":"https://trusted.example","space_id":"S1","token_source":{"type":"token_file","path":"profiles.json"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := BusinessOptions{Profile: "work", ProfileSet: true}
	settings := &config.Config{CredentialMode: config.CredentialModeUnified}
	assertTrusted := func() {
		t.Helper()
		got, err := ResolveBusiness(settings, opts)
		if err != nil || got == nil || got.APIBaseURL != "https://trusted.example" || got.Token != "environment-test-bearer" {
			t.Fatalf("explicit profile must retain the trusted origin: %v", err)
		}
	}
	assertTrusted()
	store := authstore.NewManagedStore(dir, nil)
	snap, err := store.Snapshot("work", true)
	if err != nil || !snap.Exists {
		t.Fatalf("select historical alternate: %v", err)
	}
	if result, err := store.ConfirmTarget(snap, "https://trusted.example"); err != nil || result.CleanupWarning != "" {
		t.Fatalf("publish managed ownership: %#v, %v", result, err)
	}
	assertTrusted()
	cfg, err := config.LoadProfileConfig()
	if err != nil || cfg == nil || !cfg.IsPublished() {
		t.Fatalf("read owned layout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cfg.WriteFile()), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveBusiness(settings, opts); got != nil || err == nil {
		t.Fatal("damaged owned metadata must not fall back to the previous layout or external JSON")
	}
}

func TestResolveRotatedBusinessProfileUsesMatchingTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	store := authstore.NewManagedStore(dir, nil)
	old := config.Profile{APIBaseURL: "https://old.example", SpaceID: "old-space"}
	next := config.Profile{APIBaseURL: "https://new.example", SpaceID: "new-space"}
	const name = "work"
	baseline, err := store.Snapshot(name, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(baseline, old, "old-token", authstore.BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	profiles, err := config.LoadProfileConfig()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err = store.Snapshot(name, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(baseline, next, "new-token", authstore.BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	ref := baseline.Profile.TokenSource
	_, _, readErr := ReadProfileToken(profiles, ref)
	if !errors.Is(readErr, errManagedCredentialMissing) {
		t.Fatalf("expected a stale entry error: %v", readErr)
	}
	var settings config.Config
	opts := BusinessOptions{Profile: name, ProfileSet: true, Space: old.SpaceID}
	if _, err := resolveRotatedBusinessProfile(&settings, opts, name, ref, readErr); err == nil || errors.Is(err, errManagedCredentialMissing) {
		t.Fatalf("the original Space constraint should reject the new binding: %v", err)
	}
	opts.Space = ""
	got, err := resolveRotatedBusinessProfile(&settings, opts, name, ref, readErr)
	if err != nil || got.Token != "new-token" || got.APIBaseURL != next.APIBaseURL || got.SpaceID != next.SpaceID {
		t.Fatalf("rotation did not resolve one coherent binding: %#v, %v", got, err)
	}
}
