package credential

import (
	"errors"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

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
	var runtime config.Config
	opts := BusinessOptions{Profile: name, ProfileSet: true, Space: old.SpaceID}
	if _, err := resolveRotatedBusinessProfile(&runtime, opts, name, ref, readErr); err == nil || errors.Is(err, errManagedCredentialMissing) {
		t.Fatalf("the original Space constraint should reject the new binding: %v", err)
	}
	opts.Space = ""
	got, err := resolveRotatedBusinessProfile(&runtime, opts, name, ref, readErr)
	if err != nil || got.Token != "new-token" || got.APIBaseURL != next.APIBaseURL || got.SpaceID != next.SpaceID {
		t.Fatalf("rotation did not resolve one coherent binding: %#v, %v", got, err)
	}
}
