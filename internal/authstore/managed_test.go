package authstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

func TestManagedEncryptedImport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cli")
	s := managedIn(dir)
	s.keychain = unavailableKeychain{}
	baseline, err := s.Snapshot("target", true)
	if err != nil || baseline.Exists {
		t.Fatalf("new store snapshot: %v, %v", baseline.Exists, err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot changed the directory: %v", err)
	}
	profile := config.Profile{APIBaseURL: "https://gateway.example", SpaceID: "S1"}
	token := "unified-test-token"
	if _, err := s.Import(baseline, profile, token, BackendAuto); err != nil {
		t.Fatal(err)
	}
	got, err := s.Snapshot("", false)
	if err != nil || !got.Exists || got.Name != "target" || got.Profile.TokenSource.Backend != BackendEncryptedFile {
		t.Fatalf("snapshot after import: %#v, %v", got, err)
	}
	ref := got.Profile.TokenSource
	if stored, err := s.readEntry(ref); err != nil || stored != token {
		t.Fatalf("read managed entry: %v", err)
	}
	for _, path := range []string{s.masterKeyPath(), s.encryptedPath(ref.Entry), filepath.Join(dir, configFile)} {
		content, err := os.ReadFile(path)
		if err != nil || bytes.Contains(content, []byte(token)) {
			t.Fatalf("expected readable file with no token plaintext (%s): %v", path, err)
		}
		if info, err := os.Stat(path); runtime.GOOS != "windows" && (err != nil || info.Mode().Perm() != secPerm) {
			t.Fatalf("expected private file %s: %v", path, err)
		}
	}
	if _, err := s.Import(baseline, profile, "different-token", BackendAuto); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("stale snapshot import: %v", err)
	}
	if result, err := s.Remove(got); err != nil || result.CleanupWarning != "" {
		t.Fatalf("remove target: %#v, %v", result, err)
	}
	if _, err := os.Stat(s.encryptedPath(ref.Entry)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry left behind after remove: %v", err)
	}
}
