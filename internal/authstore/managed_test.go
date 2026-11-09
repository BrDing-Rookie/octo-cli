package authstore

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

type fixtureKeychain struct {
	entries   map[string][]byte
	denied    bool
	tooLarge  bool
	keep      string
	readsFail bool
}

func (f *fixtureKeychain) Read(account string) ([]byte, error) {
	if f.denied || f.readsFail {
		return nil, os.ErrPermission
	}
	data, ok := f.entries[account]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(data), nil
}

func (f *fixtureKeychain) Create(account string, data []byte) error {
	if f.denied {
		return os.ErrPermission
	}
	if f.tooLarge && len(data) > 32 {
		return errKeychainEntryTooLarge
	}
	f.entries[account] = bytes.Clone(data)
	return nil
}

func (f *fixtureKeychain) Remove(account string) error {
	if account == f.keep {
		return os.ErrPermission
	}
	delete(f.entries, account)
	return nil
}

func managedFixtureProfile() config.Profile {
	return config.Profile{APIBaseURL: "https://gateway.example", SpaceID: "S1"}
}

func publishedConfigPath(t *testing.T, dir string) string {
	t.Helper()
	cfg, err := config.LoadProfileConfigIn(dir, true)
	if err != nil || cfg == nil || !cfg.IsPublished() {
		t.Fatalf("read published configuration: %v", err)
	}
	return filepath.Join(dir, cfg.WriteFile())
}

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
	profile := managedFixtureProfile()
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
	for _, path := range []string{s.masterKeyPath(), s.encryptedPath(ref.Entry), publishedConfigPath(t, dir)} {
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

func TestLegacyProfileWritesWaitForManagedCommit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*Store) error
	}{
		{"login", func(s *Store) error {
			return s.SaveProfile("legacy", &ProfileMeta{RobotID: "bot-legacy"}, "legacy-token")
		}},
		{"update", func(s *Store) error { return s.UpdateProfileAPIBaseURL("legacy", "https://legacy.example") }},
		{"logout", func(s *Store) error { return s.RemoveProfile("legacy") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			legacy := &Store{dir: dir}
			if err := legacy.SaveProfile("legacy", &ProfileMeta{RobotID: "bot-legacy"}, "initial-token"); err != nil {
				t.Fatal(err)
			}
			managed := NewManagedStore(dir, nil)
			snap, err := managed.Snapshot("managed", true)
			if err != nil {
				t.Fatal(err)
			}

			commitReady, commit := make(chan struct{}), make(chan struct{})
			managed.writeConfig = func(path string, data []byte) (bool, error) {
				close(commitReady)
				<-commit
				return writeManagedFile(path, data)
			}
			managedDone := make(chan error, 1)
			go func() {
				_, err := managed.Import(snap, managedFixtureProfile(), "managed-token", BackendEncryptedFile)
				managedDone <- err
			}()
			select {
			case <-commitReady:
			case err := <-managedDone:
				t.Fatalf("import stopped before commit: %v", err)
			}

			legacyStarted, legacyDone := make(chan struct{}), make(chan error, 1)
			go func() {
				close(legacyStarted)
				legacyDone <- tc.write(legacy)
			}()
			<-legacyStarted
			select {
			case err := <-legacyDone:
				close(commit)
				<-managedDone
				t.Fatalf("legacy mutation finished while import held the lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(commit)
			if err := <-managedDone; err != nil {
				t.Fatal(err)
			}
			if err := <-legacyDone; err != nil {
				t.Fatalf("legacy mutation could not coexist with the versioned config: %v", err)
			}
			after, err := managed.Snapshot("managed", true)
			if err != nil || !after.Exists {
				t.Fatalf("managed profile was lost: %v", err)
			}
			if token, err := managed.readEntry(after.Profile.TokenSource); err != nil || token != "managed-token" {
				t.Fatalf("managed credential was lost: %v", err)
			}
		})
	}
}

func TestManagedProfileMigrationPreservesCredential(t *testing.T) {
	dir := t.TempDir()
	store := NewManagedStore(dir, nil)
	profile := managedFixtureProfile()
	snap, err := store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, profile, "managed-token", BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, configFile)
	managedPath := publishedConfigPath(t, dir)
	if err := os.Rename(managedPath, legacyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(managedPath)); err != nil {
		t.Fatal(err)
	}
	snap, err = store.Snapshot("target", true)
	if err != nil || !snap.Exists {
		t.Fatalf("read old v1 layout: %v", err)
	}
	if _, err := os.Stat(managedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading must not migrate the old layout: %v", err)
	}
	ref := *snap.Profile.TokenSource
	if result, err := store.ConfirmTarget(snap, profile.APIBaseURL); err != nil || result.CleanupWarning != "" {
		t.Fatalf("migrate v1 profile: %#v, %v", result, err)
	}
	if profiles, err := (&Store{dir: dir}).LoadProfiles(); err != nil || len(profiles) != 0 {
		t.Fatalf("expected an empty legacy store after retirement: %v", err)
	}
	// Simulate a published CLI rewriting the old filename as an unversioned
	// Bot store, even when the friendly name matches the unified profile.
	legacy := `{"profiles":{"target":{"api_base_url":"https://legacy.example","robot_id":"bot-legacy"}}}`
	if err := os.WriteFile(legacyPath, []byte(legacy), secPerm); err != nil {
		t.Fatal(err)
	}
	after, err := store.Snapshot("target", true)
	if err != nil || !after.Exists || after.Profile.APIBaseURL != profile.APIBaseURL ||
		after.Profile.TokenSource == nil || *after.Profile.TokenSource != ref {
		t.Fatalf("v1 binding did not survive the legacy overwrite: %v", err)
	}
	if got, err := store.readEntry(after.Profile.TokenSource); err != nil || got != "managed-token" {
		t.Fatalf("migrated credential could not be decrypted: %v", err)
	}
}

func TestManagedMigrationPreservesConcurrentLegacyWrite(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, configFile)
	old := `{"version":1,"profiles":{"unified":{"api_base_url":"https://gateway.example/"}}}`
	if err := os.WriteFile(legacyPath, []byte(old), secPerm); err != nil {
		t.Fatal(err)
	}
	store := NewManagedStore(dir, nil)
	snap, err := store.Snapshot("unified", true)
	if err != nil || !snap.Exists {
		t.Fatalf("select original v1 profile: %v", err)
	}
	legacy := &Store{dir: dir}
	store.writeConfig = func(path string, data []byte) (bool, error) {
		committed, err := writeManagedFile(path, data)
		if err == nil {
			// Published legacy writers replace config.json without our lock.
			err = legacy.saveProfiles(map[string]ProfileMeta{"bot": {RobotID: "cli_bot"}})
		}
		return committed, err
	}
	if result, err := store.ConfirmTarget(snap, "https://gateway.example"); err != nil || result.CleanupWarning != "" {
		t.Fatalf("migrate while legacy writer publishes: %#v, %v", result, err)
	}
	if profiles, err := legacy.LoadProfiles(); err != nil || len(profiles) != 1 || profiles["bot"].RobotID != "cli_bot" {
		t.Fatalf("concurrent legacy configuration was lost: %v", err)
	}
}

func TestManagedMigrationPreservesExternalTokenPaths(t *testing.T) {
	for _, tc := range []struct {
		name, reference, target string
		dangling                bool
	}{
		{"alternate file already in use", ".octo-unified/profiles.json", ".octo-unified/profiles.json", false},
		{"dangling link to primary file", "token.link", config.ManagedProfileFile, true},
		{"candidate itself is a dangling link", config.ManagedProfileFile, "restored-token", true},
		{"alternate directory is a Token file", ".octo-unified", ".octo-unified", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			const token = "external-fixture-token"
			target := filepath.Join(dir, tc.target)
			if tc.dangling {
				if err := os.Symlink(tc.target, filepath.Join(dir, tc.reference)); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("cannot create a Windows file symlink: %v", err)
					}
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(target), dirPerm); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(token), secPerm); err != nil {
					t.Fatal(err)
				}
			}
			v1 := fmt.Sprintf(`{"version":1,"profiles":{"unified":{"api_base_url":"https://gateway.example","token_source":{"type":"token_file","path":%q}}}}`, tc.reference)
			if err := os.WriteFile(filepath.Join(dir, configFile), []byte(v1), secPerm); err != nil {
				t.Fatal(err)
			}
			store := NewManagedStore(dir, nil)
			snap, err := store.Snapshot("unified", true)
			if err != nil || !snap.Exists || snap.Profile.TokenSource == nil || snap.Profile.TokenSource.Path != tc.reference {
				t.Fatalf("read original profile and Token reference: %v", err)
			}
			if result, err := store.ConfirmTarget(snap, "https://gateway.example"); err != nil || result.CleanupWarning != "" {
				t.Fatalf("migrate while retaining the Token path: %#v, %v", result, err)
			}
			if tc.dangling {
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("migration wrote to the missing Token target: %v", err)
				}
				if err := os.WriteFile(target, []byte(token), secPerm); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := config.LoadProfileConfigIn(dir, false)
			if err != nil || cfg == nil || !cfg.IsPublished() || cfg.Profiles["unified"] == nil {
				t.Fatalf("load migrated configuration after restoring the Token: %v", err)
			}
			ref := cfg.Profiles["unified"].TokenSource
			if ref == nil || ref.Path != tc.reference {
				t.Fatalf("external Token reference changed: %#v", ref)
			}
			if got, err := os.ReadFile(cfg.TokenFilePath(ref.Path)); err != nil || string(got) != token {
				t.Fatalf("read original external Token: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, cfg.WriteFile()), []byte(`{`), secPerm); err != nil {
				t.Fatal(err)
			}
			if cfg, err := config.LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
				t.Fatalf("damaged dedicated configuration must fail closed: %v", err)
			}
		})
	}
}

func TestV1RetirementKeepsBotPublishedAfterReadingV1(t *testing.T) {
	for _, phase := range []string{"complete retirement", "interrupted after backup"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			active := filepath.Join(dir, configFile)
			v1 := []byte(`{"version":1,"profiles":{"unified":{"api_base_url":"https://gateway.example"}}}`)
			if err := os.WriteFile(active, v1, secPerm); err != nil {
				t.Fatal(err)
			}
			file, raw, err := readV1ConfigForRetirement(active)
			if err != nil || file == nil || !bytes.Equal(raw, v1) {
				t.Fatalf("inspect the v1 inode: %v", err)
			}
			t.Cleanup(func() { _ = file.Close() })
			legacy := &Store{dir: dir}
			if err := legacy.saveProfiles(map[string]ProfileMeta{"bot": {RobotID: "cli_bot"}}); err != nil {
				t.Fatal(err)
			}
			published, err := os.Stat(active)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "interrupted after backup" {
				if _, err := writeV1Backup(dir, raw); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				journal := v1RetirementJournal{owned: t.TempDir(), profiles: &config.ProfileConfig{}}
				if warning := journal.archive(file, raw); warning != "" {
					t.Fatalf("retire the inspected file: %s", warning)
				}
			}
			if after, err := os.Stat(active); err != nil || !os.SameFile(after, published) {
				t.Fatalf("concurrent legacy inode changed: %v", err)
			}
			if profiles, err := legacy.LoadProfiles(); err != nil || len(profiles) != 1 || profiles["bot"].RobotID != "cli_bot" {
				t.Fatalf("concurrent legacy contents changed: %v", err)
			}
			backups, err := filepath.Glob(filepath.Join(dir, "config.v1-*.bak"))
			if err != nil || len(backups) != 1 {
				t.Fatalf("expected one recovery file: %v, %v", backups, err)
			}
			if backup, err := os.ReadFile(backups[0]); err != nil || !bytes.Equal(backup, v1) {
				t.Fatalf("archive must contain the inspected v1 bytes: %v", err)
			}
		})
	}
}

func TestManagedMutationResumesShortV1Retirement(t *testing.T) {
	for _, scenario := range []string{"same inode", "legacy replacement", "active file removed", "older unmarked short write", "unpublished marker", "older root marker"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			store := NewManagedStore(dir, nil)
			profile := managedFixtureProfile()
			snap, err := store.Snapshot("target", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(snap, profile, "managed-token", BackendEncryptedFile); err != nil {
				t.Fatal(err)
			}
			journal := v1RetirementJournal{
				owned:    filepath.Join(filepath.Dir(publishedConfigPath(t, dir)), config.OwnedProfileMarker),
				profiles: &config.ProfileConfig{},
			}
			path := filepath.Join(dir, configFile)
			v1 := []byte(`{"version":1,"profiles":{"old":{"api_base_url":"https://gateway.example"}}}`)
			if err := os.WriteFile(path, v1, secPerm); err != nil {
				t.Fatal(err)
			}
			file, raw, err := readV1ConfigForRetirement(path)
			if err != nil || file == nil {
				t.Fatalf("inspect v1: %v", err)
			}
			t.Cleanup(func() { _ = file.Close() })
			backup, err := writeV1Backup(dir, raw)
			if err != nil {
				t.Fatal(err)
			}
			var pending string
			switch scenario {
			case "older unmarked short write":
			case "unpublished marker":
				pending = filepath.Join(journal.owned, filepath.Base(backup)+retirementStageSuffix)
				if err := os.Link(path, pending); err != nil {
					t.Fatal(err)
				}
			case "older root marker":
				pending = backup + retirementSuffix
				if err := os.Link(path, pending); err != nil {
					t.Fatal(err)
				}
			default:
				pending, err = journal.mark(file, backup)
				if err != nil || pending == "" {
					t.Fatalf("persist recovery marker: %v", err)
				}
			}
			if scenario != "unpublished marker" {
				if _, err := file.WriteAt([]byte(`{"profiles":{}}`), 0); err != nil {
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			legacy := &Store{dir: dir}
			if _, err := legacy.LoadProfiles(); err == nil {
				t.Fatal("fixture must require retirement before legacy use")
			}
			if scenario == "legacy replacement" {
				if err := legacy.saveProfiles(map[string]ProfileMeta{"bot": {RobotID: "cli_bot"}}); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "active file removed" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			snap, err = store.Snapshot("target", true)
			if err != nil || !snap.Exists {
				t.Fatalf("published profile must remain available: %v", err)
			}
			result, err := store.ConfirmTarget(snap, profile.APIBaseURL)
			if scenario == "older unmarked short write" {
				if err != nil || !strings.Contains(result.CleanupWarning, "backup") {
					t.Fatalf("unmarked damage must report the need for recovery: %#v, %v", result, err)
				}
				if _, err := legacy.LoadProfiles(); err == nil {
					t.Fatal("unmarked legacy file was overwritten")
				}
				return
			}
			if err != nil || result.CleanupWarning != "" {
				t.Fatalf("retry retirement: %#v, %v", result, err)
			}
			if got, err := legacy.LoadProfiles(); err != nil || (scenario != "legacy replacement" && len(got) != 0) ||
				(scenario == "legacy replacement" && (len(got) != 1 || got["bot"].RobotID != "cli_bot")) {
				t.Fatalf("unexpected legacy profiles after recovery: %#v, %v", got, err)
			}
			_, markerErr := os.Stat(pending)
			if scenario == "legacy replacement" || scenario == "active file removed" {
				if markerErr != nil {
					t.Fatalf("detached marker should be retained: %v", markerErr)
				}
			} else if !errors.Is(markerErr, os.ErrNotExist) {
				t.Fatalf("completed recovery marker still present: %v", markerErr)
			}
			if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, v1) {
				t.Fatalf("original v1 backup changed: %v", err)
			}
		})
	}
}

func TestV1RetirementLeavesHardLinkedSourceUntouched(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, configFile)
	v1 := []byte(`{"version":1,"profiles":{}}`)
	if err := os.WriteFile(active, v1, secPerm); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Link(active, alias); err != nil {
		t.Fatal(err)
	}
	file, raw, err := readV1ConfigForRetirement(active)
	if err != nil || file == nil {
		t.Fatalf("inspect the v1 inode: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	journal := v1RetirementJournal{owned: t.TempDir(), profiles: &config.ProfileConfig{}}
	if warning := journal.archive(file, raw); !strings.Contains(warning, "retained") {
		t.Fatalf("hard-linked v1 config must retain a recovery file: %s", warning)
	}
	if got, err := os.ReadFile(alias); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("hard link was modified: %v", err)
	}
}

func TestManagedMutationKeepsExternalTokenNamedLikeRetirementMarker(t *testing.T) {
	for _, active := range []string{"missing", "different inode"} {
		for _, operation := range []string{"update", "logout"} {
			t.Run(active+"/"+operation, func(t *testing.T) {
				dir := t.TempDir()
				const name = "config.v1-123.bak.pending"
				tokenFile := filepath.Join(dir, name)
				const token = "external-fixture-token"
				if err := os.WriteFile(tokenFile, []byte(token), secPerm); err != nil {
					t.Fatal(err)
				}
				// Even a valid-looking backup beside an arbitrary file does not
				// prove that the other file is a retirement marker.
				if err := os.WriteFile(filepath.Join(dir, "config.v1-123.bak"), []byte(`{"version":1,"profiles":{}}`), secPerm); err != nil {
					t.Fatal(err)
				}
				raw := fmt.Sprintf(`{"version":1,"profiles":{"work":{"api_base_url":"https://gateway.example","token_source":{"type":"token_file","path":%q}}}}`, name)
				if err := os.WriteFile(filepath.Join(dir, config.ManagedProfileFile), []byte(raw), secPerm); err != nil {
					t.Fatal(err)
				}
				legacy := &Store{dir: dir}
				if active == "different inode" {
					if err := legacy.saveProfiles(map[string]ProfileMeta{"bot": {RobotID: "cli_bot"}}); err != nil {
						t.Fatal(err)
					}
				}
				store := NewManagedStore(dir, nil)
				snap, err := store.Snapshot("work", true)
				if err != nil || !snap.Exists {
					t.Fatalf("select existing profile: %v", err)
				}
				var result CommitResult
				if operation == "update" {
					result, err = store.ConfirmTarget(snap, "https://gateway.example")
				} else {
					result, err = store.Remove(snap)
				}
				if err != nil || result.CleanupWarning != "" {
					t.Fatalf("mutate profile: %#v, %v", result, err)
				}
				if got, err := os.ReadFile(tokenFile); err != nil || string(got) != token {
					t.Fatalf("external Token was lost: %v", err)
				}
				if active == "different inode" {
					if got, err := legacy.LoadProfiles(); err != nil || got["bot"].RobotID != "cli_bot" {
						t.Fatalf("active Bot config was changed: %v", err)
					}
				}
			})
		}
	}
}

func TestManagedLogoutProtectsPreviouslyReferencedOwnedMarkerPath(t *testing.T) {
	dir := t.TempDir()
	store := NewManagedStore(dir, nil)
	profile := managedFixtureProfile()
	snap, err := store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, profile, "managed-token", BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProfileConfigIn(dir, true)
	if err != nil || cfg == nil {
		t.Fatalf("read owned config: %v", err)
	}
	v1 := []byte(`{"version":1,"profiles":{}}`)
	backup, err := writeV1Backup(dir, v1)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(cfg.WriteFile()), config.OwnedProfileMarker, filepath.Base(backup)+retirementSuffix)
	active := filepath.Join(dir, configFile)
	if err := os.WriteFile(active, v1, secPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(active, filepath.Join(dir, marker)); err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["target"].TokenSource = &config.TokenSource{Type: "token_file", Path: marker}
	if committed, err := store.persist(cfg); !committed || err != nil {
		t.Fatalf("seed external reference: %v", err)
	}
	snap, err = store.Snapshot("target", true)
	if err != nil || !snap.Exists {
		t.Fatalf("select profile to log out: %v", err)
	}
	if result, err := store.Remove(snap); err != nil || !strings.Contains(result.CleanupWarning, "Token file") {
		t.Fatalf("remove external reference: %#v, %v", result, err)
	}
	if after, err := store.Snapshot("target", true); err != nil || after.Exists {
		t.Fatalf("logout did not remove the reference: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, marker)); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("logout removed the previously referenced file: %v", err)
	}
	if got, err := os.ReadFile(active); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("logout modified the previously referenced inode: %v", err)
	}
}

func TestManagedRemoveRejectsSymlinkedCredentials(t *testing.T) {
	original := NewManagedStore(t.TempDir(), nil)
	copyStore := NewManagedStore(t.TempDir(), nil)
	snap, err := original.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Import(snap, managedFixtureProfile(), "original-token", BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(original.dir, credentialsDir), filepath.Join(copyStore.dir, credentialsDir)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create a Windows directory symlink: %v", err)
		}
		t.Fatal(err)
	}
	raw, err := os.ReadFile(publishedConfigPath(t, original.dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyStore.dir, config.ManagedProfileFile), raw, secPerm); err != nil {
		t.Fatal(err)
	}
	snap, err = copyStore.Snapshot("target", true)
	if err != nil || !snap.Exists {
		t.Fatalf("select copied profile: %v", err)
	}
	result, err := copyStore.Remove(snap)
	if err != nil || result.CleanupWarning == "" {
		t.Fatalf("logout must commit and report refused cleanup: %#v, %v", result, err)
	}
	if after, err := copyStore.Snapshot("target", true); err != nil || after.Exists {
		t.Fatalf("copied profile was not removed: %v", err)
	}
	if token, err := original.readEntry(snap.Profile.TokenSource); err != nil || token != "original-token" {
		t.Fatalf("the original store lost its credential: %v", err)
	}
}

func TestManagedCommitFailures(t *testing.T) {
	for _, scenario := range []string{"pre-commit", "verify-entry", "cleanup", "directory-sync"} {
		t.Run(scenario, func(t *testing.T) {
			keychain := &fixtureKeychain{entries: map[string][]byte{}}
			store := NewManagedStore(t.TempDir(), keychain)
			profile := managedFixtureProfile()
			snap, err := store.Snapshot("target", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(snap, profile, "old-token", BackendKeychain); err != nil {
				t.Fatal(err)
			}
			snap, err = store.Snapshot("target", true)
			if err != nil {
				t.Fatal(err)
			}
			old := snap.Profile.TokenSource
			switch scenario {
			case "pre-commit":
				store.writeConfig = func(string, []byte) (bool, error) { return false, os.ErrPermission }
			case "verify-entry":
				keychain.readsFail = true
			case "cleanup":
				keychain.keep, err = store.account(old.Entry)
				if err != nil {
					t.Fatal(err)
				}
			case "directory-sync":
				store.writeConfig = func(path string, data []byte) (bool, error) {
					committed, err := writeManagedFile(path, data)
					return committed, errors.Join(err, os.ErrPermission)
				}
			}
			result, commitErr := store.Import(snap, profile, "new-token", BackendKeychain)
			keychain.readsFail = false
			after, err := store.Snapshot("target", true)
			if err != nil {
				t.Fatal(err)
			}
			if stored, err := store.readEntry(old); err != nil || stored != "old-token" {
				t.Fatalf("previous entry was lost: %v", err)
			}
			if scenario == "pre-commit" || scenario == "verify-entry" {
				if !errors.Is(commitErr, os.ErrPermission) || *after.Profile.TokenSource != *old || len(keychain.entries) != 1 {
					t.Fatalf("failed commit changed reference or orphaned the candidate: %#v, %v", result, commitErr)
				}
				return
			}
			if commitErr != nil || result.CleanupWarning == "" || *after.Profile.TokenSource == *old {
				t.Fatalf("successful commit did not retain new reference and report warning: %#v, %v", result, commitErr)
			}
			if token, err := store.readEntry(after.Profile.TokenSource); err != nil || token != "new-token" {
				t.Fatalf("new entry cannot be read: %v", err)
			}
		})
	}
}

func TestManagedKeychainEntriesUseCanonicalDirectory(t *testing.T) {
	for _, backend := range []string{BackendKeychain, BackendEncryptedFile} {
		t.Run(backend, func(t *testing.T) {
			parent := t.TempDir()
			alias := filepath.Join(t.TempDir(), "parent-alias")
			if err := os.Symlink(parent, alias); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("cannot create a Windows directory symlink: %v", err)
				}
				t.Fatal(err)
			}
			assertManagedKeychainDirectoryAlias(t, backend, filepath.Join(parent, "store"), filepath.Join(alias, "store"))
		})
	}
}

func assertManagedKeychainDirectoryAlias(t *testing.T, backend, dir, alias string) {
	t.Helper()
	keychain := &fixtureKeychain{entries: map[string][]byte{}}
	original := NewManagedStore(dir, keychain)
	aliased := NewManagedStore(alias, keychain)
	baseline, err := original.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	const token = "keychain-fixture-bearer"
	if _, err := original.Import(baseline, managedFixtureProfile(), token, backend); err != nil {
		t.Fatal(err)
	}
	selected, err := aliased.Snapshot("target", true)
	if err != nil || !selected.Exists {
		t.Fatalf("alias did not select the stored profile: %v", err)
	}
	ref := selected.Profile.TokenSource
	if stored, err := aliased.readEntry(ref); err != nil || stored != token {
		t.Fatalf("alias could not read the stored token: %v", err)
	}
	result, err := aliased.Remove(selected)
	if err != nil || result.CleanupWarning != "" {
		t.Fatalf("alias could not remove the original entry: %#v, %v", result, err)
	}
	if _, err := original.readEntry(ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry still readable from the original path: %v", err)
	}
	if backend == BackendKeychain && len(keychain.entries) != 0 {
		t.Fatal("removing through the alias left behind a Keychain token")
	}
}

func TestManagedReferenceSharingAndFailedReads(t *testing.T) {
	store := NewManagedStore(t.TempDir(), nil)
	profile := managedFixtureProfile()
	snap, err := store.Snapshot("first", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, profile, "initial-token", BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadProfileConfigIn(store.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["second"] = cfg.Profiles["first"]
	ref := cfg.Profiles["first"].TokenSource
	if committed, err := store.persist(cfg); !committed || err != nil {
		t.Fatalf("seed shared reference: %v", err)
	}
	snap, err = store.Snapshot("first", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(snap); err != nil {
		t.Fatal(err)
	}
	if token, err := ReadManagedToken(cfg, ref); err != nil || token != "initial-token" {
		t.Fatalf("entry still referenced by another profile: %v", err)
	}
	snap, err = store.Snapshot("second", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, profile, "rotated-token", BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManagedToken(cfg, ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale reader did not get an entry read error: %v", err)
	}
	snap, err = store.Snapshot("second", true)
	if err != nil {
		t.Fatal(err)
	}
	entry := store.encryptedPath(snap.Profile.TokenSource.Entry)
	data, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(entry, data, secPerm); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readEntry(snap.Profile.TokenSource); err == nil || !strings.Contains(err.Error(), "decrypt managed credential") {
		t.Fatalf("tampered encrypted entry: %v", err)
	}
}

func TestManagedKeychainFallbackPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend string
		denied  bool
		wantErr error
	}{
		{"permission blocks auto fallback", BackendAuto, true, os.ErrPermission},
		{"permission blocks fallback key", BackendEncryptedFile, true, os.ErrPermission},
		{"explicit keychain stays selected", BackendKeychain, false, errKeychainEntryTooLarge},
		{"oversized entry can still use keychain master key", BackendAuto, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keychain := &fixtureKeychain{entries: map[string][]byte{}, denied: tc.denied, tooLarge: true}
			store := NewManagedStore(t.TempDir(), keychain)
			snap, err := store.Snapshot("target", true)
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("t", 48)
			_, err = store.Import(snap, managedFixtureProfile(), token, tc.backend)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("import: %v, want %v", err, tc.wantErr)
			}
			if _, err := os.Stat(store.masterKeyPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected local fallback key: %v", err)
			}
			if tc.wantErr != nil {
				return
			}
			snap, err = store.Snapshot("target", true)
			if err != nil || !snap.Exists || snap.Profile.TokenSource.Backend != BackendEncryptedFile {
				t.Fatalf("expected an encrypted reference: %#v, %v", snap, err)
			}
			if stored, err := store.readEntry(snap.Profile.TokenSource); err != nil || stored != token {
				t.Fatalf("credential using keychain master key: %v", err)
			}
		})
	}
}

func TestManagedImportRejectsMissingMasterKey(t *testing.T) {
	for _, location := range []string{"file", "file with available Keychain", "Keychain"} {
		t.Run(location, func(t *testing.T) {
			keychain := &fixtureKeychain{entries: map[string][]byte{}}
			store := NewManagedStore(t.TempDir(), nil)
			if location == "Keychain" {
				store.keychain = keychain
			}
			profile := managedFixtureProfile()
			first, err := store.Snapshot("existing", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(first, profile, "existing-token", BackendEncryptedFile); err != nil {
				t.Fatalf("first import into empty store: %v", err)
			}
			cfg, err := config.LoadProfileConfigIn(store.dir, false)
			if err != nil || cfg == nil || cfg.Profiles["existing"] == nil {
				t.Fatalf("read first profile: %v", err)
			}
			ref := cfg.Profiles["existing"].TokenSource
			configPath := filepath.Join(store.dir, cfg.WriteFile())
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var restore func()
			if location == "Keychain" {
				account, err := store.account("master-key")
				if err != nil {
					t.Fatal(err)
				}
				backup := keychain.entries[account]
				delete(keychain.entries, account)
				restore = func() { keychain.entries[account] = backup }
			} else {
				backup := store.masterKeyPath() + ".backup"
				if err := os.Rename(store.masterKeyPath(), backup); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.Rename(backup, store.masterKeyPath()); err != nil {
						t.Fatal(err)
					}
				}
				if location == "file with available Keychain" {
					store.keychain = keychain
				}
			}
			second, err := store.Snapshot("new", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(second, profile, "new-token", BackendEncryptedFile); err == nil || !strings.Contains(err.Error(), "missing master key") {
				t.Fatalf("expected import to refuse a missing key: %v", err)
			}
			if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("refused import changed existing references: %v", err)
			}
			if _, err := store.readEntry(ref); !errors.Is(err, os.ErrNotExist) || len(keychain.entries) != 0 {
				t.Fatalf("refused import installed a replacement master key: %v", err)
			}
			restore()
			if got, err := store.readEntry(ref); err != nil || got != "existing-token" {
				t.Fatalf("credential still unreadable after restoring the original key: %v", err)
			}
		})
	}
}

func TestManagedImportsSerializeAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type writer struct {
		cmd *exec.Cmd
		in  io.WriteCloser
		out *bufio.Scanner
	}
	var writers []writer
	for _, token := range []string{"first-token", "second-token"} {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedImportProcessHelper$")
		cmd.Env = append(os.Environ(), "OCTO_TEST_MANAGED_PROCESS_DIR="+dir, "OCTO_TEST_MANAGED_PROCESS_TOKEN="+token)
		cmd.Stderr = os.Stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(out)
		if !scanner.Scan() || scanner.Text() != "ready" {
			t.Fatalf("writer failed to read baseline: %s (%v)", scanner.Text(), scanner.Err())
		}
		writers = append(writers, writer{cmd, in, scanner})
	}
	for _, w := range writers {
		_, err := fmt.Fprintln(w.in, "commit")
		if err = errors.Join(err, w.in.Close()); err != nil {
			t.Fatal(err)
		}
	}
	results := map[string]int{}
	for _, w := range writers {
		if !w.out.Scan() {
			t.Fatalf("writer stopped before reporting a result: %v", w.out.Err())
		}
		results[w.out.Text()]++
		for w.out.Scan() {
			// Drain before Wait closes the pipe.
		}
		if err := w.cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if results["committed"] != 1 || results["conflict"] != 1 {
		t.Fatalf("expected one commit and one explicit conflict, got %v", results)
	}
}

func TestManagedImportProcessHelper(t *testing.T) {
	dir := os.Getenv("OCTO_TEST_MANAGED_PROCESS_DIR")
	if dir == "" {
		return
	}
	store := NewManagedStore(dir, nil)
	snap, err := store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	_, err = store.Import(snap, managedFixtureProfile(), os.Getenv("OCTO_TEST_MANAGED_PROCESS_TOKEN"), BackendAuto)
	switch {
	case err == nil:
		fmt.Println("committed")
	case errors.Is(err, ErrProfileConflict):
		fmt.Println("conflict")
	default:
		t.Fatal(err)
	}
}
