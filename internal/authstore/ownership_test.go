package authstore

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

func writeOwnershipFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, secPerm); err != nil {
		t.Fatal(err)
	}
}

func publishOwnershipFixture(t *testing.T, dir, reference string) *config.ProfileConfig {
	t.Helper()
	cfg, err := config.LoadWritableProfileConfigIn(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		cfg = &config.ProfileConfig{Version: []byte("1"), Profiles: map[string]*config.Profile{}}
	}
	p := managedFixtureProfile()
	p.TokenSource = &config.TokenSource{Type: "token_file", Path: reference}
	cfg.Profiles["external"] = &p
	if write := NewManagedStore(dir, nil).persist(cfg, nil); !write.committed || write.err != nil {
		t.Fatalf("publish fixture: %v", write.err)
	}
	cfg, err = config.LoadWritableProfileConfigIn(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func assertOwnershipFixture(t *testing.T, path string, want []byte) {
	t.Helper()
	if want == nil {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected absent %s: %v", filepath.Base(path), err)
		}
		return
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unexpected contents at %s: %v", filepath.Base(path), err)
	}
}

func symlinkOwnershipFixture(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create Windows symlink: %v", err)
		}
		t.Fatal(err)
	}
}

func TestManagedImportRejectsExternalMasterKeyPaths(t *testing.T) {
	for _, scenario := range []string{"existing", "missing", "hard link", "dangling symlink"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			store := NewManagedStore(dir, nil)
			target := store.masterKeyPath()
			ref := target
			var raw []byte
			if scenario == "existing" || scenario == "hard link" {
				raw = bytes.Repeat([]byte("a"), 32)
				writeOwnershipFixture(t, target, raw)
			}
			switch scenario {
			case "hard link":
				ref = filepath.Join(dir, "alias")
				if err := os.Link(target, ref); err != nil {
					t.Fatal(err)
				}
			case "dangling symlink":
				ref = filepath.Join(dir, "alias")
				symlinkOwnershipFixture(t, target, ref)
			}
			publishOwnershipFixture(t, dir, ref)
			snap, err := store.Snapshot("work", true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Import(snap, managedFixtureProfile(), "managed-fixture", BackendEncryptedFile)
			assertOwnershipFixture(t, target, raw)
			if err == nil {
				t.Fatal("import accepted the external file as the master key")
			}
			if cfg, err := store.Snapshot("work", true); err != nil || cfg.Exists {
				t.Fatalf("failed import committed a profile: %v", err)
			}
		})
	}
}

func TestLegacyLoginProtectsExternalWriteTargets(t *testing.T) {
	for _, name := range []string{configFile, credFile, saltFile, mailCredFile, mailPendingFile} {
		for _, scenario := range []string{"missing", "existing"} {
			t.Run(name+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, name)
				var raw []byte
				if scenario == "existing" {
					raw = []byte(`{"profiles":{}}`)
					writeOwnershipFixture(t, target, raw)
				}
				publishOwnershipFixture(t, dir, target)
				store := &Store{dir: dir}
				err := store.SaveProfile("bot", &ProfileMeta{RobotID: "bot"}, "bot-fixture")
				assertOwnershipFixture(t, target, raw)
				if err == nil {
					t.Fatal("Bot login accepted a reserved path")
				}
				for _, candidate := range []string{configFile, credFile, saltFile, mailCredFile, mailPendingFile} {
					if candidate != name {
						assertOwnershipFixture(t, filepath.Join(dir, candidate), nil)
					}
				}
			})
		}
	}
}

func TestManagedCleanupPreservesExternalEntryFile(t *testing.T) {
	for _, operation := range []string{"logout", "replace"} {
		for _, scenario := range []string{"direct", "symlink", "hard link"} {
			t.Run(operation+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				store := NewManagedStore(dir, nil)
				profile := managedFixtureProfile()
				snap, err := store.Snapshot("work", true)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Import(snap, profile, "original-fixture", BackendEncryptedFile); err != nil {
					t.Fatal(err)
				}
				snap, err = store.Snapshot("work", true)
				if err != nil || !snap.Exists {
					t.Fatalf("read original profile: %v", err)
				}
				target := store.encryptedPath(snap.Profile.TokenSource.Entry)
				raw := []byte("provider-fixture-token")
				writeOwnershipFixture(t, target, raw)
				ref := target
				if scenario != "direct" {
					ref = filepath.Join(dir, "alias")
					if scenario == "symlink" {
						symlinkOwnershipFixture(t, target, ref)
					} else if err := os.Link(target, ref); err != nil {
						t.Fatal(err)
					}
				}
				publishOwnershipFixture(t, dir, ref)
				if operation == "logout" {
					_, err = store.Remove(snap)
				} else {
					_, err = store.Import(snap, profile, "replacement-fixture", BackendEncryptedFile)
				}
				if err != nil {
					t.Fatal(err)
				}
				assertOwnershipFixture(t, target, raw)
				assertOwnershipFixture(t, ref, raw)
				got, err := store.Snapshot("work", true)
				if err != nil || got.Exists != (operation == "replace") {
					t.Fatalf("unexpected profile after %s: %v", operation, err)
				}
				if got.Exists {
					if token, err := store.readEntry(got.Profile.TokenSource); err != nil || token != "replacement-fixture" {
						t.Fatalf("replacement is unreadable: %v", err)
					}
				}
			})
		}
	}
}

func TestManagedMigrationRetriesAfterKilledStagingProcess(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, configFile)
	raw := []byte(`{"version":1,"profiles":{"work":{"api_base_url":"https://gateway.example"}}}`)
	writeOwnershipFixture(t, active, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedMigrationStagingProcess$")
	cmd.Env = append(os.Environ(), "OCTO_TEST_MIGRATION_STAGING_DIR="+dir)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scan := bufio.NewScanner(out)
	if !scan.Scan() || !strings.HasSuffix(scan.Text(), retirementSuffix) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("child did not stage a retirement pin: %q, %v", scan.Text(), scan.Err())
	}
	marker := scan.Text()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected the staging process to be killed")
	}
	assertOwnershipFixture(t, marker, raw)
	assertOwnershipFixture(t, active, raw)
	store := NewManagedStore(dir, nil)
	snap, err := store.Snapshot("work", true)
	if err != nil || !snap.Exists {
		t.Fatalf("read original profile after crash: %v", err)
	}
	if result, err := store.ConfirmTarget(snap, "https://gateway.example"); err != nil || result.CleanupWarning != "" {
		t.Fatalf("retry interrupted migration: %#v, %v", result, err)
	}
	assertOwnershipFixture(t, marker, nil)
	if raw, err := os.ReadFile(active); err != nil || strings.TrimSpace(string(raw)) != `{"profiles":{}}` {
		t.Fatalf("retry did not retire the original v1 configuration: %v", err)
	}
}

func TestManagedMigrationStagingProcess(t *testing.T) {
	dir := os.Getenv("OCTO_TEST_MIGRATION_STAGING_DIR")
	if dir == "" {
		return
	}
	lock, err := openProfileLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cfg, err := config.LoadWritableProfileConfigIn(dir, true)
	if err != nil || cfg == nil || !cfg.NeedsMigration() {
		t.Fatalf("load the migration source: %v", err)
	}
	parent, err := os.MkdirTemp(dir, config.OwnedProfileDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFixture(t, filepath.Join(parent, config.ManagedProfileFile),
		[]byte(`{"version":1,"profiles":{"work":{"api_base_url":"https://gateway.example"}}}`))
	staged, err := os.MkdirTemp(parent, publicationStagePrefix)
	if err != nil {
		t.Fatal(err)
	}
	journal := v1RetirementJournal{active: filepath.Join(dir, configFile), owned: staged, profiles: cfg}
	if warning := journal.prepareMigration(filepath.Join(parent, config.OwnedProfileMarker)); warning != "" {
		t.Fatal(warning)
	}
	markers, err := filepath.Glob(filepath.Join(staged, "config.v1-*.bak.pending"))
	if err != nil || len(markers) != 1 {
		t.Fatalf("expected one retirement marker: %v", err)
	}
	fmt.Println(markers[0])
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
