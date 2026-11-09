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
				keychain.keep = store.account(old.Entry)
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
