package authstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinKeychainScopesUseFilesystemSpelling(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "Store-Mixed")
	alias := filepath.Join(parent, "store-mixed")
	if err := os.Mkdir(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(alias)
	if errors.Is(err, os.ErrNotExist) {
		// On a case-sensitive volume both directories must stay distinct.
		if err := os.Mkdir(alias, dirPerm); err != nil {
			t.Fatal(err)
		}
		first, err := canonicalManagedDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		second, err := canonicalManagedDirectory(alias)
		if err != nil || first == second {
			t.Fatalf("distinct directory scopes: %q and %q (%v)", first, second, err)
		}
		return
	}
	if err != nil || !os.SameFile(info, other) {
		t.Fatalf("case alias does not identify the same directory: %v", err)
	}
	assertManagedKeychainDirectoryAlias(t, BackendKeychain, dir, alias)
}

func TestDarwinKeychainStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{-25300, os.ErrNotExist},
		{-25307, errKeychainUnavailable},
		{-25294, errKeychainUnavailable},
		{-25291, errKeychainUnavailable},
		{-25293, os.ErrPermission},
		{-25308, os.ErrPermission},
		{-60008, os.ErrPermission},
		{-25295, nil},
	} {
		raw := fmt.Sprintf("security: fake-token-echo\nfind-generic-password: returned %d\n", tc.status)
		err := keychainStatusError("find-generic-password", raw)
		if err == nil || strings.Contains(err.Error(), "fake-token-echo") {
			t.Fatalf("status %d leaked diagnostics or returned no error: %v", tc.status, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("status %d: %v, want %v", tc.status, err, tc.want)
		}
		if tc.want == nil && errors.Is(err, errKeychainUnavailable) {
			t.Fatalf("unexpected fallback for unrecognized failure %d", tc.status)
		}
	}
	if err := (macKeychain{}).Create("test", make([]byte, 4096)); !errors.Is(err, errKeychainEntryTooLarge) {
		t.Fatalf("oversized command did not fail before calling Keychain: %v", err)
	}
	if err := keychainStatusError("default-keychain", "security: SecKeychainCopyDefault: A default keychain could not be found.\ndefault-keychain: returned 1\n"); !errors.Is(err, errKeychainUnavailable) {
		t.Fatalf("missing default Keychain: %v", err)
	}
	if err := keychainStatusError("default-keychain", "security: SecKeychainCopyDefault: User interaction is not allowed.\ndefault-keychain: returned 1\n"); errors.Is(err, errKeychainUnavailable) {
		t.Fatalf("unexpected fallback on interaction denial: %v", err)
	}
}

func TestDarwinKeychainPinsNewEntriesAcrossSearchListChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, `original keychain "fixture".keychain-db`)
	if err := os.WriteFile(path, nil, secPerm); err != nil {
		t.Fatal(err)
	}
	const account = "scope/00112233445566778899aabbccddeeff"
	pathArg := ` "` + dir + `/original keychain \"fixture\".keychain-db"`
	store := macKeychain{dir: dir, run: func(command string) ([]byte, error) {
		if command == "default-keychain" {
			return []byte(`    "` + path + `"` + "\n"), nil
		}
		if command != keychainCommand("add-generic-password", account)+" -w 61"+pathArg {
			t.Fatalf("unexpected creation command: %s", command)
		}
		return nil, nil
	}}
	if err := store.Create(account, []byte("a")); err != nil {
		t.Fatal(err)
	}
	// Simulate a new process whose search list no longer includes the
	// original Keychain. Only a command with the explicit path finds it.
	store.run = func(command string) ([]byte, error) {
		switch command {
		case keychainCommand("find-generic-password", account) + " -w" + pathArg:
			return []byte("61\n"), nil
		case keychainCommand("delete-generic-password", account) + pathArg:
			return nil, nil
		default:
			return nil, os.ErrNotExist
		}
	}
	if data, err := store.Read(account); err != nil || string(data) != "a" {
		t.Fatalf("read the pinned Keychain: %v", err)
	}
	if err := store.Remove(account); err != nil {
		t.Fatalf("remove from the pinned Keychain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, credentialsDir, keychainLocatorName(account))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful delete retained locator: %v", err)
	}
	if err := store.Remove(account); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a legacy search miss must be reported: %v", err)
	}
}

func TestDarwinKeychainLogoutRejectsSymlinkedCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), "fixture.keychain-db")
	if err := os.WriteFile(path, nil, secPerm); err != nil {
		t.Fatal(err)
	}
	keychain := macKeychain{dir: dir, run: func(command string) ([]byte, error) {
		switch {
		case command == "default-keychain":
			return []byte(fmt.Sprintf("%q\n", path)), nil
		case strings.HasPrefix(command, "add-generic-password "):
			return nil, nil
		case strings.HasPrefix(command, "find-generic-password "):
			return []byte("61\n"), nil
		default:
			t.Fatalf("unexpected Keychain operation: %s", command)
			return nil, os.ErrInvalid
		}
	}}
	store := NewManagedStore(dir, keychain)
	snap, err := store.Snapshot("target", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, managedFixtureProfile(), "a", BackendKeychain); err != nil {
		t.Fatal(err)
	}
	snap, err = store.Snapshot("target", true)
	if err != nil || !snap.Exists {
		t.Fatalf("select Keychain profile: %v", err)
	}
	credentials := filepath.Join(dir, credentialsDir)
	external := filepath.Join(t.TempDir(), credentialsDir)
	if err := os.Rename(credentials, external); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, credentials); err != nil {
		t.Fatal(err)
	}
	result, err := store.Remove(snap)
	if err != nil || result.CleanupWarning == "" {
		t.Fatalf("logout must commit and report refused Keychain cleanup: %#v, %v", result, err)
	}
	if after, err := store.Snapshot("target", true); err != nil || after.Exists {
		t.Fatalf("profile was not removed: %v", err)
	}
	locator := filepath.Join(external, keychainLocatorName(snap.Profile.TokenSource.Entry))
	if raw, err := os.ReadFile(locator); err != nil || string(raw) != path {
		t.Fatalf("external Keychain locator changed: %v", err)
	}
}

func darwinLocatorFixture(t *testing.T, dir string) (keychain macKeychain, path string, items map[string]string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "fixture.keychain-db")
	writeOwnershipFixture(t, path, []byte{})
	items = make(map[string]string)
	keychain = macKeychain{dir: dir, run: func(command string) ([]byte, error) {
		if command == "default-keychain" {
			return []byte(fmt.Sprintf("%q\n", path)), nil
		}
		args := strings.Fields(command)
		account := args[4]
		switch args[0] {
		case "find-generic-password":
			if value, ok := items[account]; ok {
				return []byte(value + "\n"), nil
			}
			return nil, os.ErrNotExist
		case "add-generic-password":
			items[account] = args[6]
			return nil, nil
		case "delete-generic-password":
			delete(items, account)
			return nil, nil
		default:
			t.Fatalf("unexpected Keychain operation: %s", args[0])
			return nil, os.ErrInvalid
		}
	}}
	return keychain, path, items
}

func TestDarwinManagedImportProtectsMasterKeyLocator(t *testing.T) {
	for _, scenario := range []string{"missing", "dangling alias", "existing", "hard link"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			keychain, path, items := darwinLocatorFixture(t, dir)
			store := NewManagedStore(dir, keychain)
			locator := filepath.Join(dir, credentialsDir, keychainLocatorName("master-key"))
			ref := locator
			var want []byte
			if scenario == "existing" || scenario == "hard link" {
				want = []byte(path)
				writeOwnershipFixture(t, locator, want)
			}
			switch scenario {
			case "dangling alias":
				ref = filepath.Join(dir, "alias")
				symlinkOwnershipFixture(t, locator, ref)
			case "hard link":
				ref = filepath.Join(dir, "alias")
				if err := os.Link(locator, ref); err != nil {
					t.Fatal(err)
				}
			}
			publishOwnershipFixture(t, dir, ref)
			snap, err := store.Snapshot("work", true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Import(snap, managedFixtureProfile(), "encrypted-fixture-token", BackendEncryptedFile)
			if err == nil || !strings.Contains(err.Error(), "reserved by a Token file") {
				t.Errorf("expected a locator conflict: %v", err)
			}
			assertOwnershipFixture(t, locator, want)
			if len(items) != 0 {
				t.Fatal("conflicting import created a Keychain item")
			}
			if after, err := store.Snapshot("work", true); err != nil || after.Exists {
				t.Fatalf("conflicting import committed a profile: %v", err)
			}
		})
	}
}

func TestDarwinManagedCleanupProtectsEntryLocator(t *testing.T) {
	for _, operation := range []string{"logout", "replace"} {
		for _, scenario := range []string{"direct", "symlink", "hard link", "missing", "dangling alias", "unreferenced"} {
			t.Run(operation+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				keychain, path, items := darwinLocatorFixture(t, dir)
				store := NewManagedStore(dir, keychain)
				profile := managedFixtureProfile()
				snap, err := store.Snapshot("work", true)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Import(snap, profile, "original-fixture-token", BackendKeychain); err != nil {
					t.Fatal(err)
				}
				snap, err = store.Snapshot("work", true)
				if err != nil || !snap.Exists {
					t.Fatalf("read imported profile: %v", err)
				}
				entry := snap.Profile.TokenSource.Entry
				account, err := store.account(entry)
				if err != nil {
					t.Fatal(err)
				}
				locator := filepath.Join(dir, credentialsDir, keychainLocatorName(entry))
				ref := locator
				want := []byte(path)
				if scenario == "missing" || scenario == "dangling alias" {
					if err := os.Remove(locator); err != nil {
						t.Fatal(err)
					}
					want = nil
				}
				switch scenario {
				case "symlink", "dangling alias":
					ref = filepath.Join(dir, "alias")
					symlinkOwnershipFixture(t, locator, ref)
				case "hard link":
					ref = filepath.Join(dir, "alias")
					if err := os.Link(locator, ref); err != nil {
						t.Fatal(err)
					}
				}
				protected := scenario != "unreferenced"
				if protected {
					publishOwnershipFixture(t, dir, ref)
				} else {
					want = nil
				}
				var result CommitResult
				if operation == "logout" {
					result, err = store.Remove(snap)
				} else {
					result, err = store.Import(snap, profile, "replacement-fixture-token", BackendKeychain)
				}
				if err != nil {
					t.Fatal(err)
				}
				assertOwnershipFixture(t, locator, want)
				if _, kept := items[account]; kept != protected || (result.CleanupWarning != "") != protected {
					t.Fatalf("unexpected cleanup of old Keychain account: kept=%t, %#v", kept, result)
				}
				after, err := store.Snapshot("work", true)
				if err != nil || after.Exists != (operation == "replace") {
					t.Fatalf("unexpected binding after %s: %v", operation, err)
				}
				if after.Exists {
					if token, err := store.readEntry(after.Profile.TokenSource); err != nil || token != "replacement-fixture-token" {
						t.Fatalf("replacement credential is unreadable: %v", err)
					}
				}
			})
		}
	}
}
