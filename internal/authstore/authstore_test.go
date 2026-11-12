package authstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

type memoryKeychain struct {
	entries   map[string]string
	putErr    error
	afterPut  func() error
	get       func(string) (string, error)
	deleteErr error
}

func (k *memoryKeychain) Put(_ context.Context, account, token string) error {
	if k.putErr != nil {
		return k.putErr
	}
	k.entries[account] = token
	if k.afterPut != nil {
		return k.afterPut()
	}
	return nil
}

func (k *memoryKeychain) Get(_ context.Context, account string) (string, error) {
	if k.get != nil {
		return k.get(account)
	}
	return k.read(account)
}

func (k *memoryKeychain) read(account string) (string, error) {
	token, ok := k.entries[account]
	if !ok {
		return "", fs.ErrNotExist
	}
	return token, nil
}

func (k *memoryKeychain) Delete(ctx context.Context, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if k.deleteErr != nil {
		return k.deleteErr
	}
	if _, ok := k.entries[account]; !ok {
		return fs.ErrNotExist
	}
	delete(k.entries, account)
	return nil
}

func testStore(t *testing.T, keychain *memoryKeychain) *Store {
	t.Helper()
	return testStoreAt(t, filepath.Join(t.TempDir(), "cli"), keychain)
}

func testStoreAt(t *testing.T, dir string, keychain *memoryKeychain) *Store {
	t.Helper()
	t.Setenv(EnvConfigDir, dir)
	store, err := New(keychain)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testStoreCaseAlias(t *testing.T, store *Store, keychain *memoryKeychain) *Store {
	t.Helper()
	dir := filepath.Join(filepath.Dir(store.dir), "CLI")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("configuration volume is case-sensitive")
	} else if err != nil {
		t.Fatal(err)
	}
	return testStoreAt(t, dir, keychain)
}

func snapshot(t *testing.T, store *Store) *Config {
	t.Helper()
	var cfg *Config
	if err := store.View(context.Background(), func(current *Config) error {
		cfg = current
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func testProfile(id string) *Profile {
	return &Profile{
		APIBaseURL: "https://gateway.example.test", SpaceID: "space-a",
		Verified: &Verified{TokenID: id, OwnerID: "owner-a", SpaceID: "space-a"},
	}
}

func saveTestProfile(t *testing.T, store *Store, name, id, token string) {
	t.Helper()
	warning, err := store.Import(context.Background(), name, snapshot(t, store), false, testProfile(id), token)
	if err != nil || warning != "" {
		t.Fatalf("import = %v, warning = %q", err, warning)
	}
}

func requireCredential(t *testing.T, store *Store, profile *Profile, token string) {
	t.Helper()
	got, err := store.ReadToken(context.Background(), profile)
	if err != nil || got != token {
		t.Fatalf("credential did not round trip: %v", err)
	}
}

func TestEncryptedFallbackPrivateFilesAndIntegrity(t *testing.T) {
	store := testStore(t, &memoryKeychain{putErr: ErrUnavailable})
	const secret = "opaque-fallback-test-bearer"
	saveTestProfile(t, store, "agent", "id-1", secret)
	cfg := snapshot(t, store)
	p := cfg.Profiles["agent"]
	if p.TokenSource.Backend != EncryptedFile {
		t.Fatalf("backend = %s", p.TokenSource.Backend)
	}
	requireCredential(t, store, &p, secret)

	ciphertext := store.encryptedPath(p.TokenSource.Entry)
	for _, path := range []string{ciphertext, filepath.Join(store.dir, configFile), filepath.Join(store.dir, masterKeyFile)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("managed file mode = %o", info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, []byte(secret)) {
			t.Fatalf("managed file exposed the bearer: %v", err)
		}
	}
	if info, err := os.Stat(store.dir); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("configuration directory is not private: %v", err)
	}
	key, err := store.masterKey()
	if err != nil || len(key) != masterKeySize {
		t.Fatalf("master key is missing or malformed: %v", err)
	}
	second, err := New(&memoryKeychain{putErr: ErrUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	requireCredential(t, second, &p, secret)
	data, err := os.ReadFile(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(ciphertext, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadToken(context.Background(), &p); output.AsExitError(err) == nil {
		t.Fatalf("tampered ciphertext was not rejected: %v", err)
	}
}

func TestSystemPermissionFailureDoesNotFallBack(t *testing.T) {
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	saveTestProfile(t, store, "agent", "id-1", "old-token-fixture")
	old := snapshot(t, store)
	if old.Profiles["agent"].TokenSource.Backend != Keychain {
		t.Fatal("available system storage was bypassed")
	}
	keychain.putErr = fs.ErrPermission
	_, err := store.Import(context.Background(), "agent", old, false, testProfile("id-2"), "new-token-fixture")
	if exit := output.AsExitError(err); exit == nil || exit.Type != "permission" {
		t.Fatalf("expected a permission error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, masterKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("permission denial used fallback storage: %v", err)
	}
	current := snapshot(t, store).Profiles["agent"]
	requireCredential(t, store, &current, "old-token-fixture")
}

func TestSystemCredentialDirectoryCaseAlias(t *testing.T) {
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	const token = "shared-token-fixture"
	saveTestProfile(t, store, "agent", "id-1", token)

	aliasStore := testStoreCaseAlias(t, store, keychain)
	ctx := context.Background()
	if err := aliasStore.View(ctx, func(cfg *Config) error {
		p := cfg.Profiles["agent"]
		if got, err := aliasStore.ReadToken(ctx, &p); err != nil || got != token {
			t.Errorf("reading via the directory case alias failed: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, warning, err := aliasStore.Logout(ctx, "agent", func(*Profile) error { return nil }); err != nil || warning != "" {
		t.Fatalf("logout via the directory case alias: %v %q", err, warning)
	}
	if len(keychain.entries) != 0 || len(snapshot(t, store).Profiles) != 0 {
		t.Fatal("logout via the directory case alias did not remove both the profile and its credential")
	}
}

func TestSystemCredentialLegacyAccount(t *testing.T) {
	for _, storedName := range []string{"cli", "CLI"} {
		t.Run(storedName, func(t *testing.T) {
			ctx := context.Background()
			keychain := &memoryKeychain{entries: make(map[string]string)}
			store := testStore(t, keychain)
			if _, err := store.checkDir(true); err != nil {
				t.Fatal(err)
			}
			aliasStore := testStoreCaseAlias(t, store, keychain)

			const entry = "legacy-entry"
			const token = "legacy-token-fixture"
			oldDir, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(store.dir), storedName))
			if err != nil {
				t.Fatal(err)
			}
			account := fmt.Sprintf("%x", sha256.Sum256([]byte(oldDir+"\x00"+entry)))
			keychain.entries[account] = token
			cfg := emptyConfig()
			p := testProfile("id-1")
			p.TokenSource = TokenSource{Type: ManagedStore, Backend: Keychain, Entry: entry}
			cfg.Profiles["agent"] = *p
			if warning, err := store.publish(ctx, cfg, TokenSource{}); err != nil || warning != "" {
				t.Fatalf("publish legacy fixture: %v %q", err, warning)
			}

			profile := snapshot(t, aliasStore).Profiles["agent"]
			requireCredential(t, aliasStore, &profile, token)
			if _, warning, err := aliasStore.Logout(ctx, "agent", func(*Profile) error { return nil }); err != nil || warning != "" {
				t.Fatalf("logout of legacy profile: %v %q", err, warning)
			}
			if len(keychain.entries) != 0 {
				t.Fatal("logout left the legacy system credential")
			}
		})
	}
}

func TestSystemCredentialDirectoryIsolation(t *testing.T) {
	ctx := context.Background()
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	const token = "directory-token-fixture"
	saveTestProfile(t, store, "agent", "id-1", token)
	cfg := snapshot(t, store)

	otherDir := filepath.Join(filepath.Dir(store.dir), "CLI")
	if _, err := os.Stat(otherDir); err == nil {
		otherDir += "-other"
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	other := testStoreAt(t, otherDir, keychain)
	if _, err := other.checkDir(true); err != nil {
		t.Fatal(err)
	}
	if warning, err := other.publish(ctx, cfg, TokenSource{}); err != nil || warning != "" {
		t.Fatalf("copy profile to another directory: %v %q", err, warning)
	}
	profile := snapshot(t, other).Profiles["agent"]
	if _, err := other.ReadToken(ctx, &profile); err == nil {
		t.Fatal("a copied profile read a credential from a different configuration directory")
	}
	if _, warning, err := other.Logout(ctx, "agent", func(*Profile) error { return nil }); err != nil || warning != "" {
		t.Fatalf("logout of copied profile: %v %q", err, warning)
	}
	requireCredential(t, store, &profile, token)
}

func TestInterruptedImportKeepsOldReference(t *testing.T) {
	for _, mode := range []string{"cancel after readback", "readback mismatch"} {
		t.Run(mode, func(t *testing.T) {
			keychain := &memoryKeychain{entries: make(map[string]string)}
			store := testStore(t, keychain)
			saveTestProfile(t, store, "agent", "id-1", "old-token-fixture")
			old := snapshot(t, store)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			keychain.get = func(account string) (string, error) {
				if mode == "readback mismatch" {
					return "unexpected-token", nil
				}
				cancel()
				return keychain.read(account)
			}
			_, err := store.Import(ctx, "agent", old, false, testProfile("id-2"), "new-token-fixture")
			if exit := output.AsExitError(err); exit == nil || exit.Code != "PROFILE_STORAGE_ERROR" {
				t.Fatalf("interrupted import should fail before commit: %v", err)
			}
			keychain.get = nil
			p := snapshot(t, store).Profiles["agent"]
			if p.TokenSource != old.Profiles["agent"].TokenSource || p.Verified.TokenID != "id-1" || len(keychain.entries) != 1 {
				t.Fatal("failed import changed the profile reference or left a staged credential")
			}
			requireCredential(t, store, &p, "old-token-fixture")
		})
	}
}

func TestCanceledSystemWriteDiscardsNewEntry(t *testing.T) {
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	saveTestProfile(t, store, "agent", "id-1", "old-token-fixture")
	old := snapshot(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keychain.afterPut = func() error {
		cancel()
		return ctx.Err()
	}

	_, err := store.Import(ctx, "agent", old, false, testProfile("id-2"), "new-token-fixture")
	if exit := output.AsExitError(err); exit == nil || exit.Code != "PROFILE_STORAGE_ERROR" {
		t.Fatalf("expected a storage error after cancellation, got %v", err)
	}
	p := snapshot(t, store).Profiles["agent"]
	if p.TokenSource != old.Profiles["agent"].TokenSource || p.Verified.TokenID != "id-1" {
		t.Fatal("canceled write changed the active profile")
	}
	requireCredential(t, store, &p, "old-token-fixture")
	if len(keychain.entries) != 1 {
		t.Fatalf("canceled write left %d entries, want only the original credential", len(keychain.entries))
	}
}

func TestCleanupFailureKeepsPublishedState(t *testing.T) {
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	saveTestProfile(t, store, "agent", "id-1", "old-token-fixture")
	old := snapshot(t, store)
	keychain.deleteErr = fs.ErrPermission
	warning, err := store.Import(context.Background(), "agent", old, false, testProfile("id-2"), "new-token-fixture")
	if err != nil || warning == "" {
		t.Fatalf("expected a successful publication with a cleanup warning: %v %q", err, warning)
	}
	p := snapshot(t, store).Profiles["agent"]
	if p.Verified.TokenID != "id-2" || p.TokenSource == old.Profiles["agent"].TokenSource {
		t.Fatal("cleanup failure rolled back the new profile")
	}
	requireCredential(t, store, &p, "new-token-fixture")
	removed, warning, err := store.Logout(context.Background(), "agent", func(*Profile) error { return nil })
	if err != nil || warning == "" || removed != "agent" || len(snapshot(t, store).Profiles) != 0 {
		t.Fatalf("expected logout with cleanup warning: %s %q %v", removed, warning, err)
	}
}

func TestLogoutRetainsReferencedEntries(t *testing.T) {
	keychain := &memoryKeychain{entries: make(map[string]string)}
	store := testStore(t, keychain)
	saveTestProfile(t, store, "agent", "id-1", "shared-token-fixture")
	cfg := snapshot(t, store)
	cfg.Profiles["second"] = cfg.Profiles["agent"]
	if warning, err := store.publish(context.Background(), cfg, TokenSource{}); err != nil || warning != "" {
		t.Fatalf("publish test fixture: %v %q", err, warning)
	}

	scope := func(*Profile) error { return nil }
	if _, _, err := store.Logout(context.Background(), "agent", scope); err != nil {
		t.Fatal(err)
	}
	remaining := snapshot(t, store).Profiles["second"]
	requireCredential(t, store, &remaining, "shared-token-fixture")
	if _, _, err := store.Logout(context.Background(), "second", scope); err != nil {
		t.Fatal(err)
	}
	if len(keychain.entries) != 0 {
		t.Fatal("logout left an unreferenced managed entry")
	}
}

func TestLogoutRetainsEncryptedEntryWithMixedCaseReferences(t *testing.T) {
	for _, removed := range []string{"lowercase", "uppercase"} {
		t.Run("remove "+removed+" first", func(t *testing.T) {
			ctx := context.Background()
			store := testStore(t, &memoryKeychain{putErr: ErrUnavailable})
			if _, err := store.checkDir(true); err != nil {
				t.Fatal(err)
			}
			const token = "shared-token-fixture"
			entry := strings.Repeat("ab", entryIDSize)
			if published, err := store.writeEncrypted(ctx, entry, token); err != nil || !published {
				t.Fatalf("write test credential: %v", err)
			}
			cfg := emptyConfig()
			p := testProfile("id-1")
			p.TokenSource = TokenSource{Type: ManagedStore, Backend: EncryptedFile, Entry: entry}
			cfg.Profiles["lowercase"] = *p
			p.TokenSource.Entry = strings.ToUpper(entry)
			cfg.Profiles["uppercase"] = *p
			if warning, err := store.publish(ctx, cfg, TokenSource{}); err != nil || warning != "" {
				t.Fatalf("publish test fixture: %v %q", err, warning)
			}

			scope := func(*Profile) error { return nil }
			if _, warning, err := store.Logout(ctx, removed, scope); err != nil || warning != "" {
				t.Fatalf("logout of first profile: %v %q", err, warning)
			}
			if _, err := os.Stat(store.encryptedPath(entry)); err != nil {
				t.Errorf("logout removed a referenced encrypted credential: %v", err)
			}
			remaining := snapshot(t, store).Profiles
			if len(remaining) != 1 {
				t.Fatalf("profiles remaining after logout = %d, want 1", len(remaining))
			}
			for name, profile := range remaining {
				requireCredential(t, store, &profile, token)
				if _, warning, err := store.Logout(ctx, name, scope); err != nil || warning != "" {
					t.Fatalf("logout of last profile: %v %q", err, warning)
				}
			}
			if _, err := os.Stat(store.encryptedPath(entry)); !os.IsNotExist(err) {
				t.Fatalf("logout left an unreferenced encrypted credential: %v", err)
			}
		})
	}
}
