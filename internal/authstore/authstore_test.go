package authstore

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

type memoryKeychain struct {
	entries   map[string]string
	putErr    error
	get       func(string) (string, error)
	deleteErr error
}

func (k *memoryKeychain) Put(_ context.Context, account, token string) error {
	if k.putErr != nil {
		return k.putErr
	}
	k.entries[account] = token
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

func (k *memoryKeychain) Delete(_ context.Context, account string) error {
	if k.deleteErr != nil {
		return k.deleteErr
	}
	delete(k.entries, account)
	return nil
}

func testStore(t *testing.T, keychain *memoryKeychain) *Store {
	t.Helper()
	t.Setenv(EnvConfigDir, filepath.Join(t.TempDir(), "cli"))
	store, err := New(keychain)
	if err != nil {
		t.Fatal(err)
	}
	return store
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
