package authstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

const (
	// BackendAuto chooses a concrete backend when importing a token.
	BackendAuto = "auto"
	// BackendKeychain stores an entry in the system keychain.
	BackendKeychain = "keychain"
	// BackendEncryptedFile stores an AES-256-GCM encrypted entry.
	BackendEncryptedFile = "encrypted_file"
)

// ErrProfileConflict means the caller must re-read and revalidate its target.
var ErrProfileConflict = errors.New("profile changed while validating the credential")

// ManagedStore owns the versioned configuration and its managed entries.
type ManagedStore struct {
	dir           string
	allowLegacy   bool
	keychain      Keychain
	replaceConfig func(context.Context, string, string) (bool, error)
}

// ProfileSnapshot captures the target before online verification. Its private
// fields keep the baseline stable even when the caller edits Profile.
type ProfileSnapshot struct {
	Name    string
	Profile config.Profile
	Exists  bool

	baseline *profileBaseline
}

type profileBaseline struct {
	dir      string
	name     string
	implicit bool
	original *config.Profile
}

// CommitResult reports work remaining after a successful reference change.
type CommitResult struct {
	CleanupWarning string
}

// OpenManaged resolves the configuration directory without creating any files.
func OpenManaged() (*ManagedStore, error) {
	dir, allowLegacy, err := config.ProfileDirectory()
	if err != nil {
		return nil, err
	}
	s := managedIn(dir)
	s.allowLegacy = allowLegacy
	return s, nil
}

func managedIn(dir string) *ManagedStore {
	return NewManagedStore(dir, systemKeychain())
}

// NewManagedStore injects a Keychain for an absolute configuration directory.
// A nil Keychain represents a platform without system storage.
func NewManagedStore(dir string, keychain Keychain) *ManagedStore {
	if keychain == nil {
		keychain = unavailableKeychain{}
	}
	return &ManagedStore{dir: dir, keychain: keychain, replaceConfig: replaceManagedConfig}
}

// Snapshot reads only metadata. A missing target has Exists=false, while an
// unreadable configuration or a malformed selected profile returns an error.
func (s *ManagedStore) Snapshot(name string, explicit bool) (ProfileSnapshot, error) {
	profiles, err := config.LoadProfileConfigIn(s.dir, s.allowLegacy)
	if err != nil {
		return ProfileSnapshot{}, err
	}
	if !explicit && profiles != nil {
		name = profiles.CurrentProfile
	}
	snap := ProfileSnapshot{
		Name:     name,
		baseline: &profileBaseline{name: name, dir: s.dir, implicit: !explicit},
	}
	if profiles == nil {
		return snap, nil
	}
	p, exists := profiles.Profiles[name]
	if !exists {
		return snap, nil
	}
	if p == nil {
		return ProfileSnapshot{}, errors.New("selected profile is null")
	}
	snap.Exists = true
	snap.Profile = *cloneProfile(p)
	snap.baseline.original = cloneProfile(p)
	return snap, nil
}

func cloneProfile(p *config.Profile) *config.Profile {
	copied := *p
	if p.TokenSource != nil {
		ref := *p.TokenSource
		copied.TokenSource = &ref
	}
	return &copied
}

// Import commits a verified candidate. The caller performs network
// verification before invoking Import so the lock covers only local writes.
func (s *ManagedStore) Import(snap ProfileSnapshot, profile config.Profile, token, backend string) (CommitResult, error) {
	return s.ImportContext(context.Background(), snap, profile, token, backend)
}

// ImportContext checks for cancellation up to the atomic replacement of the
// Profile configuration. Once replaced, it keeps the published credential.
func (s *ManagedStore) ImportContext(ctx context.Context, snap ProfileSnapshot, profile config.Profile, token, backend string) (CommitResult, error) {
	if err := ctx.Err(); err != nil {
		return CommitResult{}, err
	}
	if err := validateImport(profile, token, backend); err != nil {
		return CommitResult{}, err
	}
	return s.modify(ctx, snap, func(cfg *config.ProfileConfig) (CommitResult, error) {
		ref, err := s.stageToken(token, backend)
		if err != nil {
			return CommitResult{}, err
		}
		profile.TokenSource = ref
		cfg.Profiles[snap.baseline.name] = &profile
		if cfg.CurrentProfile == "" {
			cfg.CurrentProfile = snap.baseline.name
		}
		committed, err := s.persist(ctx, cfg)
		if !committed {
			return CommitResult{}, errors.Join(err, s.removeEntry(ref))
		}
		return s.afterCommit(cfg, snap.baseline.original, err), nil
	})
}

func validateImport(profile config.Profile, token, backend string) error {
	if profile.APIBaseURL == "" || profile.SpaceID == "" {
		return errors.New("a verified API origin and Space are required")
	}
	var target config.Config
	if err := target.ApplyProfile(profile, ""); err != nil {
		return err
	}
	if target.APIBaseURL != profile.APIBaseURL {
		return errors.New("the verified API origin must be normalized")
	}
	if token == "" || len(token) > maxManagedToken {
		return errors.New("invalid managed credential length")
	}
	switch backend {
	case "", BackendAuto, BackendKeychain, BackendEncryptedFile:
		return nil
	default:
		return errors.New("invalid managed credential backend")
	}
}

// Remove deletes the selected reference before cleaning up its managed entry.
func (s *ManagedStore) Remove(snap ProfileSnapshot) (CommitResult, error) {
	ctx := context.Background()
	return s.modify(ctx, snap, func(cfg *config.ProfileConfig) (CommitResult, error) {
		if snap.baseline.original == nil {
			return CommitResult{}, errors.New("selected profile does not exist")
		}
		delete(cfg.Profiles, snap.baseline.name)
		if cfg.CurrentProfile == snap.baseline.name {
			cfg.CurrentProfile = ""
		}
		committed, err := s.persist(ctx, cfg)
		if !committed {
			return CommitResult{}, err
		}
		return s.afterCommit(cfg, snap.baseline.original, err), nil
	})
}

// ConfirmTarget checks an unchanged binding under the write lock. A new
// origin or Space needs a token verified against that target via Import.
func (s *ManagedStore) ConfirmTarget(snap ProfileSnapshot, apiBaseURL string) error {
	_, err := s.modify(context.Background(), snap, func(_ *config.ProfileConfig) (CommitResult, error) {
		if snap.baseline.original == nil || snap.baseline.original.APIBaseURL != apiBaseURL || apiBaseURL == "" {
			return CommitResult{}, errors.New("re-import a verified Token to change the API origin")
		}
		return CommitResult{}, nil
	})
	return err
}

func (s *ManagedStore) modify(ctx context.Context, snap ProfileSnapshot, fn func(*config.ProfileConfig) (CommitResult, error)) (CommitResult, error) {
	base := snap.baseline
	if base == nil || base.dir != s.dir || base.name == "" || strings.TrimSpace(base.name) != base.name {
		return CommitResult{}, errors.New("a valid target profile is required")
	}
	// Check the strict loader before creating a lock in a legacy directory.
	if _, err := s.loadWritableConfig(); err != nil {
		return CommitResult{}, err
	}
	if err := ensurePrivateDir(s.dir); err != nil {
		return CommitResult{}, err
	}
	lock, err := openManagedLock(ctx, filepath.Join(s.dir, ".managed.lock"))
	if err != nil {
		return CommitResult{}, err
	}
	defer func() { _ = lock.Close() }() //nolint:errcheck // closing releases the advisory lock

	cfg, err := s.loadWritableConfig()
	if err != nil {
		return CommitResult{}, err
	}
	if cfg == nil {
		cfg = &config.ProfileConfig{Version: json.RawMessage("1"), Profiles: map[string]*config.Profile{}}
	}
	actual, exists := cfg.Profiles[base.name]
	if (base.implicit && cfg.CurrentProfile != base.name) ||
		exists != (base.original != nil) || !reflect.DeepEqual(actual, base.original) {
		return CommitResult{}, ErrProfileConflict
	}
	if err := ctx.Err(); err != nil {
		return CommitResult{}, err
	}
	return fn(cfg)
}

func (s *ManagedStore) loadWritableConfig() (*config.ProfileConfig, error) {
	info, err := os.Lstat(filepath.Join(s.dir, configFile))
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("cannot modify a symlinked profile configuration")
	}
	return config.LoadProfileConfigIn(s.dir, false)
}

func (s *ManagedStore) persist(ctx context.Context, cfg *config.ProfileConfig) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err
	}
	return writeManagedFile(filepath.Join(s.dir, configFile), append(raw, '\n'), func(from, to string) (bool, error) {
		return s.replaceConfig(ctx, from, to)
	})
}

func (s *ManagedStore) afterCommit(cfg *config.ProfileConfig, old *config.Profile, syncErr error) CommitResult {
	if syncErr != nil {
		// If the rename is visible but its durability is uncertain, keep the
		// old entry in case the filesystem recovers the previous config.
		return CommitResult{CleanupWarning: "profile changed but directory sync failed; previous credential retained"}
	}
	if old == nil || old.TokenSource == nil || old.TokenSource.Type != "managed_store" {
		return CommitResult{}
	}
	ref := old.TokenSource
	for _, p := range cfg.Profiles {
		if p != nil && p.TokenSource != nil && p.TokenSource.Type == "managed_store" &&
			p.TokenSource.Backend == ref.Backend && p.TokenSource.Entry == ref.Entry {
			return CommitResult{}
		}
	}
	if err := s.removeEntry(ref); err != nil {
		return CommitResult{CleanupWarning: "profile changed but the previous managed credential could not be removed"}
	}
	return CommitResult{}
}

func (s *ManagedStore) stageToken(token, backend string) (*config.TokenSource, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate managed credential ID: %w", err)
	}
	ref := &config.TokenSource{Type: "managed_store", Entry: hex.EncodeToString(id[:]), Backend: backend}
	if backend != BackendEncryptedFile {
		ref.Backend = BackendKeychain
		err := s.createKeychain(ref.Entry, []byte(token))
		switch {
		case err == nil:
			return s.verifyEntry(ref, token)
		case backend == BackendKeychain || (!errors.Is(err, errKeychainUnavailable) && !errors.Is(err, errKeychainEntryTooLarge)):
			return nil, err
		}
	}
	ref.Backend = BackendEncryptedFile
	if err := s.writeEncrypted(ref.Entry, token); err != nil {
		return nil, err
	}
	return s.verifyEntry(ref, token)
}

func (s *ManagedStore) verifyEntry(ref *config.TokenSource, token string) (*config.TokenSource, error) {
	stored, err := s.readEntry(ref)
	if err != nil || stored != token {
		return nil, errors.Join(errors.New("new managed credential could not be verified"), err, s.removeEntry(ref))
	}
	return ref, nil
}

// ReadManagedToken reads a stored reference without changing backends.
func ReadManagedToken(profiles *config.ProfileConfig, ref *config.TokenSource) (string, error) {
	return managedIn(profiles.Directory()).readEntry(ref)
}

func (s *ManagedStore) readEntry(ref *config.TokenSource) (string, error) {
	if err := validateManagedRef(ref); err != nil {
		return "", err
	}
	if ref.Backend == BackendKeychain {
		data, err := s.readKeychain(ref.Entry)
		return string(data), err
	}
	return s.readEncrypted(ref.Entry)
}

func (s *ManagedStore) removeEntry(ref *config.TokenSource) error {
	if err := validateManagedRef(ref); err != nil {
		return err
	}
	if ref.Backend == BackendKeychain {
		account, err := s.account(ref.Entry)
		if err != nil {
			return err
		}
		return s.keychain.Remove(account)
	}
	if err := os.Remove(s.encryptedPath(ref.Entry)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func validateManagedRef(ref *config.TokenSource) error {
	if ref == nil || ref.Type != "managed_store" || ref.Path != "" ||
		(ref.Backend != BackendKeychain && ref.Backend != BackendEncryptedFile) ||
		len(ref.Entry) != 32 || strings.ToLower(ref.Entry) != ref.Entry {
		return errors.New("invalid managed credential reference")
	}
	if _, err := hex.DecodeString(ref.Entry); err != nil {
		return errors.New("invalid managed credential entry")
	}
	return nil
}
