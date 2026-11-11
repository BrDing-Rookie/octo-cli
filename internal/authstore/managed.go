package authstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// ErrProfileOriginChange means a new origin requires a verified Token import.
var ErrProfileOriginChange = errors.New("cannot change the API origin of a unified profile with auth update")

// ErrProfileLockToken means a profile may reference the shared lock as a Token.
var ErrProfileLockToken = errors.New("managed lock path is reserved by a Token file")

// ManagedStore owns the versioned configuration and its managed entries.
type ManagedStore struct {
	dir         string
	allowLegacy bool
	keychain    Keychain
	writeConfig func(string, []byte) (bool, error)
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

type profileWrite struct {
	committed         bool
	err               error
	retirementWarning string
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
	return NewManagedStore(dir, systemKeychain(dir))
}

// NewManagedStore injects a Keychain for an absolute configuration directory.
// A nil Keychain represents a platform without system storage.
func NewManagedStore(dir string, keychain Keychain) *ManagedStore {
	if keychain == nil {
		keychain = unavailableKeychain{}
	}
	return &ManagedStore{dir: dir, allowLegacy: true, keychain: keychain, writeConfig: writeManagedFile}
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
	if err := validateImport(profile, token, backend); err != nil {
		return CommitResult{}, err
	}
	return s.modify(snap, func(cfg *config.ProfileConfig) (CommitResult, error) {
		ref, err := s.stageToken(cfg, token, backend)
		if err != nil {
			return CommitResult{}, err
		}
		profile.TokenSource = ref
		cfg.Profiles[snap.baseline.name] = &profile
		if cfg.CurrentProfile == "" {
			cfg.CurrentProfile = snap.baseline.name
		}
		write := s.persist(cfg, snap.baseline.original)
		if !write.committed {
			return CommitResult{}, errors.Join(write.err, s.removeEntry(cfg, ref))
		}
		return s.afterCommit(cfg, snap.baseline.original, write), nil
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
	return s.modify(snap, func(cfg *config.ProfileConfig) (CommitResult, error) {
		if snap.baseline.original == nil {
			return CommitResult{}, errors.New("selected profile does not exist")
		}
		delete(cfg.Profiles, snap.baseline.name)
		if cfg.CurrentProfile == snap.baseline.name {
			cfg.CurrentProfile = ""
		}
		write := s.persist(cfg, snap.baseline.original)
		if !write.committed {
			return CommitResult{}, write.err
		}
		return s.afterCommit(cfg, snap.baseline.original, write), nil
	})
}

// ConfirmTarget checks an unchanged binding under the write lock. A new
// origin or Space needs a token verified against that target via Import.
func (s *ManagedStore) ConfirmTarget(snap ProfileSnapshot, apiBaseURL string) (CommitResult, error) {
	return s.modify(snap, func(cfg *config.ProfileConfig) (CommitResult, error) {
		profile := cfg.Profiles[snap.baseline.name]
		if profile == nil {
			return CommitResult{}, ErrProfileOriginChange
		}
		current, currentErr := config.NormalizeAPIBaseURL(profile.APIBaseURL)
		requested, requestErr := config.NormalizeAPIBaseURL(apiBaseURL)
		if currentErr != nil || requestErr != nil || current != requested {
			return CommitResult{}, ErrProfileOriginChange
		}
		if !cfg.IsPublished() {
			write := s.persist(cfg, nil)
			if !write.committed {
				return CommitResult{}, write.err
			}
			return s.afterCommit(cfg, nil, write), nil
		}
		return s.afterCommit(cfg, nil, profileWrite{}), nil
	})
}

func (s *ManagedStore) modify(snap ProfileSnapshot, fn func(*config.ProfileConfig) (CommitResult, error)) (CommitResult, error) {
	base := snap.baseline
	if base == nil || base.dir != s.dir || base.name == "" || strings.TrimSpace(base.name) != base.name {
		return CommitResult{}, errors.New("a valid target profile is required")
	}
	// Reject an invalid source before creating a directory or a lock.
	if _, err := config.LoadWritableProfileConfigIn(s.dir, s.allowLegacy); err != nil {
		return CommitResult{}, err
	}
	if err := ensurePrivateDir(s.dir); err != nil {
		return CommitResult{}, err
	}
	lock, err := openProfileLock(s.dir)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() { _ = lock.Close() }() //nolint:errcheck // closing releases the advisory lock

	cfg, err := config.LoadWritableProfileConfigIn(s.dir, s.allowLegacy)
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
	return fn(cfg)
}

func (s *ManagedStore) persist(cfg *config.ProfileConfig, previous *config.Profile) profileWrite {
	if !cfg.IsPublished() {
		// Only this migration can publish a retirement record.
		cfg.V1Retirement = nil
	}
	raw, err := marshalProfileConfig(cfg)
	if err != nil {
		return profileWrite{err: err}
	}
	if !cfg.IsPublished() {
		return s.publishProfileConfig(cfg, previous, raw)
	}
	path := filepath.Join(s.dir, cfg.WriteFile())
	if err := checkProfileWritePaths(cfg, path); err != nil {
		return profileWrite{err: err}
	}
	committed, err := s.writeConfig(path, raw)
	return profileWrite{committed: committed, err: err}
}

func marshalProfileConfig(cfg *config.ProfileConfig) ([]byte, error) {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	return append(raw, '\n'), err
}

func (s *ManagedStore) publishProfileConfig(cfg *config.ProfileConfig, previous *config.Profile, data []byte) profileWrite {
	dir, err := os.MkdirTemp(s.dir, config.OwnedProfileDirPrefix)
	if err != nil {
		return profileWrite{err: err}
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(dir) //nolint:errcheck // discard only our unpublished staging directory
		}
	}()
	name := filepath.Base(dir)
	path := filepath.Join(dir, config.ManagedProfileFile)
	journalDir := filepath.Join(dir, config.OwnedProfileMarker)
	seal := filepath.Join(dir, config.OwnedProfileSeal)
	stage := filepath.Join(s.dir, config.OwnedProfileStagePrefix+name)
	anchor := filepath.Join(s.dir, config.OwnedProfileAnchor)
	for _, target := range []string{dir, path, journalDir, seal, stage, anchor} {
		if reserved, err := cfg.ReferencesTokenFile(target, previous); err != nil || reserved {
			return profileWrite{err: errors.New("publication path may be a referenced Token file")}
		}
	}
	if err := ensurePrivateDir(dir); err != nil {
		return profileWrite{err: err}
	}
	if committed, err := s.writeConfig(path, data); !committed || err != nil {
		return profileWrite{err: err}
	}
	if err := stageProfileAuthority(dir, stage, seal); err != nil {
		return profileWrite{err: err}
	}
	defer func() { _ = os.Remove(stage) }() //nolint:errcheck // a leftover staging link cannot replace the publication anchor
	if err := os.Mkdir(journalDir, dirPerm); err != nil {
		return profileWrite{err: err}
	}
	journal := v1RetirementJournal{
		active: filepath.Join(s.dir, configFile), owned: journalDir,
		profiles: cfg, previous: previous,
	}
	warning := journal.prepareMigration(func() error {
		raw, err := marshalProfileConfig(cfg)
		if err != nil {
			return err
		}
		_, err = writeManagedFile(path, raw)
		return err
	})
	if err := syncManagedDirectory(dir); err != nil {
		return profileWrite{err: err}
	}
	// The non-replacing hard link is the publication point. Both the
	// prepared metadata and the selected directory precede it on disk.
	if err := os.Link(seal, anchor); err != nil {
		return profileWrite{err: err}
	}
	published = true
	cfg.SetPublishedFile(filepath.Join(name, config.ManagedProfileFile))
	return profileWrite{committed: true, err: syncManagedDirectory(s.dir), retirementWarning: warning}
}

func stageProfileAuthority(dir, stage, seal string) error {
	file, err := os.CreateTemp(dir, ".authority-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }() //nolint:errcheck // transient name before the authority is linked
	_, err = file.WriteString(filepath.Base(dir) + "\n")
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	if err := os.Link(file.Name(), stage); err != nil {
		return err
	}
	if err := os.Link(file.Name(), seal); err != nil {
		return errors.Join(err, os.Remove(stage))
	}
	return syncManagedDirectory(filepath.Dir(stage))
}

func checkProfileWritePaths(cfg *config.ProfileConfig, paths ...string) error {
	for _, path := range paths {
		reserved, err := cfg.ReferencesTokenFile(path)
		if err != nil {
			return err
		}
		if reserved {
			return errors.New("storage path is reserved by a Token file")
		}
	}
	return nil
}

func (s *ManagedStore) afterCommit(cfg *config.ProfileConfig, old *config.Profile, write profileWrite) CommitResult {
	if write.err != nil {
		// If the rename is visible but its durability is uncertain, keep the
		// old entry in case the filesystem recovers the previous config.
		return CommitResult{CleanupWarning: "profile changed but directory sync failed; previous credential retained"}
	}
	var warnings []string
	if write.retirementWarning != "" {
		warnings = append(warnings, write.retirementWarning)
	}
	if warning := s.retireV1Config(cfg, old); warning != "" {
		warnings = append(warnings, warning)
	}
	result := CommitResult{CleanupWarning: strings.Join(warnings, ". ")}
	if old == nil || old.TokenSource == nil || old.TokenSource.Type != "managed_store" {
		return result
	}
	ref := old.TokenSource
	for _, p := range cfg.Profiles {
		if p != nil && p.TokenSource != nil && p.TokenSource.Type == "managed_store" &&
			p.TokenSource.Backend == ref.Backend && p.TokenSource.Entry == ref.Entry {
			return result
		}
	}
	if err := s.removeEntry(cfg, ref); err != nil {
		if result.CleanupWarning != "" {
			result.CleanupWarning += ". "
		}
		result.CleanupWarning += "profile changed but the previous managed credential could not be removed"
	}
	return result
}

func (s *ManagedStore) stageToken(cfg *config.ProfileConfig, token, backend string) (*config.TokenSource, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate managed credential ID: %w", err)
	}
	ref := &config.TokenSource{Type: "managed_store", Entry: hex.EncodeToString(id[:]), Backend: backend}
	if backend != BackendEncryptedFile {
		ref.Backend = BackendKeychain
		err := s.createKeychain(cfg, ref.Entry, []byte(token))
		switch {
		case err == nil:
			return s.verifyEntry(cfg, ref, token)
		case backend == BackendKeychain || (!errors.Is(err, errKeychainUnavailable) && !errors.Is(err, errKeychainEntryTooLarge)):
			return nil, err
		}
	}
	ref.Backend = BackendEncryptedFile
	if err := s.writeEncrypted(cfg, ref.Entry, token); err != nil {
		return nil, err
	}
	return s.verifyEntry(cfg, ref, token)
}

func (s *ManagedStore) verifyEntry(cfg *config.ProfileConfig, ref *config.TokenSource, token string) (*config.TokenSource, error) {
	stored, err := s.readEntry(ref)
	if err != nil || stored != token {
		return nil, errors.Join(errors.New("new managed credential could not be verified"), err, s.removeEntry(cfg, ref))
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

func (s *ManagedStore) removeEntry(cfg *config.ProfileConfig, ref *config.TokenSource) error {
	if err := validateManagedRef(ref); err != nil {
		return err
	}
	if ref.Backend == BackendKeychain {
		if err := s.checkKeychainLocator(cfg, ref.Entry); err != nil {
			return err
		}
		account, err := s.account(ref.Entry)
		if err != nil {
			return err
		}
		return s.keychain.Remove(account)
	}
	if err := checkProfileWritePaths(cfg, s.encryptedPath(ref.Entry)); err != nil {
		return err
	}
	return s.removeEncrypted(ref.Entry)
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
