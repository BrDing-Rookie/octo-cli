package authstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

const (
	configFile  = "config.json"
	entryIDSize = 16
	storeHint   = "check the configuration directory and credential storage"
)

type storeError string

func (e storeError) Error() string { return string(e) }

// ErrUnavailable means the system credential store is absent or unavailable.
const ErrUnavailable = storeError("system credential storage is unavailable")

// SystemStore reads and writes a system credential by its namespaced account.
// It returns fs.ErrNotExist for a missing entry and ErrUnavailable only when
// the backend cannot be used. Permission and other failures are returned as-is.
type SystemStore interface {
	Put(context.Context, string, string) error
	Get(context.Context, string) (string, error)
	Delete(context.Context, string) error
}

// Store persists configuration and immutable credential entries.
type Store struct {
	dir    string
	system SystemStore
}

// New resolves the config directory. A nil backend uses the native store.
func New(system SystemStore) (*Store, error) {
	dir := os.Getenv(EnvConfigDir)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, storageError("could not locate the user home directory", err)
		}
		dir = filepath.Join(home, ".octo", "cli")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, storageError("could not resolve the configuration directory", err)
	}
	if system == nil {
		system = nativeStore{}
	}
	return &Store{dir: absolute, system: system}, nil
}

// View runs a read while holding the same lock used for publication and cleanup.
func (s *Store) View(ctx context.Context, fn func(*Config) error) error {
	return s.withConfig(ctx, false, fn)
}

func (s *Store) withConfig(ctx context.Context, create bool, fn func(*Config) error) error {
	if err := ctx.Err(); err != nil {
		return storageError("configuration access was canceled", err)
	}
	exists, err := s.checkDir(create)
	if err != nil {
		return storageError("could not access a private configuration directory", err)
	}
	if !exists {
		return fn(emptyConfig())
	}
	unlock, err := lockDirectory(ctx, s.dir)
	if err != nil {
		return storageError("could not lock the configuration directory", err)
	}
	defer unlock()
	cfg, err := s.load()
	if err != nil {
		return err
	}
	return fn(cfg)
}

func emptyConfig() *Config {
	return &Config{Version: 1, Profiles: make(map[string]Profile)}
}

func (s *Store) load() (*Config, error) {
	raw, err := readPrivate(filepath.Join(s.dir, configFile))
	if errors.Is(err, fs.ErrNotExist) {
		return emptyConfig(), nil
	}
	if err != nil {
		return nil, storageError("could not read the profile configuration", err)
	}

	var cfg Config
	if !utf8.Valid(raw) || json.Unmarshal(raw, &cfg) != nil || cfg.Version != 1 || cfg.Profiles == nil {
		return nil, invalidProfile("invalid or unsupported profile configuration version")
	}
	if cfg.CurrentProfile != "" {
		if _, ok := cfg.Profiles[cfg.CurrentProfile]; !ok || ValidateName(cfg.CurrentProfile) != nil {
			return nil, invalidProfile("current_profile does not identify a valid configured profile")
		}
	}
	return &cfg, nil
}

// ReadToken reads the chosen profile source. Call it inside View when
// resolving a stored profile, so its entry cannot be removed during the read.
func (s *Store) ReadToken(ctx context.Context, p *Profile) (string, error) {
	if err := p.ValidateSource(); err != nil {
		return "", err
	}
	if p.TokenSource.Type == TokenFile {
		token, err := credential.ReadFile(s.externalPath(p.TokenSource.Path))
		if err != nil {
			return "", output.ErrAuth("profile credential file: "+err.Error(), "check the configured token file")
		}
		return token, nil
	}

	token, err := s.readManaged(ctx, p.TokenSource)
	if err != nil {
		return "", storageError("could not read the profile's managed credential", err)
	}
	if credential.ValidateBearer(token) != nil {
		return "", invalidProfile("profile has an invalid managed credential")
	}
	return token, nil
}

func (s *Store) readManaged(ctx context.Context, source TokenSource) (string, error) {
	if source.Backend == EncryptedFile {
		return s.readEncrypted(source.entryID())
	}
	account, legacy, err := s.accounts(source.Entry)
	if err != nil {
		return "", err
	}
	token, err := s.system.Get(ctx, account)
	if errors.Is(err, fs.ErrNotExist) && legacy != "" {
		return s.system.Get(ctx, legacy)
	}
	return token, err
}

func (s *Store) accounts(entry string) (account, legacy string, err error) {
	dir, err := filepath.EvalSymlinks(s.dir)
	if err != nil {
		return "", "", err
	}
	canonical, err := credentialDirectory(dir)
	if err != nil {
		return "", "", err
	}
	if canonical != dir {
		// Older imports may have hashed the original spelling of the path.
		legacy = credentialAccount(dir, entry)
	}
	return credentialAccount(canonical, entry), legacy, nil
}

func credentialAccount(dir, entry string) string {
	// The digest also keeps arbitrary path and entry characters out of helpers.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(dir+"\x00"+entry)))
}

// Import publishes a new credential and its profile if the target still
// matches the snapshot used to resolve the import.
// The warning describes failures after the configuration became visible.
func (s *Store) Import(ctx context.Context, name string, snapshot *Config, implicit bool, p *Profile, token string) (warning string, err error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	target, err := p.Scope()
	if err != nil {
		return "", err
	}
	if err := credential.ValidateBearer(token); err != nil {
		return "", output.ErrAuth(err.Error(), "")
	}

	err = s.withConfig(ctx, true, func(cfg *Config) error {
		previous := snapshot.Profiles[name]
		if cfg.Profiles[name] != previous || implicit && cfg.CurrentProfile != snapshot.CurrentProfile {
			return output.ErrWithHint("config", "PROFILE_CHANGED", "profile changed during import", "retry the import")
		}

		source, err := s.stageCredential(ctx, token)
		if err != nil {
			return err
		}
		target.TokenSource = source
		cfg.Profiles[name] = target
		cfg.CurrentProfile = name
		warning, err = s.publish(ctx, cfg, previous.TokenSource)
		if err != nil {
			s.discard(source)
		}
		return err
	})
	return warning, err
}

// Logout removes a selected profile and cleans its unreferenced managed entry.
func (s *Store) Logout(ctx context.Context, name string, scope func(*Profile) error) (removed, warning string, err error) {
	err = s.withConfig(ctx, false, func(cfg *Config) error {
		removed = name
		if removed == "" {
			removed = cfg.CurrentProfile
		}
		p, ok := cfg.Profiles[removed]
		if !ok {
			return output.ErrAuth("profile not found", "select an existing profile")
		}
		if err := scope(&p); err != nil {
			return err
		}
		if err := p.ValidateSource(); err != nil {
			return err
		}
		delete(cfg.Profiles, removed)
		if cfg.CurrentProfile == removed {
			cfg.CurrentProfile = ""
		}
		warning, err = s.publish(ctx, cfg, p.TokenSource)
		return err
	})
	return removed, warning, err
}

func (s *Store) stageCredential(ctx context.Context, token string) (TokenSource, error) {
	source, err := s.putManaged(ctx, token)
	if err != nil {
		return TokenSource{}, storageError("could not save the new managed credential", err)
	}
	saved, err := s.readManaged(ctx, source)
	if err != nil || saved != token {
		s.discard(source)
		return TokenSource{}, storageError("could not verify the saved managed credential", err)
	}
	return source, nil
}

func (s *Store) putManaged(ctx context.Context, token string) (TokenSource, error) {
	if err := ctx.Err(); err != nil {
		return TokenSource{}, err
	}
	var id [entryIDSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		return TokenSource{}, err
	}
	source := TokenSource{Type: ManagedStore, Backend: Keychain, Entry: hex.EncodeToString(id[:])}
	account, _, err := s.accounts(source.Entry)
	if err != nil {
		return TokenSource{}, err
	}
	if err := s.system.Put(ctx, account, token); !errors.Is(err, ErrUnavailable) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// The system store may have committed the new entry before cancellation.
			s.discard(source)
		}
		return source, err
	}
	source.Backend = EncryptedFile
	published, err := s.writeEncrypted(ctx, source.entryID(), token)
	if published && err != nil {
		s.discard(source)
	}
	return source, err
}

func (s *Store) publish(ctx context.Context, cfg *Config, previous TokenSource) (string, error) {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", storageError("could not encode the profile configuration", err)
	}
	published, err := writePrivate(ctx, filepath.Join(s.dir, configFile), append(raw, '\n'))
	if !published {
		return "", storageError("could not publish the profile configuration", err)
	}
	if err != nil {
		return "profile was published, but its directory could not be synced", nil
	}
	if previous.Type == ManagedStore && !referenced(cfg, previous) {
		if err := s.deleteManaged(context.WithoutCancel(ctx), previous); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "could not clean up the unreferenced managed credential", nil
		}
	}
	return "", nil
}

func referenced(cfg *Config, source TokenSource) bool {
	entry := source.entryID()
	for _, p := range cfg.Profiles {
		if p.TokenSource.Type == ManagedStore && p.TokenSource.Backend == source.Backend && p.TokenSource.entryID() == entry {
			return true
		}
	}
	return false
}

func (s *Store) discard(source TokenSource) {
	_ = s.deleteManaged(context.Background(), source) //nolint:errcheck // preserve the original failure
}

func (s *Store) deleteManaged(ctx context.Context, source TokenSource) error {
	if source.Backend == EncryptedFile {
		if entry, err := hex.DecodeString(source.Entry); err != nil || len(entry) != entryIDSize {
			return invalidProfile("profile has an invalid encrypted credential reference")
		}
		return os.Remove(s.encryptedPath(source.entryID()))
	}
	if source.Backend != Keychain || !validID(source.Entry) {
		return invalidProfile("profile has an invalid system credential reference")
	}
	account, legacy, err := s.accounts(source.Entry)
	if err != nil {
		return err
	}
	err = s.system.Delete(ctx, account)
	if errors.Is(err, fs.ErrNotExist) && legacy != "" {
		return s.system.Delete(ctx, legacy)
	}
	return err
}

func storageError(message string, cause error) error {
	if errors.Is(cause, fs.ErrPermission) {
		return output.ErrWithHint("permission", "PERMISSION_DENIED", message, storeHint)
	}
	return output.ErrWithHint("config", "PROFILE_STORAGE_ERROR", message, storeHint)
}
