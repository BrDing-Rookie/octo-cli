// Package authstore manages the CLI's versioned profiles and credentials.
package authstore

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

const (
	// EnvConfigDir overrides the isolated configuration directory.
	EnvConfigDir = "OCTO_CONFIG_DIR"
	// DefaultProfile names the first implicit import.
	DefaultProfile = "default"

	// ManagedStore identifies a credential imported and maintained by the CLI.
	ManagedStore = "managed_store"
	// TokenFile identifies a caller-owned credential file.
	TokenFile = "token_file"
	// Keychain identifies the native credential backend.
	Keychain = "keychain"
	// EncryptedFile identifies the private AES-GCM fallback.
	EncryptedFile = "encrypted_file"
)

// Config is the on-disk version 1 profile index.
type Config struct {
	Version        int                `json:"version"`
	CurrentProfile string             `json:"current_profile"`
	Profiles       map[string]Profile `json:"profiles"`
}

// Profile binds a credential source to a business origin and Space.
type Profile struct {
	APIBaseURL  string      `json:"api_base_url"`
	SpaceID     string      `json:"space_id"`
	TokenSource TokenSource `json:"token_source"`
	Verified    *Verified   `json:"verified,omitempty"`
}

// TokenSource is a reference to either an immutable managed entry or a
// caller-owned file. Relative Profile paths are relative to the config directory.
type TokenSource struct {
	Type    string `json:"type"`
	Backend string `json:"backend,omitempty"`
	Entry   string `json:"entry,omitempty"`
	Path    string `json:"path,omitempty"`
}

// entryID returns the storage identity of a validated managed reference.
// Encrypted files and their associated data use lowercase hexadecimal IDs.
func (s TokenSource) entryID() string {
	if s.Backend == EncryptedFile {
		return strings.ToLower(s.Entry)
	}
	return s.Entry
}

// Verified records the non-secret fields checked during a managed import.
type Verified struct {
	TokenID string `json:"token_id"`
	OwnerID string `json:"owner_id"`
	SpaceID string `json:"space_id"`
}

// ValidateName checks a profile name without echoing user input in errors.
func ValidateName(name string) error {
	if !validID(name) {
		return output.ErrValidation("invalid profile name", "use a nonempty profile name without whitespace or control characters")
	}
	return nil
}

// ValidateSpace checks the Space ID used by stored profiles and requests.
func ValidateSpace(space string) error {
	if !validID(space) {
		return output.ErrValidation("a valid Space ID is required", "set --space or OCTO_SPACE_ID")
	}
	return nil
}

func validID(value string) bool {
	return utf8.ValidString(value) && credential.ValidateBearer(value) == nil
}

// Valid reports whether all required verifier fields are populated.
func (v Verified) Valid() bool {
	return validID(v.TokenID) && validID(v.OwnerID) && validID(v.SpaceID)
}

// Scope validates and normalizes a Profile's origin and checks its Space binding.
func (p *Profile) Scope() (Profile, error) {
	origin, err := config.NormalizeAPIBaseURL(p.APIBaseURL)
	if err != nil {
		return Profile{}, invalidProfile("profile has an invalid API origin")
	}
	if err := ValidateSpace(p.SpaceID); err != nil {
		return Profile{}, invalidProfile("profile has an invalid Space ID")
	}
	if p.Verified != nil && (!p.Verified.Valid() || p.Verified.SpaceID != p.SpaceID) {
		return Profile{}, invalidProfile("profile has invalid or conflicting verified metadata")
	}
	normalized := *p
	normalized.APIBaseURL = origin
	return normalized, nil
}

// ValidateSource checks the persisted reference before opening a credential.
func (p *Profile) ValidateSource() error {
	source := p.TokenSource
	switch source.Type {
	case TokenFile:
		if source.Path == "" || strings.ContainsRune(source.Path, 0) || source.Backend != "" || source.Entry != "" || p.Verified != nil {
			return invalidProfile("profile has an invalid external credential reference")
		}
	case ManagedStore:
		if p.Verified == nil || source.Path != "" || !validID(source.Entry) {
			return invalidProfile("profile has an invalid managed credential reference")
		}
		switch source.Backend {
		case Keychain:
		case EncryptedFile:
			if entry, err := hex.DecodeString(source.Entry); err != nil || len(entry) != entryIDSize {
				return invalidProfile("profile has an invalid encrypted credential reference")
			}
		default:
			return invalidProfile("profile has an unsupported managed credential backend")
		}
	default:
		return invalidProfile("profile has an unsupported credential source")
	}
	return nil
}

func invalidProfile(message string) error {
	return output.ErrWithHint("config", "INVALID_PROFILE", message, "check the Profile configuration or reimport the credential")
}

func (s *Store) externalPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(s.dir, path)
}
