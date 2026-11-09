package authstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

const (
	maxManagedToken = 64 * 1024
	keyInKeychain   = 1
	keyInFile       = 2
	credentialsDir  = "credentials"
	masterKeyFile   = "master.key"
)

var (
	errKeychainUnavailable   = errors.New("system keychain unavailable")
	errKeychainEntryTooLarge = errors.New("credential exceeds the system Keychain command limit")
)

// Keychain provides system-backed storage for one OS user.
type Keychain interface {
	Read(account string) ([]byte, error)
	Create(account string, data []byte) error
	Remove(account string) error
}

type unavailableKeychain struct{}

// Read reports that no system provider is available.
func (unavailableKeychain) Read(string) ([]byte, error) { return nil, errKeychainUnavailable }

// Create reports that no system provider is available.
func (unavailableKeychain) Create(string, []byte) error { return errKeychainUnavailable }

// Remove reports that no system provider is available.
func (unavailableKeychain) Remove(string) error { return errKeychainUnavailable }

func (s *ManagedStore) account(entry string) (string, error) {
	// There is no account to resolve when the platform has no Keychain. On
	// Windows, resolving the directory can itself hit a legacy path limit.
	if _, unavailable := s.keychain.(unavailableKeychain); unavailable {
		return "", errKeychainUnavailable
	}
	// The same store may be reached through a symlinked parent, such as
	// /tmp and /private/tmp on macOS. Keep those aliases in one namespace.
	dir, err := canonicalManagedDirectory(s.dir)
	if err != nil {
		return "", fmt.Errorf("resolve managed credential directory: %w", err)
	}
	digest := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(digest[:]) + "/" + entry, nil
}

func (s *ManagedStore) readKeychain(entry string) ([]byte, error) {
	account, err := s.account(entry)
	if err != nil {
		return nil, err
	}
	return s.keychain.Read(account)
}

func (s *ManagedStore) createKeychain(entry string, data []byte) error {
	account, err := s.account(entry)
	if err != nil {
		return err
	}
	return s.keychain.Create(account, data)
}

func (s *ManagedStore) encryptedPath(entry string) string {
	return filepath.Join(s.dir, credentialsDir, entry+".enc")
}

func (s *ManagedStore) masterKeyPath() string {
	return filepath.Join(s.dir, credentialsDir, masterKeyFile)
}

func (s *ManagedStore) writeEncrypted(entry, token string) error {
	if err := ensurePrivateDir(filepath.Join(s.dir, credentialsDir)); err != nil {
		return err
	}
	key, location, err := s.masterKeyForWrite()
	if err != nil {
		return err
	}
	blob, err := seal([]byte(token), key)
	if err != nil {
		return err
	}
	committed, err := writeManagedFile(s.encryptedPath(entry), append([]byte{location}, blob...))
	if committed && err != nil {
		return errors.Join(err, s.removeEncrypted(entry))
	}
	return err
}

func (s *ManagedStore) removeEncrypted(entry string) error {
	return removeCredentialFile(s.dir, entry+".enc")
}

func openCredentialRoot(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(credentialsDir)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && info.IsDir()) {
		return root, nil
	}
	if err == nil {
		err = errors.New("managed storage requires a real credentials directory")
	}
	return nil, errors.Join(err, root.Close())
}

func removeCredentialFile(dir, name string) error {
	root, err := openCredentialRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }() //nolint:errcheck // directory handle used only for lookup and removal

	// Keep removal inside the store even if the directory is swapped after Lstat.
	err = root.Remove(filepath.Join(credentialsDir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s *ManagedStore) readEncrypted(entry string) (string, error) {
	blob, err := readCredentialFile(s.dir, entry+".enc", maxManagedToken+64)
	if err != nil {
		return "", err
	}
	if len(blob) == 0 {
		return "", errors.New("invalid encrypted credential")
	}
	key, err := s.masterKey(blob[0])
	if err != nil {
		return "", err
	}
	raw, err := open(blob[1:], key)
	if err != nil {
		return "", fmt.Errorf("decrypt managed credential: %w", err)
	}
	return string(raw), nil
}

func (s *ManagedStore) masterKey(location byte) ([32]byte, error) {
	var raw []byte
	var err error
	switch location {
	case keyInKeychain:
		raw, err = s.readKeychain("master-key")
	case keyInFile:
		raw, err = readCredentialFile(s.dir, masterKeyFile, 32)
	default:
		return [32]byte{}, errors.New("invalid encrypted credential key location")
	}
	if err != nil {
		return [32]byte{}, err
	}
	if len(raw) != 32 {
		return [32]byte{}, errors.New("invalid managed credential master key")
	}
	return [32]byte(raw), nil
}

func (s *ManagedStore) masterKeyForWrite() (key [32]byte, location byte, err error) {
	fileKey, fileErr := s.masterKey(keyInFile)
	key, err = s.masterKey(keyInKeychain)
	fileMissing := errors.Is(fileErr, fs.ErrNotExist)
	keychainMissing := errors.Is(err, fs.ErrNotExist)
	if fileMissing || keychainMissing {
		if checkErr := s.checkMissingMasterKeys(fileMissing, keychainMissing); checkErr != nil {
			return key, 0, checkErr
		}
	}
	switch {
	case err == nil:
		return key, keyInKeychain, nil
	case keychainMissing:
		if _, err = rand.Read(key[:]); err != nil {
			return key, 0, err
		}
		err = s.createKeychain("master-key", key[:])
		if err == nil {
			return key, keyInKeychain, nil
		}
	}
	if !errors.Is(err, errKeychainUnavailable) {
		return key, 0, err
	}
	if fileMissing {
		if _, fileErr = rand.Read(fileKey[:]); fileErr == nil {
			_, fileErr = writeManagedFile(s.masterKeyPath(), fileKey[:])
		}
	}
	return fileKey, keyInFile, fileErr
}

// Check the on-disk headers, including ciphertext restored without a profile.
// Imports hold the write lock throughout this check and key initialization.
func (s *ManagedStore) checkMissingMasterKeys(fileMissing, keychainMissing bool) error {
	root, err := openCredentialRoot(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }() //nolint:errcheck // directory handle used only for reads
	entries, err := fs.ReadDir(root.FS(), credentialsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".enc") {
			continue
		}
		blob, err := readPrivateFile(root, filepath.Join(credentialsDir, entry.Name()), maxManagedToken+64)
		if err != nil {
			return err
		}
		if len(blob) == 0 || (blob[0] != keyInFile && blob[0] != keyInKeychain) {
			return errors.New("cannot determine the master key for existing encrypted credentials")
		}
		if (blob[0] == keyInFile && fileMissing) || (blob[0] == keyInKeychain && keychainMissing) {
			return errors.New("existing encrypted credentials depend on a missing master key")
		}
	}
	return nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, dirPerm); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("managed storage path must be a directory")
	}
	return protectManagedPath(path, info, dirPerm)
}

func readCredentialFile(dir, name string, limit int64) ([]byte, error) {
	root, err := openCredentialRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }() //nolint:errcheck // directory handle used only for reads
	return readPrivateFile(root, filepath.Join(credentialsDir, name), limit)
}

func readPrivateFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("managed storage requires a regular file")
	}
	if err := checkManagedFilePrivacy(filepath.Join(root.Name(), name), info); err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if int64(len(data)) > limit {
		return nil, errors.New("managed credential file exceeds size limit")
	}
	return data, errors.Join(readErr, closeErr)
}

// openProfileLock serializes profile writes and v1 migration.
func openProfileLock(dir string) (*os.File, error) {
	path := filepath.Join(dir, ".managed.lock")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("managed lock must be a regular file")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, secPerm)
	if err != nil {
		return nil, err
	}
	if err := lockManagedFile(lock); err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return lock, nil
}

// retireV1Config runs only after the dedicated config has been committed.
// A v0.19.5 process can replace the old pathname without taking our lock.
func (s *ManagedStore) retireV1Config(cfg *config.ProfileConfig) string {
	const warning = "could not retire the previous v1 configuration"
	active := filepath.Join(s.dir, configFile)
	file, raw, err := readV1ConfigForRetirement(active)
	if err != nil {
		return warning
	}
	if file == nil {
		return ""
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // retirement explicitly syncs the open file
	reserved, err := cfg.ReferencesTokenFile(active)
	if err != nil {
		return warning
	}
	if reserved {
		return "previous v1 configuration retained because a profile uses that path as a Token file"
	}
	// Also cover a retry after the dedicated rename became visible but its
	// directory sync failed. Do not retire the v1 file until both paths are durable.
	dedicatedDir := filepath.Dir(filepath.Join(s.dir, cfg.WriteFile()))
	if err := syncManagedDirectory(dedicatedDir); err != nil {
		return warning
	}
	if dedicatedDir != s.dir {
		if err := syncManagedDirectory(s.dir); err != nil {
			return warning
		}
	}
	return archiveV1Config(file, raw)
}

func readV1ConfigForRetirement(active string) (*os.File, []byte, error) {
	info, err := os.Lstat(active)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	file, err := openV1ConfigForRetirement(active)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, nil, errors.Join(err, file.Close())
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	var old config.ProfileConfig
	if json.Unmarshal(raw, &old) != nil || string(old.Version) != "1" || old.Profiles == nil {
		return nil, nil, file.Close()
	}
	return file, raw, nil
}

func archiveV1Config(active *os.File, raw []byte) string {
	const warning = "could not retire the previous v1 configuration"
	backup, err := writeV1Backup(filepath.Dir(active.Name()), raw)
	if err != nil {
		if backup == "" {
			return warning
		}
		return "could not sync the v1 configuration backup " + filepath.Base(backup)
	}
	if err := clearArchivedV1Config(active, len(raw)); err != nil {
		return warning + ", original bytes retained in " + filepath.Base(backup)
	}
	return ""
}

func writeV1Backup(dir string, raw []byte) (string, error) {
	backup, err := os.CreateTemp(dir, "config.v1-*.bak")
	if err != nil {
		return "", err
	}
	if err := backup.Close(); err != nil {
		_ = os.Remove(backup.Name()) //nolint:errcheck // preserve the primary error
		return "", err
	}
	visible, err := writeManagedFile(backup.Name(), raw)
	if !visible {
		_ = os.Remove(backup.Name()) //nolint:errcheck // only our empty placeholder exists here
		return "", err
	}
	return backup.Name(), err
}

func clearArchivedV1Config(active *os.File, size int) error {
	links, err := v1ConfigLinkCount(active)
	if err != nil || links == 0 {
		return err
	}
	if links > 1 {
		return errors.New("cannot clear a hard-linked v1 configuration")
	}
	// Write only the inode we inspected and backed up. Legacy writers publish
	// by rename, so a replacement at config.json is never moved or overwritten.
	// Padding avoids a second truncate operation and leaves valid legacy JSON.
	retired := bytes.Repeat([]byte{' '}, size)
	copy(retired, `{"profiles":{}}`)
	if _, err := active.WriteAt(retired, 0); err != nil {
		return err
	}
	return active.Sync()
}

// writeManagedFile returns true once replacement is visible, even if a
// subsequent directory sync fails.
func writeManagedFile(path string, data []byte) (bool, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".managed-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:errcheck // no-op after replacement

	if err := secureManagedTemp(tmp); err != nil {
		return false, errors.Join(err, tmp.Close())
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if err := errors.Join(err, tmp.Close()); err != nil {
		return false, err
	}
	return replaceManagedFile(tmp.Name(), path)
}

func secureManagedTemp(tmp *os.File) error {
	info, err := tmp.Stat()
	if err != nil {
		return err
	}
	return protectManagedPath(tmp.Name(), info, secPerm)
}
