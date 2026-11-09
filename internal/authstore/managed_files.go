package authstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

const (
	maxManagedToken = 64 * 1024
	keyInKeychain   = 1
	keyInFile       = 2
)

var errKeychainUnavailable = errors.New("system keychain unavailable")

// Keychain provides system-backed storage for one OS user.
type Keychain interface {
	Read(account string) ([]byte, error)
	Create(account string, data []byte) error
	Remove(account string) error
}

type unavailableKeychain struct{}

func (unavailableKeychain) Read(string) ([]byte, error) { return nil, errKeychainUnavailable }
func (unavailableKeychain) Create(string, []byte) error { return errKeychainUnavailable }
func (unavailableKeychain) Remove(string) error         { return errKeychainUnavailable }

func (s *ManagedStore) account(entry string) string {
	digest := sha256.Sum256([]byte(s.dir))
	return hex.EncodeToString(digest[:]) + "/" + entry
}

func (s *ManagedStore) encryptedPath(entry string) string {
	return filepath.Join(s.dir, "credentials", entry+".enc")
}

func (s *ManagedStore) masterKeyPath() string {
	return filepath.Join(s.dir, "credentials", "master.key")
}

func (s *ManagedStore) writeEncrypted(entry, token string) error {
	if err := ensurePrivateDir(filepath.Join(s.dir, "credentials")); err != nil {
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
		return errors.Join(err, os.Remove(s.encryptedPath(entry)))
	}
	return err
}

func (s *ManagedStore) readEncrypted(entry string) (string, error) {
	blob, err := readPrivateFile(s.encryptedPath(entry), maxManagedToken+64)
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
		raw, err = s.keychain.Read(s.account("master-key"))
	case keyInFile:
		raw, err = readPrivateFile(s.masterKeyPath(), 32)
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

func (s *ManagedStore) masterKeyForWrite() ([32]byte, byte, error) {
	key, err := s.masterKey(keyInKeychain)
	switch {
	case err == nil:
		return key, keyInKeychain, nil
	case errors.Is(err, fs.ErrNotExist):
		if _, err = rand.Read(key[:]); err != nil {
			return key, 0, err
		}
		err = s.keychain.Create(s.account("master-key"), key[:])
		if err == nil {
			return key, keyInKeychain, nil
		}
	}
	if !errors.Is(err, errKeychainUnavailable) {
		return key, 0, err
	}
	key, err = s.masterKey(keyInFile)
	if errors.Is(err, fs.ErrNotExist) {
		if _, err = rand.Read(key[:]); err == nil {
			_, err = writeManagedFile(s.masterKeyPath(), key[:])
		}
	}
	return key, keyInFile, err
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
	if runtime.GOOS != "windows" && info.Mode().Perm() != dirPerm {
		return os.Chmod(path, dirPerm)
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
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

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("managed storage requires a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed storage file must be private")
	}
	return nil
}

func openManagedLock(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if err := validatePrivateFile(info); err != nil {
			return nil, err
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

// writeManagedFile returns true once replacement is visible, even if a
// subsequent directory sync fails.
func writeManagedFile(path string, data []byte) (bool, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".managed-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:errcheck // no-op after replacement

	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return false, err
	}
	return replaceManagedFile(tmp.Name(), path)
}
