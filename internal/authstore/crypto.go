package authstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io/fs"
	"path/filepath"
)

const masterKeyFile = "master.key"
const masterKeySize = 32

func (s *Store) encryptedPath(entry string) string {
	return filepath.Join(s.dir, "credential-"+entry+".enc")
}

func (s *Store) writeEncrypted(ctx context.Context, entry, token string) (bool, error) {
	key, err := s.masterKey()
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, masterKeySize)
		if _, err = rand.Read(key); err != nil {
			return false, err
		}
		_, err = writePrivate(ctx, filepath.Join(s.dir, masterKeyFile), key)
	}
	if err != nil {
		return false, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return false, err
	}
	sealed := gcm.Seal(nil, nil, []byte(token), []byte(entry))
	return writePrivate(ctx, s.encryptedPath(entry), sealed)
}

func (s *Store) readEncrypted(entry string) (string, error) {
	key, err := s.masterKey()
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	sealed, err := readPrivate(s.encryptedPath(entry))
	if err != nil {
		return "", err
	}
	data, err := gcm.Open(nil, nil, sealed, []byte(entry))
	return string(data), err
}

func (s *Store) masterKey() ([]byte, error) {
	key, err := readPrivate(filepath.Join(s.dir, masterKeyFile))
	if err == nil && len(key) != masterKeySize {
		return nil, storeError("invalid encryption master key")
	}
	return key, err
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
