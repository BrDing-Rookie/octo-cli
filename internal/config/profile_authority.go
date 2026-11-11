package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type publicationAuthority struct {
	Directory string `json:"directory"`
	StoreID   string `json:"store_id"`
	FileID    string `json:"file_id"`
}

// WriteProfileAuthority marks a newly created file as belonging to this store
// and this inode. Byte writes and hard links to ordinary Token files cannot
// create the platform proof.
func WriteProfileAuthority(file *os.File, dir string) error {
	record, err := publicationIdentity(file, filepath.Dir(dir))
	if err != nil {
		return err
	}
	record.Directory = filepath.Base(dir)
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeAuthorityProof(file, raw)
}

func publicationIdentity(file *os.File, root string) (publicationAuthority, error) {
	fileID, err := authorityFileID(file)
	if err != nil {
		return publicationAuthority{}, err
	}
	store, err := os.Open(root)
	if err != nil {
		return publicationAuthority{}, err
	}
	storeID, err := authorityFileID(store)
	return publicationAuthority{StoreID: storeID, FileID: fileID}, errors.Join(err, store.Close())
}

func verifyAuthorityProof(anchor string, info os.FileInfo) (string, error) {
	file, err := os.Open(anchor)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // only reading the authority
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", errors.New("managed profile publication anchor changed")
	}
	raw, err := readAuthorityProof(file)
	if err != nil {
		return "", err
	}
	var record publicationAuthority
	if json.Unmarshal(raw, &record) != nil {
		return "", errors.New("invalid managed profile publication proof")
	}
	expected, err := publicationIdentity(file, filepath.Dir(anchor))
	if err != nil {
		return "", err
	}
	if record.StoreID != expected.StoreID || record.FileID != expected.FileID {
		return "", errors.New("managed profile publication proof belongs to a different file or store")
	}
	return record.Directory, nil
}
