package authstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/config"
)

const (
	retirementSuffix      = ".pending"
	retirementStageSuffix = retirementSuffix + "-stage"
)

// retireV1Config runs only after the dedicated config has been committed.
// A v0.19.5 process can replace the old pathname without taking our lock.
func (s *ManagedStore) retireV1Config(cfg *config.ProfileConfig) string {
	const warning = "could not retire the previous v1 configuration"
	active := filepath.Join(s.dir, configFile)
	if err := resumeV1Retirements(active, cfg); err != nil {
		return warning + ", recovery is pending"
	}
	file, raw, err := readV1ConfigForRetirement(active)
	if err != nil {
		return warning + ", inspect config.json and any v1 backup before using the legacy CLI"
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
	file, err := openInspectedConfigFile(active)
	if err != nil || file == nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	var old config.ProfileConfig
	if err := json.Unmarshal(raw, &old); err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if string(old.Version) != "1" || old.Profiles == nil {
		return nil, nil, file.Close()
	}
	return file, raw, nil
}

func openInspectedConfigFile(active string) (*os.File, error) {
	info, err := os.Lstat(active)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file, err := openV1ConfigForRetirement(active)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
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
	pending, err := markV1Retirement(active, backup)
	if err == nil && pending != "" {
		err = finishV1Retirement(active, pending, raw)
	}
	if err != nil {
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

// markV1Retirement pins the inspected inode across process exits. A link made
// during a legacy rename is checked before it can become a recovery marker.
func markV1Retirement(active *os.File, backup string) (string, error) {
	links, err := v1ConfigLinkCount(active)
	if err != nil || links == 0 {
		return "", err
	}
	if links > 1 {
		return "", errors.New("cannot clear a hard-linked v1 configuration")
	}
	pending := backup + retirementSuffix
	stage := backup + retirementStageSuffix
	if err := os.Link(active.Name(), stage); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer func() { _ = os.Remove(stage) }() //nolint:errcheck // unverified links are never used for recovery
	if same, err := sameOpenFile(active, stage); err != nil || !same {
		return "", err
	}
	if committed, err := replaceManagedFile(stage, pending); !committed || err != nil {
		return "", err
	}
	return pending, nil
}

func resumeV1Retirements(active string, cfg *config.ProfileConfig) error {
	dir := filepath.Dir(active)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "config.v1-") && strings.HasSuffix(name, ".bak"+retirementStageSuffix) {
			if err := discardUnpublishedV1Marker(active, filepath.Join(dir, name), cfg); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(name, "config.v1-") || !strings.HasSuffix(name, ".bak"+retirementSuffix) {
			continue
		}
		if !entry.Type().IsRegular() {
			return errors.New("invalid v1 retirement marker")
		}
		if err := resumeV1Retirement(active, filepath.Join(dir, name), cfg); err != nil {
			return err
		}
	}
	return nil
}

// An exit before publication can leave a staging link on the active inode.
// Remove that extra link so a retry can inspect and archive the file again.
func discardUnpublishedV1Marker(active, stage string, cfg *config.ProfileConfig) error {
	current, err := os.Lstat(active)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	link, err := os.Lstat(stage)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !link.Mode().IsRegular() || !os.SameFile(current, link) {
		return nil
	}
	if _, err := readV1Backup(strings.TrimSuffix(stage, retirementStageSuffix)); err != nil {
		return err
	}
	if reserved, err := cfg.ReferencesTokenFile(stage); reserved || err != nil {
		return errors.New("unpublished retirement marker may be a referenced Token file")
	}
	return removeRetirementMarker(stage)
}

func resumeV1Retirement(path, pending string, cfg *config.ProfileConfig) error {
	active, err := openInspectedConfigFile(path)
	if err != nil {
		return err
	}
	if active == nil {
		return removeRetirementMarker(pending)
	}
	defer func() { _ = active.Close() }() //nolint:errcheck // retirement syncs before cleanup
	if same, err := sameOpenFile(active, pending); err != nil || !same {
		if err != nil {
			return err
		}
		return removeRetirementMarker(pending)
	}
	if reserved, err := cfg.ReferencesTokenFile(path); err != nil || reserved {
		return errors.New("retirement target may be a referenced Token file")
	}
	raw, err := readV1Backup(strings.TrimSuffix(pending, retirementSuffix))
	if err != nil {
		return err
	}
	return finishV1Retirement(active, pending, raw)
}

func readV1Backup(backup string) ([]byte, error) {
	info, err := os.Lstat(backup)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("invalid v1 retirement backup")
	}
	raw, err := os.ReadFile(backup)
	if err != nil {
		return nil, err
	}
	var old config.ProfileConfig
	if json.Unmarshal(raw, &old) != nil || string(old.Version) != "1" || old.Profiles == nil {
		return nil, errors.New("invalid v1 retirement backup")
	}
	return raw, nil
}

func sameOpenFile(active *os.File, path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	opened, err := active.Stat()
	return err == nil && info.Mode().IsRegular() && os.SameFile(opened, info), err
}

func finishV1Retirement(active *os.File, pending string, raw []byte) error {
	if same, err := sameOpenFile(active, active.Name()); err != nil || !same {
		if err != nil {
			return err
		}
		return removeRetirementMarker(pending)
	}
	if err := clearArchivedV1Config(active, raw); err != nil {
		return err
	}
	return removeRetirementMarker(pending)
}

func removeRetirementMarker(pending string) error {
	if err := os.Remove(pending); err != nil {
		return err
	}
	return syncManagedDirectory(filepath.Dir(pending))
}

func clearArchivedV1Config(active *os.File, raw []byte) error {
	links, err := v1ConfigLinkCount(active)
	if err != nil || links < 2 {
		return err
	}
	if links > 2 {
		return errors.New("cannot clear a hard-linked v1 configuration")
	}
	// Write only the inode we inspected and backed up. Legacy writers publish
	// by rename, so a replacement at config.json is never moved or overwritten.
	// Padding avoids a second truncate operation and leaves valid legacy JSON.
	retired := bytes.Repeat([]byte{' '}, len(raw))
	copy(retired, `{"profiles":{}}`)
	current, err := io.ReadAll(io.NewSectionReader(active, 0, int64(len(raw))+1))
	if err != nil {
		return err
	}
	if len(current) != len(raw) {
		return errors.New("v1 configuration size changed during retirement")
	}
	for i, value := range current {
		if value != raw[i] && value != retired[i] {
			return errors.New("v1 configuration contents changed during retirement")
		}
	}
	if _, err := active.WriteAt(retired, 0); err != nil {
		return err
	}
	return active.Sync()
}
