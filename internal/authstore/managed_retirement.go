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

type v1RetirementJournal struct {
	active   string
	owned    string
	profiles *config.ProfileConfig
	previous *config.Profile
}

func (j v1RetirementJournal) protects(path string) (bool, error) {
	return j.profiles.ReferencesTokenFile(path, j.previous)
}

// retireV1Config runs only after the dedicated config has been committed.
// A v0.19.5 process can replace the old pathname without taking our lock.
func (s *ManagedStore) retireV1Config(cfg *config.ProfileConfig, previous *config.Profile) string {
	const warning = "could not retire the previous v1 configuration"
	active := filepath.Join(s.dir, configFile)
	dedicatedDir := filepath.Dir(filepath.Join(s.dir, cfg.WriteFile()))
	journal := v1RetirementJournal{
		active: active, owned: filepath.Join(dedicatedDir, config.OwnedProfileMarker),
		profiles: cfg, previous: previous,
	}
	if err := journal.resume(); err != nil {
		return warning + ", recovery is pending"
	}
	reserved, err := journal.protects(active)
	if err != nil {
		return warning
	}
	if reserved {
		return "previous configuration path retained because a profile uses it as a Token file"
	}
	file, raw, err := readV1ConfigForRetirement(active)
	if err != nil {
		return warning + ", inspect config.json and any v1 backup before using the legacy CLI"
	}
	if file == nil {
		return ""
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // retirement explicitly syncs the open file
	// Also cover a retry after the dedicated rename became visible but its
	// directory sync failed. Do not retire the v1 file until both paths are durable.
	if err := syncManagedDirectory(dedicatedDir); err != nil {
		return warning
	}
	if dedicatedDir != s.dir {
		if err := syncManagedDirectory(s.dir); err != nil {
			return warning
		}
	}
	return journal.archive(file, raw)
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

func (j v1RetirementJournal) archive(active *os.File, raw []byte) string {
	const warning = "could not retire the previous v1 configuration"
	backup, err := writeV1Backup(filepath.Dir(active.Name()), raw)
	if err != nil {
		if backup == "" {
			return warning
		}
		return "could not sync the v1 configuration backup " + filepath.Base(backup)
	}
	pending, err := j.mark(active, backup)
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

// mark pins the inspected inode across process exits. A link made
// during a legacy rename is checked before it can become a recovery marker.
func (j v1RetirementJournal) mark(active *os.File, backup string) (string, error) {
	links, err := v1ConfigLinkCount(active)
	if err != nil || links == 0 {
		return "", err
	}
	if links > 1 {
		return "", errors.New("cannot clear a hard-linked v1 configuration")
	}
	pending := filepath.Join(j.owned, filepath.Base(backup)+retirementSuffix)
	stage := pending + "-stage"
	for _, path := range []string{pending, stage} {
		if reserved, err := j.protects(path); err != nil || reserved {
			return "", errors.New("retirement marker path may be a referenced Token file")
		}
	}
	if _, err := os.Lstat(pending); !errors.Is(err, fs.ErrNotExist) {
		return "", errors.New("retirement marker path is already occupied or inaccessible")
	}
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

func (j v1RetirementJournal) resume() error {
	info, err := os.Lstat(j.owned)
	if err != nil || !info.IsDir() {
		return errors.New("managed retirement directory is unavailable")
	}
	if err := j.resumeDirectory(j.owned, true); err != nil {
		return err
	}
	return j.resumeDirectory(filepath.Dir(j.active), false)
}

func (j v1RetirementJournal) resumeDirectory(dir string, owned bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		suffix := retirementMarkerSuffix(name)
		if suffix == "" || !entry.Type().IsRegular() {
			continue
		}
		marker := filepath.Join(dir, name)
		reserved, err := j.protects(marker)
		if err != nil && owned {
			return err
		}
		if reserved || err != nil {
			continue
		}
		if err := j.resumeMarker(marker, suffix); err != nil {
			return err
		}
	}
	return nil
}

func retirementMarkerSuffix(name string) string {
	if strings.HasPrefix(name, "config.v1-") {
		for _, suffix := range []string{retirementSuffix, retirementStageSuffix} {
			if strings.HasSuffix(name, ".bak"+suffix) {
				return suffix
			}
		}
	}
	return ""
}

func (j v1RetirementJournal) resumeMarker(marker, suffix string) error {
	active, err := openMatchingRetirementFile(j.active, marker)
	if err != nil {
		return err
	}
	// A detached link cannot prove that it pinned the inspected active file.
	// Retain it even in the owned directory rather than guessing from its name.
	if active == nil {
		return nil
	}
	defer func() { _ = active.Close() }() //nolint:errcheck // retirement syncs before cleanup
	backup := filepath.Join(filepath.Dir(j.active), strings.TrimSuffix(filepath.Base(marker), suffix))
	raw, err := readV1Backup(backup)
	if err != nil {
		return err
	}
	if suffix == retirementStageSuffix {
		if err := checkRetirementBytes(active, raw, retiredV1Bytes(raw)); err != nil {
			return err
		}
		return removeRetirementMarker(marker)
	}
	if reserved, err := j.protects(j.active); err != nil || reserved {
		return errors.New("retirement target may be a referenced Token file")
	}
	return finishV1Retirement(active, marker, raw)
}

func openMatchingRetirementFile(active, marker string) (*os.File, error) {
	info, err := os.Lstat(active)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	link, err := os.Lstat(marker)
	if err != nil {
		return nil, err
	}
	if !link.Mode().IsRegular() || !os.SameFile(info, link) {
		return nil, nil
	}
	file, err := openInspectedConfigFile(active)
	if err != nil || file == nil {
		return nil, err
	}
	if same, err := sameOpenFile(file, marker); err != nil || !same {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
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
		return err
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
	retired := retiredV1Bytes(raw)
	if err := checkRetirementBytes(active, raw, retired); err != nil {
		return err
	}
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
	if _, err := active.WriteAt(retired, 0); err != nil {
		return err
	}
	return active.Sync()
}

func retiredV1Bytes(raw []byte) []byte {
	retired := bytes.Repeat([]byte{' '}, len(raw))
	copy(retired, `{"profiles":{}}`)
	return retired
}

func checkRetirementBytes(active *os.File, raw, retired []byte) error {
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
	return nil
}
