package authstore

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	retirementWarning     = "could not retire the previous v1 configuration"
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
	active := filepath.Join(s.dir, configFile)
	dedicatedDir := filepath.Dir(filepath.Join(s.dir, cfg.WriteFile()))
	journal := v1RetirementJournal{
		active: active, owned: filepath.Join(dedicatedDir, config.OwnedProfileMarker),
		profiles: cfg, previous: previous,
	}
	reserved, err := journal.protects(active)
	if err != nil {
		return retirementWarning
	}
	if reserved {
		return "previous configuration path retained because a profile uses it as a Token file"
	}
	if cfg.V1Retirement == nil {
		return ""
	}
	// Also cover a retry after publication became visible but its directory
	// sync failed. The journal must be durable before it can change config.json.
	if err := errors.Join(syncManagedDirectory(dedicatedDir), syncManagedDirectory(s.dir)); err != nil {
		return retirementWarning
	}
	marker, err := journal.resume()
	if err != nil {
		return retirementWarning + ", recovery is pending"
	}
	// Disable recovery before unlinking the pin. If interrupted here, a
	// leftover link cannot be adopted by a later mutation.
	cfg.V1Retirement = nil
	write := s.persist(context.Background(), cfg, nil)
	if !write.committed || write.err != nil {
		return retirementWarning + ", recovery record could not be cleared"
	}
	if marker != "" {
		if err := removeRetirementMarker(marker); err != nil {
			return "could not remove the completed v1 retirement marker"
		}
	}
	return ""
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
	file, err := openExistingManagedFile(active)
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

// prepareMigration records retirement intent only for the authoritative v1
// file loaded for this mutation. A later write cannot infer ownership from
// the contents of config.json, which may have been an external Token.
func (j v1RetirementJournal) prepareMigration(persistRecord func() error) string {
	if !j.profiles.NeedsMigration() {
		return ""
	}
	reserved, err := j.protects(j.active)
	if err != nil || reserved {
		// The post-commit check reports the preserved Token path.
		return ""
	}
	active, raw, err := readV1ConfigForRetirement(j.active)
	if err != nil {
		return retirementWarning + ", inspect config.json before using the legacy CLI"
	}
	if active == nil {
		return ""
	}
	defer func() { _ = active.Close() }() //nolint:errcheck // preparing the journal only reads the active file
	info, err := active.Stat()
	if err != nil || !j.profiles.MatchesV1Source(info, raw) {
		return retirementWarning + ", the migration source changed"
	}
	if err := j.discardAbandonedPins(active, raw); err != nil {
		return retirementWarning + ", could not inspect a previous migration"
	}
	return j.stageRetirement(active, raw, persistRecord)
}

func (j v1RetirementJournal) stageRetirement(active *os.File, raw []byte, persistRecord func() error) string {
	backup, err := writeV1Backup(filepath.Dir(j.active), raw)
	if err != nil {
		if backup == "" {
			return retirementWarning
		}
		return "could not sync the v1 configuration backup " + filepath.Base(backup)
	}
	for _, suffix := range []string{retirementSuffix, retirementStageSuffix} {
		target := filepath.Join(j.owned, filepath.Base(backup)+suffix)
		if reserved, err := j.protects(target); err != nil || reserved {
			return retirementWarning + ", original bytes retained in " + filepath.Base(backup)
		}
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			return retirementWarning + ", original bytes retained in " + filepath.Base(backup)
		}
	}
	j.profiles.V1Retirement = &config.V1Retirement{Backup: filepath.Base(backup), Digest: sha256.Sum256(raw)}
	if err := persistRecord(); err != nil {
		j.profiles.V1Retirement = nil
		return retirementWarning + ", could not persist the retirement record"
	}
	if _, err := j.mark(active, backup); err != nil {
		return retirementWarning + ", original bytes retained in " + filepath.Base(backup)
	}
	return ""
}

// Only a staged publication with a durable record can claim an abandoned pin.
func (j v1RetirementJournal) discardAbandonedPins(active *os.File, raw []byte) error {
	links, err := managedFileLinkCount(active)
	if err != nil || links <= 1 {
		return err
	}
	root := filepath.Dir(j.active)
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), config.OwnedProfileDirPrefix) {
			if err := j.discardStagedPins(active, raw, root, entry.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (j v1RetirementJournal) discardStagedPins(active *os.File, raw []byte, root, name string) error {
	parent := filepath.Join(root, name)
	stage := filepath.Join(root, config.OwnedProfileStagePrefix+name)
	seal := filepath.Join(parent, config.OwnedProfileSeal)
	metadata := filepath.Join(parent, config.ManagedProfileFile)
	journal := filepath.Join(parent, config.OwnedProfileMarker)
	if !j.ownsStagedJournal(stage, seal, metadata, journal) {
		return nil
	}
	data, err := readV1Backup(metadata)
	if err != nil {
		return nil
	}
	var cfg config.ProfileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	record := cfg.V1Retirement
	if record == nil || !isV1BackupName(record.Backup) || record.Digest != sha256.Sum256(raw) {
		return nil
	}
	backup := filepath.Join(root, record.Backup)
	for _, suffix := range []string{retirementSuffix, retirementStageSuffix} {
		marker := filepath.Join(journal, record.Backup+suffix)
		if j.isAbandonedPin(active, raw, marker, backup) {
			if err := removeRetirementMarker(marker); err != nil {
				return err
			}
		}
	}
	return nil
}

func (j v1RetirementJournal) ownsStagedJournal(stage, seal, metadata, journal string) bool {
	for _, path := range []string{stage, seal, metadata, journal} {
		if reserved, err := j.protects(path); err != nil || reserved {
			return false
		}
	}
	name, err := config.VerifyProfileAuthority(stage)
	if err != nil || name != filepath.Base(filepath.Dir(seal)) {
		return false
	}
	journalInfo, err := os.Lstat(journal)
	return err == nil && journalInfo.IsDir()
}

func (j v1RetirementJournal) isAbandonedPin(active *os.File, raw []byte, marker, backup string) bool {
	for _, path := range []string{marker, backup} {
		if reserved, err := j.protects(path); err != nil || reserved {
			return false
		}
	}
	same, err := sameOpenFile(active, marker)
	if err != nil || !same || checkRetirementBytes(active, raw, raw) != nil {
		return false
	}
	archived, err := readV1Backup(backup)
	return err == nil && bytes.Equal(archived, raw)
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
	links, err := managedFileLinkCount(active)
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
	if committed, err := replaceManagedFile(context.Background(), stage, pending); !committed || err != nil {
		return "", err
	}
	return pending, nil
}

func (j v1RetirementJournal) resume() (string, error) {
	record := j.profiles.V1Retirement
	if record == nil {
		return "", nil
	}
	if !isV1BackupName(record.Backup) {
		return "", errors.New("invalid v1 retirement record")
	}
	marker := filepath.Join(j.owned, record.Backup+retirementSuffix)
	active, err := openMatchingRetirementFile(j.active, marker)
	// A detached link cannot prove that it pinned the inspected active file.
	// Retain it even in the owned directory rather than guessing from its name.
	if err != nil || active == nil {
		return "", err
	}
	defer func() { _ = active.Close() }() //nolint:errcheck // retirement syncs before cleanup
	backup := filepath.Join(filepath.Dir(j.active), record.Backup)
	for _, path := range []string{j.active, marker, backup} {
		if reserved, err := j.protects(path); err != nil || reserved {
			return "", errors.New("retirement path may be a referenced Token file")
		}
	}
	raw, err := readV1Backup(backup)
	if err != nil || sha256.Sum256(raw) != record.Digest {
		return "", errors.New("v1 retirement backup does not match the published record")
	}
	if same, err := sameOpenFile(active, j.active); err != nil || !same {
		return "", err
	}
	if err := clearArchivedV1Config(active, raw); err != nil {
		return "", err
	}
	return marker, nil
}

func isV1BackupName(name string) bool {
	digits, prefix := strings.CutPrefix(name, "config.v1-")
	digits, suffix := strings.CutSuffix(digits, ".bak")
	return prefix && suffix && digits != "" && strings.Trim(digits, "0123456789") == ""
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
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
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
	links, err := managedFileLinkCount(active)
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
