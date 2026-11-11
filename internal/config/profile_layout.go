package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	// OwnedProfileDirPrefix names directories allocated exclusively by the CLI.
	OwnedProfileDirPrefix = ".octo-managed-profile-"
	// OwnedProfileMarker holds the journal for the selected store.
	OwnedProfileMarker = ".retirement"
	// OwnedProfileAnchor is the single publication point at the config root.
	OwnedProfileAnchor = ".managed-profile"
	// OwnedProfileSeal is the immutable file that the anchor hard-links to.
	OwnedProfileSeal = ".authority"
	// OwnedProfileStagePrefix names temporary root links before publication.
	OwnedProfileStagePrefix = ".managed-profile-stage-"
	legacyPublishedMarker   = ".published"
)

func loadProfileConfigIn(dir string, allowLegacy, writable bool) (*ProfileConfig, error) {
	if cfg, err := loadPublishedProfiles(dir); cfg != nil || err != nil {
		return cfg, err
	}
	cfg, err := loadUnownedProfiles(dir, allowLegacy, writable)
	// The migration may have published while we were inspecting old paths.
	if published, publishErr := loadPublishedProfiles(dir); published != nil || publishErr != nil {
		return published, publishErr
	}
	return cfg, err
}

func loadPublishedProfiles(dir string) (*ProfileConfig, error) {
	anchor := filepath.Join(dir, OwnedProfileAnchor)
	name, err := readPublicationAnchor(anchor)
	if os.IsNotExist(err) {
		unverified := rejectUnverifiedPublications(dir)
		name, err = readPublicationAnchor(anchor)
		if os.IsNotExist(err) {
			return nil, unverified
		}
	}
	if err != nil {
		return nil, err
	}
	file := filepath.Join(name, ManagedProfileFile)
	if err := checkPublishedProfileOwnership(dir, name); err != nil {
		return nil, err
	}
	cfg, err := loadProfileConfigFile(dir, file, false, true)
	if cfg == nil && err == nil {
		return nil, errors.New("published managed profile configuration is missing")
	}
	return cfg, err
}

func readPublicationAnchor(anchor string) (string, error) {
	info, err := os.Lstat(anchor)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 128 {
		return "", errors.New("invalid managed profile publication anchor")
	}
	raw, err := os.ReadFile(anchor)
	if err != nil {
		return "", fmt.Errorf("read managed profile publication anchor: %v", err)
	}
	name, newline := strings.CutSuffix(string(raw), "\n")
	suffix, prefix := strings.CutPrefix(name, OwnedProfileDirPrefix)
	if !newline || !prefix || suffix == "" || strings.Trim(suffix, "0123456789") != "" {
		return "", errors.New("invalid managed profile publication directory")
	}
	parent := filepath.Join(filepath.Dir(anchor), name)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", errors.New("managed profile publication directory is missing or invalid")
	}
	seal, err := os.Lstat(filepath.Join(parent, OwnedProfileSeal))
	if err != nil || !seal.Mode().IsRegular() || !os.SameFile(info, seal) {
		return "", errors.New("managed profile publication has no matching authority file")
	}
	return name, nil
}

func rejectUnverifiedPublications(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), OwnedProfileDirPrefix) {
			continue
		}
		parent := filepath.Join(dir, entry.Name())
		_, err := os.Lstat(filepath.Join(parent, legacyPublishedMarker))
		if !os.IsNotExist(err) {
			return errors.New("previous managed profile publication has no verified authority")
		}
		seal, err := os.Lstat(filepath.Join(parent, OwnedProfileSeal))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !seal.Mode().IsRegular() {
			return errors.New("invalid managed profile authority")
		}
		stage, err := os.Lstat(filepath.Join(dir, OwnedProfileStagePrefix+entry.Name()))
		if err != nil || !stage.Mode().IsRegular() || !os.SameFile(stage, seal) {
			return errors.New("managed profile publication anchor is missing")
		}
	}
	return nil
}

func checkPublishedProfileOwnership(dir, name string) error {
	// The original v1 configuration can disqualify even an anchored store
	// when it reserves one of its paths for an external provider.
	old, err := loadProfileConfigFile(dir, oldProfileFile, true, false)
	if err != nil || old == nil {
		return nil
	}
	profileDir := filepath.Join(dir, name)
	for _, path := range []string{
		filepath.Join(dir, OwnedProfileAnchor), profileDir,
		filepath.Join(profileDir, OwnedProfileSeal), filepath.Join(profileDir, OwnedProfileMarker),
		filepath.Join(profileDir, ManagedProfileFile),
	} {
		reserved, err := old.ReferencesTokenFile(path)
		if err != nil {
			return err
		}
		if reserved {
			return errors.New("published profile path may be an external Token file")
		}
	}
	return nil
}

type historicalProfileFile struct {
	name string
	cfg  *ProfileConfig
	err  error
	link bool
}

func loadUnownedProfiles(dir string, allowLegacy, writable bool) (*ProfileConfig, error) {
	old, oldErr := loadProfileConfigFile(dir, oldProfileFile, allowLegacy, writable)
	// An unmarked dedicated file may be a Token referenced by the old
	// configuration. If that configuration is unreadable, neither the
	// candidate's contents nor its filename can establish its authority.
	if oldErr != nil && !errors.Is(oldErr, errLegacyProfileConfig) {
		return nil, oldErr
	}
	if old != nil {
		// An archive can flag a path as ambiguous even after the historical
		// configuration that used that Token path has disappeared.
		reserved, err := profilePathWasToken(archivedV1Profiles(dir), filepath.Join(dir, oldProfileFile))
		if err != nil {
			return nil, err
		}
		if reserved {
			return nil, errors.New("original profile configuration path may be an external Token file")
		}
	}
	files := []historicalProfileFile{inspectHistoricalFile(dir, ManagedProfileFile)}
	// A regular Token or symlink at the old alternate directory is not a
	// configuration candidate. Do not probe children through that pathname.
	if info, err := os.Lstat(filepath.Join(dir, profileCollisionDir)); err == nil && info.IsDir() {
		files = append(files, inspectHistoricalFile(dir, filepath.Join(profileCollisionDir, ManagedProfileFile)))
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := checkHistoricalClaims(dir, old, files); err != nil {
		return nil, err
	}
	cfg, err := selectHistoricalProfiles(dir, files, old)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return old, oldErr
	}
	return corroborateHistoricalProfiles(old, cfg)
}

func corroborateHistoricalProfiles(old, candidate *ProfileConfig) (*ProfileConfig, error) {
	// A root backup is also an allowed external Token path. Even a
	// byte-for-byte match on different inodes cannot establish authority.
	if old == nil {
		return nil, errors.New("previous managed profile configuration has no independent ownership evidence")
	}
	if len(candidate.Profiles) == 0 {
		return candidate, nil // preserve an empty store's suppression of older profiles
	}
	if candidate.CurrentProfile != old.CurrentProfile || !reflect.DeepEqual(candidate.Profiles, old.Profiles) {
		return nil, errors.New("historical profile bindings differ from the original v1 configuration")
	}
	// Matching metadata can migrate from the verified original inode.
	return old, nil
}

// A parseable Token must not get to decide which other parseable file is
// configuration. In particular, config.json may itself be a Token of a
// historical dedicated profile, so check both directions before using it.
func checkHistoricalClaims(dir string, old *ProfileConfig, files []historicalProfileFile) error {
	var candidates []*ProfileConfig
	if old != nil {
		candidates = append(candidates, old)
	}
	for _, file := range files {
		if file.cfg != nil {
			candidates = append(candidates, file.cfg)
		}
	}
	for i, left := range candidates {
		for _, right := range candidates[i+1:] {
			leftClaims, leftErr := left.ReferencesTokenFile(filepath.Join(dir, right.file))
			rightClaims, rightErr := right.ReferencesTokenFile(filepath.Join(dir, left.file))
			if err := errors.Join(leftErr, rightErr); err != nil {
				return err
			}
			if leftClaims && rightClaims || (left == old && (leftClaims || rightClaims)) {
				return errors.New("ambiguous previous managed profile configuration and Token ownership")
			}
		}
	}
	return nil
}

func inspectHistoricalFile(dir, name string) historicalProfileFile {
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return historicalProfileFile{name: name, link: true, err: fmt.Errorf("symlinked profile configuration (%s)", name)}
	}
	cfg, err := loadProfileConfigFile(dir, name, false, true)
	return historicalProfileFile{name: name, cfg: cfg, err: err}
}

func selectHistoricalProfiles(dir string, files []historicalProfileFile, old *ProfileConfig) (*ProfileConfig, error) {
	var selected *ProfileConfig
	var broken, linked error
	for _, file := range files {
		if file.cfg == nil && file.err == nil {
			continue
		}
		reserved, err := historicalFileIsToken(dir, file, old)
		if err != nil {
			return nil, err
		}
		if reserved {
			continue
		}
		if file.link {
			linked = errors.Join(linked, file.err)
			continue
		}
		if file.err != nil {
			broken = errors.Join(broken, file.err)
			continue
		}
		if selected != nil {
			return nil, errors.New("ambiguous previous managed profile configuration")
		}
		selected = file.cfg
	}
	if broken != nil {
		return nil, broken
	}
	if selected != nil {
		return selected, nil
	}
	if linked != nil {
		return nil, linked
	}
	return nil, nil
}

func historicalFileIsToken(dir string, file historicalProfileFile, old *ProfileConfig) (bool, error) {
	if old == nil {
		return false, nil
	}
	path := filepath.Join(dir, file.name)
	reserved, err := old.ReferencesTokenFile(path)
	if err != nil || !reserved {
		return false, err
	}
	return file.link || isOpaqueProfileTokenFile(path), nil
}

func archivedV1Profiles(dir string) []*ProfileConfig {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var configs []*ProfileConfig
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, "config.v1-") || !strings.HasSuffix(name, ".bak") {
			continue
		}
		if cfg, err := loadProfileConfigFile(dir, name, false, true); err == nil && cfg != nil {
			configs = append(configs, cfg)
		}
	}
	return configs
}

func profilePathWasToken(configs []*ProfileConfig, path string) (bool, error) {
	for _, cfg := range configs {
		if reserved, err := cfg.ReferencesTokenFile(path); reserved || err != nil {
			return reserved, err
		}
	}
	return false, nil
}

func isOpaqueProfileTokenFile(path string) bool {
	const limit = 64 * 1024
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > limit {
		return false
	}
	token := bytes.TrimSpace(raw)
	return len(token) != 0 && token[0] != '{' && token[0] != '[' &&
		bytes.IndexFunc(token, func(r rune) bool { return r < '!' || r > '~' }) < 0
}
