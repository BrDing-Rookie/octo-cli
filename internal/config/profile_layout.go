package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// OwnedProfileDirPrefix names directories allocated exclusively by the CLI.
	OwnedProfileDirPrefix = ".octo-managed-profile-"
	// OwnedProfileMarker publishes a staged configuration after it is durable.
	OwnedProfileMarker = ".published"
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
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var file string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), OwnedProfileDirPrefix) {
			continue
		}
		marker, err := os.Lstat(filepath.Join(dir, entry.Name(), OwnedProfileMarker))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !marker.IsDir() || file != "" {
			return nil, errors.New("invalid or ambiguous managed profile ownership")
		}
		file = filepath.Join(entry.Name(), ManagedProfileFile)
	}
	if file == "" {
		return nil, nil
	}
	cfg, err := loadProfileConfigFile(dir, file, false, true)
	if cfg == nil && err == nil {
		return nil, errors.New("published managed profile configuration is missing")
	}
	return cfg, err
}

type historicalProfileFile struct {
	name string
	cfg  *ProfileConfig
	err  error
	link bool
}

func loadUnownedProfiles(dir string, allowLegacy, writable bool) (*ProfileConfig, error) {
	old, oldErr := loadProfileConfigFile(dir, oldProfileFile, allowLegacy, writable)
	files := []historicalProfileFile{inspectHistoricalFile(dir, ManagedProfileFile)}
	// A regular Token or symlink at the old alternate directory is not a
	// configuration candidate. Do not probe children through that pathname.
	if info, err := os.Lstat(filepath.Join(dir, profileCollisionDir)); err == nil && info.IsDir() {
		files = append(files, inspectHistoricalFile(dir, filepath.Join(profileCollisionDir, ManagedProfileFile)))
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var evidence []*ProfileConfig
	if old != nil {
		evidence = []*ProfileConfig{old}
	} else {
		evidence = archivedV1Profiles(dir)
	}
	cfg, err := selectHistoricalProfiles(dir, files, evidence, old != nil)
	if cfg != nil || err != nil {
		return cfg, err
	}
	return old, oldErr
}

func inspectHistoricalFile(dir, name string) historicalProfileFile {
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return historicalProfileFile{name: name, link: true, err: fmt.Errorf("symlinked profile configuration (%s)", name)}
	}
	cfg, err := loadProfileConfigFile(dir, name, false, true)
	return historicalProfileFile{name: name, cfg: cfg, err: err}
}

func selectHistoricalProfiles(dir string, files []historicalProfileFile, evidence []*ProfileConfig, activeV1 bool) (*ProfileConfig, error) {
	var selected *ProfileConfig
	var broken, linked error
	var external bool
	for _, file := range files {
		if file.cfg == nil && file.err == nil {
			continue
		}
		reserved, err := historicalFileIsToken(dir, file, evidence, activeV1)
		if err != nil {
			return nil, err
		}
		if reserved {
			external = true
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
	if external && !activeV1 {
		return nil, errors.New("previous managed profile configuration is missing")
	}
	return nil, nil
}

func historicalFileIsToken(dir string, file historicalProfileFile, evidence []*ProfileConfig, activeV1 bool) (bool, error) {
	path := filepath.Join(dir, file.name)
	reserved, err := profilePathWasToken(evidence, path)
	if err != nil || !reserved {
		return false, err
	}
	return !activeV1 || file.link || file.cfg != nil || isOpaqueProfileTokenFile(path), nil
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
