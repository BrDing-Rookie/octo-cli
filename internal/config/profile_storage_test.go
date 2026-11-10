package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyProfileRecognitionIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		legacy    bool
	}{
		{"empty legacy", `{"profiles":{}}`, true},
		{"legacy profile", `{"profiles":{"target":{"robot_id":"bot","bot_kind":"user_bot","created_at":"2026-11-06T01:00:00Z","api_base_url":"https://gateway.example","space_id":"S1"}}}`, true},
		{"legacy CLI profile without robot ID", `{"profiles":{"target":{"bot_kind":"unknown","created_at":"2026-11-06T01:00:00Z"}}}`, true},
		{"unversioned Space only", `{"profiles":{"target":{"space_id":"S1"}}}`, false},
		{"unknown field", `{"profiles":{"target":{"robot_id":"bot","unknown":true}}}`, false},
		{"null entry", `{"profiles":{"target":null}}`, false},
		{"versioned field", `{"current_profile":"target","profiles":{"target":{"robot_id":"bot"}}}`, false},
		{"null version", `{"version":null,"profiles":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadProfileConfigIn(dir, true)
			if cfg != nil || (err == nil) != tc.legacy {
				t.Fatalf("load: %#v, %v, expected recognized legacy=%t", cfg, err, tc.legacy)
			}
			if _, err := LoadProfileConfigIn(dir, false); err == nil {
				t.Fatal("strict writes must refuse unversioned or corrupt configuration")
			}
		})
	}
}

func TestProfileConfigDistinguishesTokenFileFromDedicatedStore(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, ManagedProfileFile)
	if err := os.WriteFile(primary, []byte("fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "external-token")
	if err := os.Link(primary, alias); err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf(`{"version":1,"profiles":{"old":{"token_source":{"type":"token_file","path":%q}}}}`, alias)
	if err := os.WriteFile(filepath.Join(dir, oldProfileFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadWritableProfileConfigIn(dir, true)
	if err != nil || cfg == nil || !cfg.NeedsMigration() {
		t.Fatalf("referenced token file must remain external: %v", err)
	}
	path := filepath.Join(dir, profileCollisionDir, ManagedProfileFile)
	if err := os.WriteFile(primary, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
		t.Fatalf("partial JSON must remain a configuration error: %v", err)
	}
	if err := os.WriteFile(primary, []byte("fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil || !strings.Contains(err.Error(), profileCollisionDir) {
		t.Fatalf("invalid alternate configuration must not fall back to the old file: %v", err)
	}
}

func TestDedicatedProfileFileIsAuthoritative(t *testing.T) {
	dir := t.TempDir()
	old := `{"version":1,"current_profile":"old","profiles":{"old":{"space_id":"S1"}}}`
	if err := os.WriteFile(filepath.Join(dir, oldProfileFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); err != nil || cfg == nil || !cfg.NeedsMigration() {
		t.Fatalf("load original v1 file: %v", err)
	}
	path := filepath.Join(dir, ManagedProfileFile)
	if err := os.WriteFile(path, []byte(`{"version":1,"profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); err != nil || cfg == nil || len(cfg.Profiles) != 0 || cfg.NeedsMigration() {
		t.Fatalf("dedicated empty store must mask the original v1 file: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
		t.Fatalf("invalid dedicated file must not fall back: %#v, %v", cfg, err)
	}
}

func TestV1RemainsReadableWhenBothHistoricalPathsAreTokenFiles(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, ManagedProfileFile)
	alternate := filepath.Join(dir, profileCollisionDir, ManagedProfileFile)
	if err := os.MkdirAll(filepath.Dir(alternate), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{primary, alternate} {
		if err := os.WriteFile(path, []byte("fixture-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v1 := fmt.Sprintf(`{"version":1,"profiles":{"one":{"token_source":{"type":"token_file","path":%q}},"two":{"token_source":{"type":"token_file","path":%q}}}}`, primary, alternate)
	if err := os.WriteFile(filepath.Join(dir, oldProfileFile), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); err != nil || cfg == nil || len(cfg.Profiles) != 2 {
		t.Fatalf("the original profiles must remain readable: %v", err)
	}
	if cfg, err := LoadWritableProfileConfigIn(dir, true); err != nil || cfg == nil || !cfg.NeedsMigration() {
		t.Fatalf("migration should be able to use an owned location: %v", err)
	}
}

func TestHistoricalAlternateRequiresCorroboratingOriginalV1(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, ManagedProfileFile)
	alternate := filepath.Join(dir, profileCollisionDir, ManagedProfileFile)
	if err := os.MkdirAll(filepath.Dir(alternate), 0o700); err != nil {
		t.Fatal(err)
	}
	const owned = `{"version":1,"profiles":{"work":{"api_base_url":"https://trusted.example","token_source":{"type":"token_file","path":"profiles.json"}}}}`
	files := map[string]string{
		primary:                                 "external-token",
		alternate:                               owned,
		filepath.Join(dir, "config.v1-123.bak"): owned,
	}
	for name, contents := range files {
		if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
		t.Fatal("a matching root archive does not establish ownership")
	}
	if err := os.WriteFile(filepath.Join(dir, oldProfileFile), []byte(owned), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadProfileConfigIn(dir, true)
	if err != nil || cfg == nil || !cfg.NeedsMigration() || cfg.Profiles["work"] == nil || cfg.Profiles["work"].APIBaseURL != "https://trusted.example" {
		t.Fatalf("corroborated metadata must migrate from the original v1 inode: %v", err)
	}
	if err := os.WriteFile(alternate, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
		t.Fatal("a damaged historical alternate must not fall back to its Token file")
	}
}

func TestHistoricalProfileRejectsHardLinkedArchive(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, ManagedProfileFile)
	if err := os.WriteFile(candidate, []byte(`{"version":1,"profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(candidate, filepath.Join(dir, "config.v1-1.bak")); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadProfileConfigIn(dir, true); cfg != nil || err == nil {
		t.Fatal("a second path to the candidate inode is not independent evidence")
	}
}
