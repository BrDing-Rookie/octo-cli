package config

import (
	"os"
	"path/filepath"
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
