package cmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUnifiedAuthListRedactsEnvironmentBearers(t *testing.T) {
	const token = "runtime-fixture-secret"
	const alias = "alias-fixture-secret"
	const mask = "***REDACTED***"
	for _, tc := range []struct {
		name, token, alias, metadata, want string
	}{
		{"ordinary metadata", "", "", "ordinary-target", "ordinary-target"},
		{"canonical token", " " + token + "\n", "", token, mask},
		{"bot alias", "", " " + alias + "\n", alias, mask},
		{"shadowed alias", token, alias, token + "-" + alias, mask + "-" + mask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
			if tc.token != "" {
				t.Setenv("OCTO_TOKEN", tc.token)
			}
			if tc.alias != "" {
				t.Setenv("OCTO_BOT_TOKEN", tc.alias)
			}
			name := "profile-" + tc.metadata
			phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(`{
				"version":1,"current_profile":%q,"profiles":{
					%q:{"api_base_url":%q,"space_id":%q,"token_source":{"type":"token_file","path":"missing-token"}},
					"ordinary":{"api_base_url":"https://ordinary.example","space_id":"ordinary-space","token_source":{"type":"token_file","path":"also-missing"}}
				}}`, name, name, "https://"+tc.metadata+".example", "space-"+tc.metadata))

			// Listing metadata must stay offline even with unreadable references
			// and an explicit credential file that does not exist.
			out, err := phaseOneRun("--format", "json", "--credential-file", filepath.Join(dir, "missing-override"), "auth", "list")
			if err != nil {
				t.Fatalf("offline auth list failed: %v (%s)", err, out)
			}
			for _, bearer := range []string{tc.token, tc.alias} {
				if bearer = strings.TrimSpace(bearer); bearer != "" && strings.Contains(out, bearer) {
					t.Fatal("auth list disclosed an environment bearer in profile metadata")
				}
			}
			var result struct {
				OK   bool `json:"ok"`
				Data struct {
					Count          int                 `json:"count"`
					CurrentProfile string              `json:"current_profile"`
					Profiles       []map[string]string `json:"profiles"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("decode auth list: %v", err)
			}
			want := []map[string]string{
				{"profile": "ordinary", "api_base_url": "https://ordinary.example", "space_id": "ordinary-space"},
				{"profile": "profile-" + tc.want, "api_base_url": "https://" + tc.want + ".example", "space_id": "space-" + tc.want},
			}
			if !result.OK || result.Data.Count != 2 || result.Data.CurrentProfile != "profile-"+tc.want || !reflect.DeepEqual(result.Data.Profiles, want) {
				t.Fatalf("unexpected auth list metadata: %s", out)
			}
		})
	}
}
