package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestUnifiedAuthStatusReadsSelectedProfileOffline(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_PROFILE", "other")
	t.Setenv("OCTO_TOKEN", "runtime-token")
	t.Setenv("OCTO_TOKEN_FILE", filepath.Join(dir, "missing-env-file"))
	t.Setenv("OCTO_API_BASE_URL", "https://ignored.example")
	phaseOneWrite(t, filepath.Join(dir, "token"), "local-status-secret\n")
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{
		"version":1,"current_profile":"other","profiles":{
			"selected":{"api_base_url":"http://127.0.0.1:1/","space_id":"target-space","token_source":{"type":"token_file","path":"token"}},
			"other":null
		}}`)

	out, err := phaseOneRun("--format", "json", "--no-retry", "--verbose", "--profile", "selected",
		"--credential-file", filepath.Join(dir, "missing-flag-file"), "auth", "status")
	assertUnifiedAuthStatus(t, out, err, "readable", "selected", "http://127.0.0.1:1", "target-space", "profile:token_file")
	if strings.Contains(out, "local-status-secret") || strings.Contains(out, "runtime-token") {
		t.Fatal("credential appeared in status output")
	}
}

func TestUnifiedAuthStatusMissingEvenWithLegacyCredentials(t *testing.T) {
	legacy, dir := phaseOneStores(t, "selected", "bot-id")
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	t.Setenv("OCTO_API_BASE_URL", "https://runtime.example")
	t.Setenv("OCTO_BOT_TOKEN", "bf_runtime-token")

	for _, storeDir := range []string{dir, legacy.Dir()} {
		t.Setenv("OCTO_CONFIG_DIR", storeDir)
		out, err := phaseOneRun("--format", "json", "--profile", "selected", "--space", "target-space", "auth", "status")
		assertUnifiedAuthStatus(t, out, err, "missing", "selected", "https://runtime.example", "target-space", "")
	}
}

func TestUnifiedAuthStatusReportsReadFailures(t *testing.T) {
	const (
		external = `{"type":"token_file","path":"token"}`
		managed  = `{"type":"managed_store","backend":"encrypted_file","entry":"0123456789abcdef0123456789abcdef"}`
	)
	profileConfig := func(ref string) string {
		return fmt.Sprintf(`{"version":1,"current_profile":"selected","profiles":{"selected":{
			"api_base_url":"https://status.example","space_id":"target-space","token_source":%s}}}`, ref)
	}
	for _, tc := range []struct {
		name, config, token, message string
		exitCode                     int
	}{
		{"malformed config", "{", "", "invalid config.json", 2},
		{"unrecognized unversioned config", `{"profiles":{"selected":null}}`, "", "unsupported config.json version", 2},
		{"unsupported version", `{"version":2,"profiles":{}}`, "", "unsupported config.json version", 2},
		{"null profile", `{"version":1,"profiles":{"selected":null}}`, "", "selected profile is null", 2},
		{"missing origin", `{"version":1,"profiles":{"selected":{"token_source":` + external + `}}}`, "local-secret", "requires api_base_url", 2},
		{"missing reference", profileConfig("null"), "", "no unified credential configured", 3},
		{"unknown reference", profileConfig(`{"type":"unknown"}`), "", "invalid profile token_source", 2},
		{"missing token file", profileConfig(external), "", "cannot read credential", 3},
		{"missing managed entry", profileConfig(managed), "", "cannot read credential", 3},
		{"legacy token file", profileConfig(external), "bf_legacy-secret", "legacy Token", 3},
		{"conflicting space", profileConfig(external), "local-secret", "does not match the selected profile", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv("OCTO_PROFILE", "selected")
			t.Setenv("OCTO_TOKEN", "runtime-token")
			phaseOneWrite(t, filepath.Join(dir, "config.json"), tc.config)
			if tc.token != "" {
				phaseOneWrite(t, filepath.Join(dir, "token"), tc.token)
			}
			if tc.name == "conflicting space" {
				t.Setenv("OCTO_SPACE_ID", "another-space")
			}
			out, err := phaseOneRun("--format", "json", "auth", "status")
			assertUnifiedAuthStatusError(t, out, err, tc.message, tc.exitCode)
		})
	}
}

func TestUnifiedAuthStatusReadsManagedEntry(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_PROFILE", "selected")
	store := authstore.NewManagedStore(dir, nil)
	before, err := store.Snapshot("selected", true)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Profile{APIBaseURL: "https://status.example", SpaceID: "target-space"}
	if _, err := store.Import(before, profile, "managed-fixture-secret", authstore.BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	out, err := phaseOneRun("--format", "json", "auth", "status")
	assertUnifiedAuthStatus(t, out, err, "readable", "selected", profile.APIBaseURL, profile.SpaceID, "profile:managed_store")

	after, err := store.Snapshot("selected", true)
	if err != nil || after.Profile.TokenSource == nil {
		t.Fatalf("cannot read managed fixture reference: %v", err)
	}
	entryPath := filepath.Join(dir, "credentials", after.Profile.TokenSource.Entry+".enc")
	raw, err := os.ReadFile(entryPath)
	if err != nil || len(raw) == 0 {
		t.Fatalf("cannot read managed fixture entry: %v", err)
	}
	raw[len(raw)-1] ^= 1
	phaseOneWrite(t, entryPath, string(raw))
	out, err = phaseOneRun("--format", "json", "auth", "status")
	assertUnifiedAuthStatusError(t, out, err, "cannot read credential", 3)
}

func TestUnifiedAuthStatusReloadsReplacedManagedEntry(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_PROFILE", "selected")
	store := authstore.NewManagedStore(dir, nil)
	before, err := store.Snapshot("selected", true)
	if err != nil {
		t.Fatal(err)
	}
	oldProfile := config.Profile{APIBaseURL: "https://old.example", SpaceID: "old-space"}
	if _, err := store.Import(before, oldProfile, "old-fixture-token", authstore.BackendEncryptedFile); err != nil {
		t.Fatal(err)
	}
	old, err := store.Snapshot("selected", true)
	if err != nil || !old.Exists {
		t.Fatalf("cannot load original profile: %v", err)
	}
	newProfile := config.Profile{APIBaseURL: "https://new.example", SpaceID: "new-space"}
	f := cmdutil.NewDefaultFactory()
	var out bytes.Buffer
	f.IOStreams.Out, f.IOStreams.ErrOut = &out, &out
	err = runUnifiedAuthStatus(f, func(profiles *config.ProfileConfig, ref *config.TokenSource) (string, string, error) {
		if *ref == *old.Profile.TokenSource {
			// Commit the replacement after status has selected the old reference.
			result, err := store.Import(old, newProfile, "new-fixture-token", authstore.BackendEncryptedFile)
			if err != nil || result.CleanupWarning != "" {
				t.Fatalf("replace managed credential: %v %s", err, result.CleanupWarning)
			}
		}
		return credential.ReadProfileToken(profiles, ref)
	})
	assertUnifiedAuthStatus(t, out.String(), err, "readable", "selected", newProfile.APIBaseURL, newProfile.SpaceID, "profile:managed_store")
}

func TestUnifiedAuthStatusDistinguishesMissingDirectoriesFromBrokenSymlinks(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_PROFILE", "selected")
	missing := filepath.Join(dir, "missing")
	broken := filepath.Join(dir, "broken")
	valid := filepath.Join(dir, "valid")
	for link, target := range map[string]string{broken: missing, valid: dir} {
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("cannot create a Windows directory symlink: %v", err)
			}
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, path string
		broken     bool
	}{
		{"absent directory", filepath.Join(missing, "store"), false},
		{"valid directory symlink", filepath.Join(valid, "store"), false},
		{"dangling directory symlink", broken, true},
		{"dangling ancestor symlink", filepath.Join(broken, "store"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTO_CONFIG_DIR", tc.path)
			out, err := phaseOneRun("--format", "json", "auth", "status")
			if tc.broken {
				assertUnifiedAuthStatusError(t, out, err, "cannot read config.json", 2)
				return
			}
			assertUnifiedAuthStatus(t, out, err, "missing", "selected", config.LoadRuntime().APIBaseURL, "", "")
		})
	}
}

func TestUnifiedAuthStatusRejectsUnreadableConfiguration(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_PROFILE", "selected")
	path := filepath.Join(dir, "config.json")
	phaseOneWrite(t, path, `{"version":1,"profiles":{}}`)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(path); !os.IsPermission(err) {
		t.Skipf("cannot exercise permission denial: %v", err)
	}
	out, err := phaseOneRun("--format", "json", "auth", "status")
	assertUnifiedAuthStatusError(t, out, err, "cannot read config.json", 2)
}

func TestUnifiedAuthStatusRejectsUnknownTarget(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	out, err := phaseOneRun("--format", "json", "auth", "status")
	assertUnifiedAuthStatusError(t, out, err, "no target profile selected", 2)
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{"version":1,"current_profile":"dangling","profiles":{}}`)
	out, err = phaseOneRun("--format", "json", "auth", "status")
	assertUnifiedAuthStatusError(t, out, err, "current_profile must reference an existing, non-null profile", 2)
}

func TestUnifiedAuthStatusRejectsMissingTargetWhenCurrentProfileIsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, profiles string
	}{
		{"dangling", `{}`},
		{"null", `{"default":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
			phaseOneWrite(t, filepath.Join(dir, "config.json"),
				`{"version":1,"current_profile":"default","profiles":`+tc.profiles+`}`)
			out, err := phaseOneRun("--format", "json", "--profile", "absent", "auth", "status")
			assertUnifiedAuthStatusError(t, out, err, "current_profile must reference an existing, non-null profile", 2)
		})
	}
}

func TestUnifiedAuthStatusRedactsBearerInMetadata(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv("OCTO_CREDENTIAL_MODE", "unified")
	const secret = "status-fixture-secret"
	phaseOneWrite(t, filepath.Join(dir, "token"), secret)
	phaseOneWrite(t, filepath.Join(dir, "config.json"), `{"version":1,"current_profile":"`+secret+`","profiles":{"`+secret+`":{
		"api_base_url":"https://`+secret+`.example","space_id":"`+secret+`","token_source":{"type":"token_file","path":"token"}
	}}}`)
	out, err := phaseOneRun("--format", "json", "auth", "status")
	var result struct {
		Data map[string]string `json:"data"`
	}
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Data["status"] != "readable" || strings.Contains(out, secret) {
		t.Fatal("status failed or included the bearer in profile metadata")
	}
}

func TestUnifiedAuthStatusRedactsEnvironmentBearerInMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, env, status, source string
	}{
		{"readable", config.EnvToken, "readable", "profile:token_file"},
		{"missing", config.EnvToken, "missing", ""},
		{"shadowed alias", config.EnvBotToken, "missing", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			const secret = "runtime-fixture-secret"
			const origin = "https://" + secret + ".example"
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			t.Setenv(config.EnvToken, "other-environment-bearer")
			t.Setenv(tc.env, " "+secret+"\n")
			t.Setenv(config.EnvSpaceID, secret)
			t.Setenv(config.EnvAPIBaseURL, origin)
			if tc.status == "readable" {
				phaseOneWrite(t, filepath.Join(dir, "token"), "stored-fixture-token")
				phaseOneWrite(t, filepath.Join(dir, "config.json"), fmt.Sprintf(
					`{"version":1,"profiles":{%q:{"api_base_url":%q,"token_source":{"type":"token_file","path":"token"}}}}`, secret, origin))
			}
			out, err := phaseOneRun("--format", "json", "--profile", secret, "auth", "status")
			if strings.Contains(out, secret) {
				t.Fatal("environment bearer appeared in status output")
			}
			const mask = "***REDACTED***"
			assertUnifiedAuthStatus(t, out, err, tc.status, mask, "https://"+mask+".example", mask, tc.source)
		})
	}
}

func assertUnifiedAuthStatus(t *testing.T, out string, err error, status, profile, origin, space, source string) {
	t.Helper()
	var result struct {
		OK   bool              `json:"ok"`
		Data map[string]string `json:"data"`
	}
	if err != nil {
		t.Fatalf("status failed: %v (%s)", err, out)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Data["status"] != status || result.Data["profile"] != profile ||
		result.Data["api_base_url"] != origin || result.Data["space_id"] != space || result.Data["source"] != source {
		t.Fatalf("unexpected status envelope: %s", out)
	}
}

func assertUnifiedAuthStatusError(t *testing.T, out string, err error, message string, code int) {
	t.Helper()
	exit := output.AsExitError(err)
	var envelope struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if exit == nil || exit.ExitCode() != code || json.Unmarshal([]byte(out), &envelope) != nil || envelope.OK ||
		envelope.Error.Code != exit.Code || !strings.Contains(envelope.Error.Message, message) {
		t.Fatalf("unexpected status error: %v (%s)", err, out)
	}
}
