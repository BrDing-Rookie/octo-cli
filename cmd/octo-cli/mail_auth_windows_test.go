package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/cmd"
	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"golang.org/x/sys/windows"
)

func TestWindowsMailAuthStatusPreservesCodeWhenTargetCannotBeReplaced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block func(*testing.T, string) func()
	}{
		{"reader without delete sharing", func(t *testing.T, path string) func() {
			return holdMailCredentialReader(t, path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		}},
		{"reader with delete sharing", func(t *testing.T, path string) func() {
			return holdMailCredentialReader(t, path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
		}},
		{"read-only target", markMailCredentialReadOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exerciseMailAuthWithBlockedReplacement(t, tc.block)
		})
	}
}

func holdMailCredentialReader(t *testing.T, path string, sharing uint32) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, sharing, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		if handle != windows.InvalidHandle {
			if err := windows.CloseHandle(handle); err != nil {
				t.Error(err)
			}
			handle = windows.InvalidHandle
		}
	}
}

func markMailCredentialReadOnly(t *testing.T, path string) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(name, attributes|windows.FILE_ATTRIBUTE_READONLY); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := windows.SetFileAttributes(name, attributes); err != nil {
			t.Error(err)
		}
	}
}

func exerciseMailAuthWithBlockedReplacement(t *testing.T, block func(*testing.T, string) func()) {
	t.Helper()
	const botID, spaceID, botToken = "fixture-bot", "fixture-space", "app_fixture"
	pending := authstore.PendingMailAuthorization{DeviceCode: "omd_fixture", CodeVerifier: "fixture-verifier"}
	var exchanges atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent-mail-api/webapi/v0/agent-auth/token" {
			http.NotFound(w, r)
			return
		}
		exchanges.Add(1)
		var proof map[string]string
		if err := json.NewDecoder(r.Body).Decode(&proof); err != nil ||
			proof["deviceCode"] != pending.DeviceCode || proof["codeVerifier"] != pending.CodeVerifier {
			t.Error("exchange did not use the original pending authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"accessToken":"omb_replacement","botId":"fixture-bot","mailboxAddress":"fixture@example.test"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(strings.ToUpper(name), "OCTO_") {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv(config.EnvAPIBaseURL, srv.URL)
	t.Setenv(config.EnvBotToken, botToken)
	t.Setenv(config.EnvBotID, botID)
	t.Setenv(config.EnvSpaceID, spaceID)

	store, err := authstore.New()
	if err != nil {
		t.Fatal(err)
	}
	key, err := authstore.MailBindingKey(botID, spaceID, botToken, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMailCredential(key, "omb_original"); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingMailAuthorization(key, &pending); err != nil {
		t.Fatal(err)
	}
	release := block(t, filepath.Join(dir, "mail-credentials.enc"))
	released := false
	t.Cleanup(func() {
		if !released {
			release()
		}
	})
	if token, err := store.GetMailCredential(key); err != nil || token != "omb_original" {
		t.Fatalf("the blocked destination must still be readable: %v", err)
	}
	out, err := runMailAuthStatus()
	if exchanges.Load() != 0 {
		t.Fatalf("the server received %d exchanges for a blocked destination", exchanges.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "can replace mail-credentials.enc") {
		t.Fatalf("expected replacement preflight error: %v (%s)", err, out)
	}
	if got, err := store.PendingMailAuthorization(key); err != nil || got != pending {
		t.Fatalf("blocked exchange changed the pending authorization: %v", err)
	}
	if token, err := store.GetMailCredential(key); err != nil || token != "omb_original" {
		t.Fatalf("blocked exchange changed the existing credential: %v", err)
	}

	release()
	released = true
	out, err = runMailAuthStatus()
	if err != nil || !strings.Contains(out, "connected") || exchanges.Load() != 1 {
		t.Fatalf("retry using the original pending code: %v (%s)", err, out)
	}
	if token, err := store.GetMailCredential(key); err != nil || token != "omb_replacement" {
		t.Fatalf("read the new credential: %v", err)
	}
	if _, err := store.PendingMailAuthorization(key); !errors.Is(err, authstore.ErrMailCredentialNotFound) {
		t.Fatalf("successful retry should remove the pending authorization: %v", err)
	}
}

func runMailAuthStatus() (string, error) {
	factory := cmdutil.NewDefaultFactory()
	var out bytes.Buffer
	factory.IOStreams.Out, factory.IOStreams.ErrOut = &out, &out
	root := cmd.NewRootCmd(factory)
	root.SetArgs([]string{"mail", "auth", "status"})
	err := root.Execute()
	return out.String(), err
}
