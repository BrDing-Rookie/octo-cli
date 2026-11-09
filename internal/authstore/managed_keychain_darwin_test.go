package authstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinKeychainScopesUseFilesystemSpelling(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "Store-Mixed")
	alias := filepath.Join(parent, "store-mixed")
	if err := os.Mkdir(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(alias)
	if errors.Is(err, os.ErrNotExist) {
		// On a case-sensitive volume both directories must stay distinct.
		if err := os.Mkdir(alias, dirPerm); err != nil {
			t.Fatal(err)
		}
		first, err := canonicalManagedDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		second, err := canonicalManagedDirectory(alias)
		if err != nil || first == second {
			t.Fatalf("distinct directory scopes: %q and %q (%v)", first, second, err)
		}
		return
	}
	if err != nil || !os.SameFile(info, other) {
		t.Fatalf("case alias does not identify the same directory: %v", err)
	}
	assertManagedKeychainDirectoryAlias(t, BackendKeychain, dir, alias)
}

func TestDarwinKeychainStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{-25300, os.ErrNotExist},
		{-25307, errKeychainUnavailable},
		{-25294, errKeychainUnavailable},
		{-25291, errKeychainUnavailable},
		{-25293, os.ErrPermission},
		{-25308, os.ErrPermission},
		{-60008, os.ErrPermission},
		{-25295, nil},
	} {
		raw := fmt.Sprintf("security: fake-token-echo\nfind-generic-password: returned %d\n", tc.status)
		err := keychainStatusError("find-generic-password", raw)
		if err == nil || strings.Contains(err.Error(), "fake-token-echo") {
			t.Fatalf("status %d leaked diagnostics or returned no error: %v", tc.status, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("status %d: %v, want %v", tc.status, err, tc.want)
		}
		if tc.want == nil && errors.Is(err, errKeychainUnavailable) {
			t.Fatalf("unexpected fallback for unrecognized failure %d", tc.status)
		}
	}
	if err := (macKeychain{}).Create("test", make([]byte, 4096)); !errors.Is(err, errKeychainEntryTooLarge) {
		t.Fatalf("oversized command did not fail before calling Keychain: %v", err)
	}
}
