package authstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedWindowsPath(t *testing.T) {
	longSuffix := strings.Repeat(strings.Repeat("d", 100)+`\`, 3) + configFile
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"short", `C:\store\` + configFile, `C:\store\` + configFile},
		{"local", `C:/store/../` + longSuffix, `\\?\C:\` + longSuffix},
		{"UNC", `\\server\share\store\..\` + longSuffix, `\\?\UNC\server\share\` + longSuffix},
		{"extended", `\\?\UNC\server\share\` + longSuffix, `\\?\UNC\server\share\` + longSuffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := managedWindowsPath(tc.path); err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestWindowsManagedStoreWithLongPath(t *testing.T) {
	dir := t.TempDir()
	for range 3 {
		dir = filepath.Join(dir, strings.Repeat("d", 100))
	}
	store := NewManagedStore(dir, nil)
	profile := managedFixtureProfile()
	for _, token := range []string{"first-token", "rotated-token"} {
		snap, err := store.Snapshot("target", true)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := store.Import(snap, profile, token, BackendAuto); err != nil || result.CleanupWarning != "" {
			t.Fatalf("import using a long path: %#v, %v", result, err)
		}
	}
	snap, err := store.Snapshot("target", true)
	if err != nil || !snap.Exists {
		t.Fatalf("read committed profile: %v", err)
	}
	if got, err := store.readEntry(snap.Profile.TokenSource); err != nil || got != "rotated-token" {
		t.Fatalf("read rotated credential: %v", err)
	}
	if result, err := store.Remove(snap); err != nil || result.CleanupWarning != "" {
		t.Fatalf("remove profile using a long path: %#v, %v", result, err)
	}
}

func TestWindowsManagedReplacementWaitsForReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old"), secPerm); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "staged")
	if err := os.WriteFile(staged, []byte("new"), secPerm); err != nil {
		t.Fatal(err)
	}
	from, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		t.Fatal(err)
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("the held reader should prevent an immediate replacement: %v", err)
	}
	closed := make(chan error, 1)
	time.AfterFunc(75*time.Millisecond, func() { closed <- reader.Close() })
	committed, err := replaceManagedFile(staged, path)
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || !committed {
		t.Fatalf("replace with concurrent reader: committed=%v, %v", committed, err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "new" {
		t.Fatalf("expected updated config after reader closes: %q, %v", raw, err)
	}
}

func TestWindowsPublishManagedAnchorDoesNotReplace(t *testing.T) {
	dir := t.TempDir()
	seal := filepath.Join(dir, "seal")
	stage := filepath.Join(dir, "staged")
	anchor := filepath.Join(dir, "anchor")
	writeOwnershipFixture(t, seal, []byte("new"))
	writeOwnershipFixture(t, anchor, []byte("existing"))
	if err := os.Link(seal, stage); err != nil {
		t.Fatal(err)
	}
	if committed, err := publishManagedAnchor(stage, anchor); committed || err == nil {
		t.Fatalf("publication replaced an existing destination: %v, %v", committed, err)
	}
	assertOwnershipFixture(t, anchor, []byte("existing"))
	if err := os.Remove(anchor); err != nil {
		t.Fatal(err)
	}
	if committed, err := publishManagedAnchor(stage, anchor); !committed || err != nil {
		t.Fatalf("publish the prepared anchor: %v", err)
	}
	assertOwnershipFixture(t, stage, nil)
	got, err := os.Stat(anchor)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(seal)
	if err != nil || !os.SameFile(got, want) {
		t.Fatalf("publication lost the prepared inode: %v", err)
	}
}
