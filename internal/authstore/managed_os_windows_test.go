package authstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

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
