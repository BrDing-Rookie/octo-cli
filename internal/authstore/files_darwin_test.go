package authstore

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func addTestACE(t *testing.T, path, ace string) {
	t.Helper()
	cmd := exec.Command("/bin/chmod", "+a", ace, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set fixture ACL: %v (%s)", err, out)
	}
}

func TestDarwinPrivateDirectoryRejectsACLGrant(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cli")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	addTestACE(t, dir, "group:everyone allow list,search")
	store := &Store{dir: dir}
	if _, err := store.checkDir(false); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected the directory ACL grant to be rejected, got %v", err)
	}
}

func TestDarwinPrivateFileRejectsACLGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), masterKeyFile)
	if err := os.WriteFile(path, []byte("fixture data"), 0o600); err != nil {
		t.Fatal(err)
	}
	addTestACE(t, path, "group:everyone allow read")
	if _, err := readPrivate(path); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected the file ACL grant to be rejected before reading, got %v", err)
	}
}

func TestDarwinPrivateFileAllowsDenyOnlyACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), masterKeyFile)
	if err := os.WriteFile(path, []byte("fixture data"), 0o600); err != nil {
		t.Fatal(err)
	}
	addTestACE(t, path, "group:everyone deny writeattr")
	if data, err := readPrivate(path); err != nil || string(data) != "fixture data" {
		t.Fatalf("expected the owner to read the deny-only fixture, got %v", err)
	}
}

func TestDarwinPrivateWriteRejectsInheritedACLGrant(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cli")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	addTestACE(t, dir, "group:everyone allow read,file_inherit,only_inherit")
	path := filepath.Join(dir, masterKeyFile)
	if published, err := writePrivate(context.Background(), path, []byte("fixture data")); published || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected the inherited ACL grant to be rejected before writing, got published=%v, err=%v", published, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write published a file under an inherited ACL grant: %v", err)
	}
}
