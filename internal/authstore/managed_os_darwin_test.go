package authstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinManagedStorageRejectsExtendedACL(t *testing.T) {
	parent := t.TempDir()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read,search,file_inherit,directory_inherit", parent).CombinedOutput(); err != nil {
		t.Fatalf("install inherited ACL: %v (%s)", err, out)
	}
	store := NewManagedStore(filepath.Join(parent, "cli"), nil)
	snap, err := store.Snapshot("work", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(snap, managedFixtureProfile(), "fixture-token", BackendEncryptedFile); err == nil || !strings.Contains(err.Error(), "extended ACL") {
		t.Fatalf("import should reject the inherited ACL: %v", err)
	}
	if _, err := os.Lstat(store.masterKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("master key must not be written: %v", err)
	}

	file := filepath.Join(t.TempDir(), "existing-key")
	if err := os.WriteFile(file, []byte("fixture-key"), secPerm); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", file).CombinedOutput(); err != nil {
		t.Fatalf("install file ACL: %v (%s)", err, out)
	}
	root, err := os.OpenRoot(filepath.Dir(file))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if _, err := readPrivateFile(root, filepath.Base(file), 32); err == nil || !strings.Contains(err.Error(), "extended ACL") {
		t.Fatalf("read should reject the extended ACL: %v", err)
	}
}
