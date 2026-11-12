package authstore

import (
	"errors"
	"io/fs"
	"testing"
)

func TestMacKeychainErrorUsesExitStatus(t *testing.T) {
	const deletionMessage = "password has been deleted."
	if err := macKeychainError(deletionMessage, nil); err != nil {
		t.Fatalf("successful deletion should not warn: %v", err)
	}
	if err := macKeychainError(deletionMessage, storeError("delete failed")); err == nil {
		t.Fatal("confirmation text masked a failed deletion")
	}
	if err := macKeychainError("User interaction is not allowed.", storeError("access denied")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("access refusal did not remain a permission error: %v", err)
	}
}
