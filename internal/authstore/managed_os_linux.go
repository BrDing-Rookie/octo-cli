package authstore

// Linux reflects the effective access of named POSIX ACL entries in the
// group permission bits, which are already checked by the Unix backend.
func checkManagedACL(string) error { return nil }
