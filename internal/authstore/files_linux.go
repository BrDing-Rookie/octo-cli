package authstore

import "os"

func checkPrivateACL(_ string, _ os.FileInfo, _ *os.File) error {
	// The group mode bits already bound Linux POSIX ACL grants.
	return nil
}
