//go:build darwin || linux

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const profileAuthorityAttribute = "user.com.octo.cli.profile-authority.v1"

func authorityFileID(file *os.File) (string, error) {
	var info unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x", info.Dev, info.Ino), nil
}

func writeAuthorityProof(file *os.File, raw []byte) error {
	return unix.Fsetxattr(int(file.Fd()), profileAuthorityAttribute, raw, unix.XATTR_CREATE)
}

func readAuthorityProof(file *os.File) ([]byte, error) {
	var raw [512]byte
	n, err := unix.Fgetxattr(int(file.Fd()), profileAuthorityAttribute, raw[:])
	if err != nil {
		return nil, err
	}
	return raw[:n], nil
}
