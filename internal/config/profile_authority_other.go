//go:build !darwin && !linux && !windows

package config

import (
	"errors"
	"os"
)

var errProfileAuthorityUnsupported = errors.New("managed profile publication proof is unavailable on this platform")

func authorityFileID(*os.File) (string, error)    { return "", errProfileAuthorityUnsupported }
func writeAuthorityProof(*os.File, []byte) error  { return errProfileAuthorityUnsupported }
func readAuthorityProof(*os.File) ([]byte, error) { return nil, errProfileAuthorityUnsupported }
