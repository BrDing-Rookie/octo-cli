package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxAuthorityProof = 4096

func authorityFileID(file *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x:%x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func writeAuthorityProof(file *os.File, raw []byte) error {
	in := windows.DataBlob{Size: uint32(len(raw)), Data: unsafe.SliceData(raw)}
	context := authorityProofContext()
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &context, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return err
	}
	defer freeAuthorityBlob(out)
	_, err := file.Write(unsafe.Slice(out.Data, int(out.Size)))
	return err
}

func readAuthorityProof(file *os.File) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(file, maxAuthorityProof+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxAuthorityProof {
		return nil, errors.New("invalid managed profile authority size")
	}
	in := windows.DataBlob{Size: uint32(len(raw)), Data: unsafe.SliceData(raw)}
	context := authorityProofContext()
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &context, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer freeAuthorityBlob(out)
	if out.Size > maxAuthorityProof {
		return nil, errors.New("invalid managed profile authority proof")
	}
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func authorityProofContext() windows.DataBlob {
	raw := []byte("com.octo.cli.profile-authority.v1")
	return windows.DataBlob{Size: uint32(len(raw)), Data: unsafe.SliceData(raw)}
}

func freeAuthorityBlob(blob windows.DataBlob) {
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data)))) //nolint:errcheck // release the DPAPI buffer after copying
}
