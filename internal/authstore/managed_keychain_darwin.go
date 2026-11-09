package authstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const macKeychainService = "com.octo.cli.managed"

type macKeychain struct{}

func systemKeychain() Keychain {
	return macKeychain{}
}

// Read decodes the ASCII hex used for both tokens and binary master keys.
func (macKeychain) Read(account string) ([]byte, error) {
	raw, err := runKeychain("find-generic-password", account, "-w")
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, errors.New("invalid managed Keychain data")
	}
	return decoded, nil
}

// Create adds an entry without replacing an existing value.
func (macKeychain) Create(account string, data []byte) error {
	_, err := runKeychain("add-generic-password", account, "-w "+hex.EncodeToString(data))
	return err
}

// Remove treats an already absent entry as cleaned up.
func (macKeychain) Remove(account string) error {
	_, err := runKeychain("delete-generic-password", account, "")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func runKeychain(op, account, flags string) ([]byte, error) {
	// Release builds have CGO disabled. Interactive security accepts a line
	// over a private pipe, keeping the password out of process arguments.
	// All values are fixed or use only hex, slash and hyphen.
	line := op + " -s " + macKeychainService + " -a " + account + " " + flags + "\n"
	if len(line) >= 4096 {
		return nil, errKeychainEntryTooLarge
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(line)
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	switch {
	case err == nil:
		return stdout, nil
	case ctx.Err() != nil:
		return nil, errors.New("system Keychain operation timed out")
	case errors.Is(err, fs.ErrNotExist):
		return nil, errKeychainUnavailable
	default:
		return nil, keychainStatusError(op, stderr.String())
	}
}

func keychainStatusError(op, stderr string) error {
	marker := op + ": returned "
	_, statusText, ok := strings.Cut(strings.TrimSpace(stderr), marker)
	status, parseErr := strconv.Atoi(statusText)
	if !ok || parseErr != nil {
		return errors.New("system Keychain operation failed")
	}
	switch status {
	case -25300: // errSecItemNotFound
		return fs.ErrNotExist
	case -25291, -25294, -25307: // no available, specified, or default keychain
		return errKeychainUnavailable
	case -25293, -25308, -60005, -60008:
		return fs.ErrPermission
	default:
		// The tool may echo its input in diagnostics. Keep only the status.
		return fmt.Errorf("system Keychain operation failed (status %d)", status)
	}
}
