package authstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const macKeychainService = "com.octo.cli.managed"
const securityLineLimit = 4096

type macKeychain struct {
	dir string
	run func(string) ([]byte, error)
}

func systemKeychain(dir string) Keychain {
	return macKeychain{dir: dir, run: runSecurityCommand}
}

func canonicalManagedDirectory(dir string) (string, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	// F_GETPATH returns the spelling of the opened directory, including on
	// case-insensitive APFS where EvalSymlinks keeps the caller's input case.
	var path [unix.PathMax]byte
	// FcntlInt passes the buffer address as an integer to libSystem.
	var pin runtime.Pinner
	pin.Pin(&path)
	defer pin.Unpin()
	_, err = unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&path[0]))))
	closeErr := unix.Close(fd)
	if err != nil {
		return "", errors.Join(err, closeErr)
	}
	return unix.ByteSliceToString(path[:]), closeErr
}

// Read decodes the ASCII hex used for both tokens and binary master keys.
func (k macKeychain) Read(account string) ([]byte, error) {
	pathArg, err := k.boundPathArgument(account)
	if err != nil {
		return nil, err
	}
	raw, err := k.run(keychainCommand("find-generic-password", account) + " -w" + pathArg)
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
func (k macKeychain) Create(account string, data []byte) error {
	command := keychainCommand("add-generic-password", account) + " -w " + hex.EncodeToString(data)
	if len(command)+1 >= securityLineLimit {
		return errKeychainEntryTooLarge
	}
	bound, err := k.boundPathArgument(account)
	if err != nil {
		return err
	}
	if bound != "" {
		// An interrupted first write can leave a master-key locator with
		// no item. Retry the non-replacing add in the original Keychain.
		_, err := k.run(command + bound)
		if errors.Is(err, errKeychainUnavailable) {
			return errors.New("bound system Keychain is inaccessible")
		}
		return err
	}
	path, err := k.defaultPath()
	if err != nil {
		return err
	}
	pathArg, err := keychainPathArgument(path)
	if err != nil {
		return err
	}
	if len(command)+len(pathArg)+1 >= securityLineLimit {
		return errKeychainEntryTooLarge
	}
	name := keychainLocatorName(account)
	locator := filepath.Join(k.dir, credentialsDir, name)
	if err := ensurePrivateDir(filepath.Dir(locator)); err != nil {
		return err
	}
	// Persist the locator before adding the item, so even an interruption
	// cannot leave a committed reference dependent on the search list.
	visible, err := writeManagedFile(locator, []byte(path))
	if err != nil {
		if visible {
			return errors.Join(err, removeCredentialFile(k.dir, name))
		}
		return err
	}
	if _, err := k.run(command + pathArg); err != nil {
		return errors.Join(err, removeCredentialFile(k.dir, name))
	}
	return nil
}

func (k macKeychain) defaultPath() (string, error) {
	output, err := k.run("default-keychain")
	if err != nil {
		return "", err
	}
	path, opened := strings.CutPrefix(strings.TrimSpace(string(output)), `"`)
	path, closed := strings.CutSuffix(path, `"`)
	if !opened || !closed {
		return "", errors.New("cannot locate the default system Keychain")
	}
	return path, nil
}

// Remove keeps the locator unless deletion is confirmed. With a legacy
// reference a search miss cannot distinguish absence from a changed list.
func (k macKeychain) Remove(account string) error {
	pathArg, err := k.boundPathArgument(account)
	if err != nil {
		return err
	}
	if _, err := k.run(keychainCommand("delete-generic-password", account) + pathArg); err != nil {
		return err
	}
	if pathArg != "" {
		return removeCredentialFile(k.dir, keychainLocatorName(account))
	}
	return nil
}

func keychainLocatorName(account string) string {
	// The account contains the canonical directory hash and a generated
	// entry name (or master-key). Only the entry name is needed here.
	return ".keychain-" + filepath.Base(account)
}

func (k macKeychain) boundPathArgument(account string) (string, error) {
	path, err := readCredentialFile(k.dir, keychainLocatorName(account), unix.PathMax)
	if errors.Is(err, fs.ErrNotExist) {
		// Entries written before locators were introduced still use the list.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return keychainPathArgument(string(path))
}

func keychainPathArgument(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("invalid managed Keychain path")
	}
	if _, err := os.Stat(path); err != nil {
		// An explicitly bound but missing Keychain is a storage error, not
		// a missing item or a reason to search a different Keychain.
		return "", errors.New("bound system Keychain is inaccessible")
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(path)
	return ` "` + escaped + `"`, nil
}

func keychainCommand(op, account string) string {
	return op + " -s " + macKeychainService + " -a " + account
}

func runSecurityCommand(command string) ([]byte, error) {
	// Release builds have CGO disabled. Interactive security accepts a line
	// over a private pipe, keeping the password out of process arguments.
	line := command + "\n"
	if len(line) >= securityLineLimit {
		return nil, errKeychainEntryTooLarge
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(line)
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	op, _, _ := strings.Cut(command, " ")
	diagnostics := stderr.String()
	switch {
	case strings.Contains(diagnostics, "security: SecKeychainOpen "):
		return nil, errors.New("bound system Keychain is inaccessible")
	case err == nil:
		return stdout, nil
	case ctx.Err() != nil:
		return nil, errors.New("system Keychain operation timed out")
	case errors.Is(err, fs.ErrNotExist):
		return nil, errKeychainUnavailable
	default:
		return nil, keychainStatusError(op, diagnostics)
	}
}

func keychainStatusError(op, stderr string) error {
	if op == "default-keychain" {
		// security's default-keychain command collapses OSStatus to exit 1.
		for _, line := range strings.Split(stderr, "\n") {
			switch line {
			case "security: SecKeychainCopyDefault: A default keychain could not be found.",
				"security: SecKeychainCopyDefault: No keychain is available. You may need to restart your computer.",
				"security: SecKeychainCopyDefault: The specified keychain could not be found.":
				return errKeychainUnavailable
			}
		}
	}
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
