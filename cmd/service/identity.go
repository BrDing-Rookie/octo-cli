package service

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

const tokenKindNotAllowed = "TOKEN_KIND_NOT_ALLOWED"

// applyIdentityRouting enforces x-octo-allowed-token-kinds and applies
// x-octo-mount-by-token-kind to urlPath. Operations declaring neither
// extension are returned untouched and never resolve a credential here, so
// every pre-existing domain keeps its byte-identical path and its historical
// credential-resolution timing.
//
// Errors are already-classified *output.ExitError values:
//
//   - missing / ambiguous / unreadable credential → auth or validation, as the
//     credential chain classified it (exit 3 / 2)
//   - credential kind outside the allowed list, or absent from the mount table
//     → validation, TOKEN_KIND_NOT_ALLOWED (exit 2)
func applyIdentityRouting(f *cmdutil.Factory, d *registry.OperationDetail, urlPath string) (string, error) {
	if len(d.AllowedTokenKinds) == 0 && len(d.MountByTokenKind) == 0 {
		return urlPath, nil
	}

	kind, err := activeTokenKind(f)
	if err != nil {
		return "", err
	}

	if len(d.AllowedTokenKinds) > 0 && !containsString(d.AllowedTokenKinds, kind) {
		return "", tokenKindError(kind, d.AllowedTokenKinds)
	}
	if len(d.MountByTokenKind) == 0 {
		return urlPath, nil
	}
	mount, ok := d.MountByTokenKind[kind]
	if !ok {
		return "", tokenKindError(kind, mountKinds(d.MountByTokenKind))
	}
	return swapMount(urlPath, mount, d.MountByTokenKind)
}

// activeTokenKind resolves the credential and classifies it by token prefix.
// Resolution is cached on the Factory, and root's PersistentPreRunE has already
// forced it via cfg.Validate, so this adds no I/O — but ErrNoCredential must be
// translated here because buildConfig deliberately swallows it.
func activeTokenKind(f *cmdutil.Factory) (string, error) {
	cred, err := f.Credential()
	if err != nil {
		if errors.Is(err, credential.ErrNoCredential) {
			return "", output.ErrAuth(
				"no credential configured",
				"set OCTO_TOKEN (or OCTO_BOT_TOKEN), or select a stored profile with --bot-id / --profile")
		}
		return "", err
	}
	if cred == nil || cred.Token == "" {
		return "", output.ErrAuth(
			"no credential configured",
			"set OCTO_TOKEN (or OCTO_BOT_TOKEN), or select a stored profile with --bot-id / --profile")
	}
	return credential.TokenKind(cred.Token), nil
}

// tokenKindError reports an incompatible credential kind. The message names the
// kind actually in use so an Agent holding several credentials can tell which
// one it picked up.
func tokenKindError(kind string, allowed []string) *output.ExitError {
	got := kind
	if got == "" {
		got = "none"
	}
	return output.ErrWithHint(
		"validation",
		tokenKindNotAllowed,
		fmt.Sprintf("credential kind %q cannot run this operation (allowed: %s)", got, strings.Join(allowed, ", ")),
		"select a compatible credential with --bot-id / --profile, or set OCTO_TOKEN; `octo-cli auth list` shows stored profiles",
	)
}

// swapMount replaces the mount prefix the spec path is written with by the
// mount for the active token kind.
//
// The spec paths carry a full, real path (e.g. /v1/bot/items) rather
// than a bare suffix, so `octo-cli schema` stays readable and the default
// token kind takes a zero-rewrite path. Which leading segment is the mount is
// therefore derived: exactly one value in the table must prefix the path, and
// the longest such match wins. A path that matches none is a spec bug and fails
// loudly rather than silently reaching a wrong URL.
func swapMount(urlPath, target string, table map[string]string) (string, error) {
	current := ""
	for _, candidate := range table {
		if !strings.HasPrefix(urlPath, candidate) {
			continue
		}
		if len(candidate) > len(current) {
			current = candidate
		}
	}
	if current == "" {
		return "", output.ErrWithHint(
			"internal",
			"MOUNT_PREFIX_UNKNOWN",
			fmt.Sprintf("operation path %q does not start with any x-octo-mount-by-token-kind prefix", urlPath),
			"operation-spec bug: write the path with one of the declared mounts",
		)
	}
	if current == target {
		return urlPath, nil
	}
	return target + strings.TrimPrefix(urlPath, current), nil
}

// mountKinds lists the token kinds a mount table covers, sorted so error
// messages are stable.
func mountKinds(table map[string]string) []string {
	kinds := make([]string, 0, len(table))
	for k := range table {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
