package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

const authCurrentPath = "/v1/auth/tokens/_current"

var authPermissionField = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+|\*)$`)
var authInvalidOffsetMinute = regexp.MustCompile(`[+-]\d{2}:[6-9]\d$`)

type authTokenSelf struct {
	Token       authTokenMetadata `json:"token"`
	Permissions []authPermission  `json:"permissions"`
	BotBindings []authBotBinding  `json:"bot_bindings"`
}

type authTokenMetadata struct {
	ID         string                              `json:"token_id"`
	OwnerID    string                              `json:"owner_id"`
	SpaceID    string                              `json:"space_id"`
	Name       *string                             `json:"name"`
	Remark     authRequiredNullable[string]        `json:"remark"`
	Status     string                              `json:"status"`
	ExpiresAt  authRequiredNullable[authTimestamp] `json:"expires_at"`
	IsExpired  *bool                               `json:"is_expired"`
	Version    *uint64                             `json:"version"`
	CreatedAt  *authTimestamp                      `json:"created_at"`
	UpdatedAt  *authTimestamp                      `json:"updated_at"`
	LastUsedAt authRequiredNullable[authTimestamp] `json:"last_used_at"`
}

// UnmarshalJSON checks metadata keys before the typed decode can overwrite them.
func (meta *authTokenMetadata) UnmarshalJSON(data []byte) error {
	if !uniqueTokenSelfObjectKeys(data, true) {
		return errors.New("invalid or ambiguous TokenSelf metadata")
	}
	type wireMetadata authTokenMetadata
	return json.Unmarshal(data, (*wireMetadata)(meta))
}

type authTimestamp struct{ time.Time }

// UnmarshalJSON decodes JSON escapes before parsing the timestamp.
func (timestamp *authTimestamp) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	// Go's fallback parser normalizes a timezone minute of 60.
	if authInvalidOffsetMinute.MatchString(value) {
		return errors.New("invalid timestamp timezone minute")
	}
	if err := timestamp.UnmarshalText([]byte(value)); err != nil {
		return err
	}
	// Go can parse timestamps that its JSON encoder rejects.
	_, err := timestamp.MarshalJSON()
	return err
}

// authRequiredNullable distinguishes an omitted field from an explicit null
// while preserving the field's JSON type and output representation.
type authRequiredNullable[T any] struct {
	value   *T
	present bool
}

// UnmarshalJSON decodes the value and records that the field was present.
func (field *authRequiredNullable[T]) UnmarshalJSON(data []byte) error {
	field.present = true
	return json.Unmarshal(data, &field.value)
}

// MarshalJSON emits the underlying value, including null.
func (field authRequiredNullable[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(field.value)
}

type authPermission struct {
	Domain  string    `json:"domain"`
	Actions []*string `json:"actions"`
}

// UnmarshalJSON rejects duplicate permission fields before decoding actions.
func (permission *authPermission) UnmarshalJSON(data []byte) error {
	if !uniqueTokenSelfObjectKeys(data, true) {
		return errors.New("invalid or ambiguous TokenSelf permission")
	}
	type wirePermission authPermission
	return json.Unmarshal(data, (*wirePermission)(permission))
}

type authBotBinding map[string]any

// UnmarshalJSON checks exact map keys and preserves numbers in binding data.
func (binding *authBotBinding) UnmarshalJSON(data []byte) error {
	if !uniqueTokenSelfObjectKeys(data, false) {
		return errors.New("invalid or ambiguous TokenSelf bot binding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode((*map[string]any)(binding))
}

func newAuthGetCmd(f *cmdutil.Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Check the selected unified CLI Token online",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runAuthGet(cmd.Context(), f); err != nil {
				return failErrContext(cmd.Context(), f, err)
			}
			return nil
		},
	}
}

func runAuthGet(ctx context.Context, f *cmdutil.Factory) error {
	active, err := f.BusinessCredential()
	if err != nil {
		return err
	}
	if active == nil {
		return output.ErrValidation("auth get requires unified credentials", "set OCTO_CREDENTIAL_MODE=unified")
	}
	raw, err := requestAuthCurrent(ctx, f, active)
	if err != nil {
		return err
	}
	if !f.Globals.DryRun {
		self, err := decodeAuthTokenSelf(raw)
		if err != nil {
			return err
		}
		if active.SpaceID != "" && self.Token.SpaceID != active.SpaceID {
			return output.ErrValidation("selected CLI Token belongs to a different Space", "select the Token's target Space")
		}
		raw, err = self.redactedPayload(active.Token)
		if err != nil {
			return err
		}
	}
	var rendered bytes.Buffer
	err = f.WriteSuccessWithMeta(ctx, &rendered, raw, output.EnvelopeMeta{})
	if err == nil {
		err = f.IOStreams.WriteStdout(ctx, rendered.Bytes())
	}
	if err != nil && errors.Is(err, ctx.Err()) {
		return output.ErrNetwork("CLI Token self-check was cancelled", "retry the self-check")
	}
	return err
}

func runUnifiedAuthLogin(cmd *cobra.Command, f *cmdutil.Factory, withToken bool, apiBaseURL, ownerID string) error {
	if err := validateUnifiedAuthLogin(cmd, f, withToken, apiBaseURL); err != nil {
		return err
	}
	name, _ := config.ProfileSelector(f.Globals.Profile, f.Globals.ProfileSet)
	if name == "" || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return output.ErrValidation("unified auth login requires a valid Profile name", "pass --profile or set OCTO_PROFILE to a UTF-8 name without surrounding whitespace")
	}
	store, err := f.ManagedStore()
	if err != nil {
		return credential.ProfileConfigError(err)
	}
	baseline, err := store.Snapshot(name, true)
	if err != nil {
		return credential.ProfileConfigError(err)
	}
	target, err := authLoginTarget(f, baseline.Profile, apiBaseURL)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	token, err := readUnifiedLoginToken(ctx, f.IOStreams.In)
	if err != nil {
		return err
	}
	candidate := &credential.BusinessContext{Token: token, APIBaseURL: target.APIBaseURL, SpaceID: target.SpaceID}
	raw, err := requestAuthCurrent(ctx, f, candidate)
	if err != nil {
		return err
	}
	self, err := decodeAuthTokenSelf(raw)
	if err != nil {
		return err
	}
	if err := self.Token.verifyImport(target.SpaceID, ownerID); err != nil {
		return err
	}
	return importVerifiedToken(ctx, f, store, baseline, target, token)
}

func validateUnifiedAuthLogin(cmd *cobra.Command, f *cmdutil.Factory, withToken bool, apiBaseURL string) error {
	switch {
	case !withToken:
		return output.ErrValidation("unified auth login requires --with-token", "pipe the candidate CLI Token through stdin")
	case f.Globals.CredentialFileSet, f.Globals.BotIDSet:
		return output.ErrValidation("unified auth login does not accept --credential-file or --bot-id", "select a Profile and pipe the candidate CLI Token through stdin")
	case cmd.Flags().Changed("api-base-url") && apiBaseURL == "":
		return output.ErrValidation("--api-base-url is empty", "pass the target API origin")
	case cmd.Flags().Changed("space") && strings.TrimSpace(f.Globals.Space) == "":
		return output.ErrValidation("--space is empty", "pass the target Space ID")
	}
	return nil
}

func authLoginTarget(f *cmdutil.Factory, previous config.Profile, apiBaseURL string) (config.Profile, error) {
	runtime := config.LoadRuntime()
	target := config.Profile{APIBaseURL: previous.APIBaseURL, SpaceID: previous.SpaceID}
	if apiBaseURL != "" {
		target.APIBaseURL = apiBaseURL
	}
	if f.Globals.Space != "" {
		// Explicit import into a new Space is allowed after that Space is verified.
		target.SpaceID = f.Globals.Space
	}
	if err := runtime.ApplyProfile(target, f.Globals.Space); err != nil {
		return config.Profile{}, output.ErrValidation(err.Error(), "check the target API origin and Space")
	}
	if strings.TrimSpace(runtime.SpaceID) == "" {
		return config.Profile{}, output.ErrValidation("unified auth login requires a target Space", "pass --space or set OCTO_SPACE_ID")
	}
	return config.Profile{APIBaseURL: runtime.APIBaseURL, SpaceID: runtime.SpaceID}, nil
}

func readUnifiedLoginToken(ctx context.Context, stdin io.Reader) (string, error) {
	if ctx.Err() != nil {
		return "", authImportCanceled()
	}
	const limit = 64 * 1024
	type readResult struct {
		raw []byte
		err error
	}
	// Stdin may be an inherited blocking pipe. Let the command exit on
	// cancellation even if the pipe owner leaves it open.
	done := make(chan readResult, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(stdin, limit+1))
		done <- readResult{raw: raw, err: err}
	}()
	var read readResult
	select {
	case <-ctx.Done():
	case read = <-done:
	}
	if ctx.Err() != nil {
		return "", authImportCanceled()
	}
	if read.err != nil || len(read.raw) > limit {
		return "", output.ErrValidation("cannot read candidate CLI Token from stdin", "pipe a single CLI Token")
	}
	token := strings.TrimSpace(string(read.raw))
	if err := credential.ValidateBusinessToken(token, "stdin"); err != nil {
		return "", err
	}
	return token, nil
}

func requestAuthCurrent(ctx context.Context, f *cmdutil.Factory, cred *credential.BusinessContext) ([]byte, error) {
	return f.NewBusinessClientContext(ctx, cred).Do(ctx, &client.Request{
		Method:                http.MethodGet,
		Path:                  authCurrentPath,
		ExpectedSuccessStatus: http.StatusOK,
	})
}

func decodeAuthTokenSelf(raw []byte) (authTokenSelf, error) {
	var envelope struct {
		Data  json.RawMessage  `json:"data"`
		Error *json.RawMessage `json:"error"`
	}
	var self authTokenSelf
	invalid := output.ErrAPI("INVALID_TOKEN_SELF", "invalid TokenSelf response from octo-auth", "check the octo-auth gateway and response contract")
	if !uniqueTokenSelfObjectKeys(raw, true) || json.Unmarshal(raw, &envelope) != nil ||
		envelope.Error != nil || !uniqueTokenSelfObjectKeys(envelope.Data, true) {
		return self, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&self); err != nil || !self.valid() {
		return authTokenSelf{}, invalid
	}
	return self, nil
}

// Check the containing object's keys before decoding can overwrite a value.
// Fold struct keys like encoding/json does. Map keys are case-sensitive.
func uniqueTokenSelfObjectKeys(raw []byte, foldKeys bool) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	var value json.RawMessage
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return false
		}
		if foldKeys {
			key = strings.Map(foldTokenSelfKeyRune, key)
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	return true
}

func foldTokenSelfKeyRune(r rune) rune {
	// Like encoding/json, use the smallest rune in the Unicode fold set.
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

func (s *authTokenSelf) valid() bool {
	if !s.Token.valid() || s.Permissions == nil || s.BotBindings == nil {
		return false
	}
	for _, permission := range s.Permissions {
		if !permission.valid() {
			return false
		}
	}
	for _, binding := range s.BotBindings {
		id, _ := binding["bot_id"].(string)
		if _, ok := binding["bot_name"].(string); id == "" || !ok {
			return false
		}
	}
	return true
}

func (m *authTokenMetadata) valid() bool {
	return m.ID != "" && m.OwnerID != "" && m.SpaceID != "" && m.Name != nil &&
		(m.Status == "active" || m.Status == "revoked") && m.IsExpired != nil &&
		m.Version != nil && m.CreatedAt != nil && m.UpdatedAt != nil &&
		m.Remark.present && m.ExpiresAt.present && m.LastUsedAt.present
}

func (p authPermission) valid() bool {
	if !authPermissionField.MatchString(p.Domain) || p.Actions == nil {
		return false
	}
	prefix := p.Domain + ":"
	for _, action := range p.Actions {
		if action == nil {
			return false
		}
		if *action == "*" && p.Domain == "*" {
			continue
		}
		name, ok := strings.CutPrefix(*action, prefix)
		if !ok || !authPermissionField.MatchString(name) {
			return false
		}
	}
	return true
}

func (m *authTokenMetadata) verifyImport(spaceID, ownerID string) error {
	if m.Status == "revoked" {
		return output.ErrWithHint("auth_error", "TOKEN_REVOKED", "the candidate CLI Token is revoked", "provide an active CLI Token")
	}
	if *m.IsExpired {
		return output.ErrWithHint("auth_error", "TOKEN_EXPIRED", "the candidate CLI Token is expired", "provide an active CLI Token")
	}
	if m.SpaceID != spaceID {
		return output.ErrValidation("candidate CLI Token belongs to a different Space", "select the Token's target Space")
	}
	if ownerID != "" && m.OwnerID != ownerID {
		return output.ErrValidation("candidate CLI Token belongs to a different owner", "provide a Token owned by the expected account")
	}
	return nil
}

func importVerifiedToken(ctx context.Context, f *cmdutil.Factory, store *authstore.ManagedStore, baseline authstore.ProfileSnapshot, target config.Profile, token string) error {
	payload := map[string]string{
		"profile":      client.RedactBearer(baseline.Name, token),
		"api_base_url": client.RedactBearer(target.APIBaseURL, token),
		"space_id":     client.RedactBearer(target.SpaceID, token),
		"token_source": "managed_store",
	}
	meta := output.EnvelopeMeta{Identity: map[string]string{
		"type": "token", "source": "stdin", "profile": payload["profile"],
	}}
	var rendered bytes.Buffer
	render := func() error {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return f.WriteSuccessWithMeta(ctx, &rendered, raw, meta)
	}

	filtered := f.Globals.JQ != ""
	if filtered {
		if err := render(); err != nil {
			if errors.Is(err, ctx.Err()) {
				return authImportCanceled()
			}
			return err
		}
	}
	result, err := store.ImportContext(ctx, baseline, target, token, authstore.BackendAuto)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return authImportCanceled()
	}
	if errors.Is(err, authstore.ErrProfileConflict) {
		return output.ErrWithHint("validation", "PROFILE_CONFLICT", "profile changed during CLI Token verification", "retry the import after checking the target Profile")
	}
	if err != nil {
		return output.ErrWithHint("config", "CREDENTIAL_STORE_ERROR", "cannot commit the verified CLI Token", "check the Profile directory and system credential store")
	}
	if result.CleanupWarning != "" {
		warning := client.RedactBearer(result.CleanupWarning, token)
		if filtered {
			// Cleanup runs after commit, so report its warning outside the jq result.
			writeUI(f.IOStreams.StderrWithContext(ctx), warning+"\n")
		} else {
			payload["cleanup_warning"] = warning
		}
	}
	if !filtered {
		err = render()
	}
	if err == nil {
		err = f.IOStreams.WriteStdoutAfterCommit(ctx, rendered.Bytes())
	}
	if err != nil {
		return output.ErrWithHint("internal", "TOKEN_IMPORT_OUTPUT_FAILED",
			"the CLI Token was saved to the Profile, but the import result could not be rendered or written",
			"check the Profile with auth get before retrying and review the output options")
	}
	return nil
}

func authImportCanceled() error {
	return output.ErrNetwork("CLI Token import was cancelled", "retry the import")
}

func (s *authTokenSelf) redactedPayload(bearer string) ([]byte, error) {
	// Redact the projected metadata's wire values after validating their types.
	// Preserve unaffected numbers exactly, including versions above 2^53.
	raw, err := json.Marshal(&s.Token)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var metadata map[string]any
	if err := decoder.Decode(&metadata); err != nil {
		return nil, err
	}
	for key, value := range metadata {
		metadata[key] = redactAuthValue(value, bearer)
	}
	for i := range s.Permissions {
		group := &s.Permissions[i]
		group.Domain = client.RedactBearer(group.Domain, bearer)
		for _, action := range group.Actions {
			*action = client.RedactBearer(*action, bearer)
		}
	}
	for _, binding := range s.BotBindings {
		redactAuthBinding(binding, bearer)
	}
	return json.Marshal(map[string]any{
		"token": metadata, "permissions": s.Permissions, "bot_bindings": s.BotBindings,
	})
}

func redactAuthBinding(binding map[string]any, bearer string) {
	for key, value := range binding {
		switch key {
		case "token", "token_hash", "token_ciphertext", "device_code_hash":
			delete(binding, key)
			continue
		case "bot_id", "bot_name":
		default:
			if client.RedactBearer(key, bearer) != key {
				delete(binding, key)
				continue
			}
		}
		binding[key] = redactAuthValue(value, bearer)
	}
}

func redactAuthValue(value any, bearer string) any {
	switch v := value.(type) {
	case string:
		return client.RedactBearer(v, bearer)
	case json.Number, bool:
		spelling := fmt.Sprint(v)
		if masked := client.RedactBearer(spelling, bearer); masked != spelling {
			return masked
		}
	case map[string]any:
		redactAuthBinding(v, bearer)
	case []any:
		for i, elem := range v {
			v[i] = redactAuthValue(elem, bearer)
		}
	}
	return value
}
