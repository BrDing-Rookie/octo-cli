package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// EnvelopeMeta carries optional envelope-level metadata that callers may attach
// to a success response. Fields are emitted with an underscore prefix to mark
// them as CLI-added (not backend data).
//
// Identity, when non-nil, replaces the default identity object. The Factory sets
// it to an object describing the bot the command acted as (profile, robot id,
// kind, source) so every response echoes the active identity.
type EnvelopeMeta struct {
	RateLimit json.RawMessage
	Notice    json.RawMessage
	Identity  any
	// DataEnvelope recognizes the service's data and optional pagination fields.
	DataEnvelope bool
}

// IdentityType is the actor type tag. The envelope's identity is always an
// object so the field has one consistent shape; commands that resolve a
// credential enrich it via EnvelopeMeta.Identity, others get just {type}.
const IdentityType = "bot"

// defaultIdentity is the minimal identity object emitted when no richer one is
// supplied (e.g. unauthenticated diagnostic commands like version/schema).
func defaultIdentity() map[string]any {
	return map[string]any{"type": IdentityType}
}

// WriteSuccess emits the result and extracts pagination metadata when present.
func WriteSuccess(w io.Writer, raw json.RawMessage, meta EnvelopeMeta) error {
	var identity any = defaultIdentity()
	if meta.Identity != nil {
		identity = meta.Identity
	}
	env := map[string]any{
		"ok":       true,
		"identity": identity,
	}

	dataField, paginationField := backendSuccessPayload(raw, meta.DataEnvelope)
	if len(dataField) == 0 {
		env["data"] = nil
	} else {
		env["data"] = dataField
	}
	if len(paginationField) > 0 {
		env["_pagination"] = paginationField
	}

	if len(meta.RateLimit) > 0 {
		env["_rate_limit"] = meta.RateLimit
	}
	if len(meta.Notice) > 0 {
		env["_notice"] = meta.Notice
	}

	return writeJSON(w, env)
}

// WriteError emits an error envelope to w. err is rendered as the envelope's
// error object; non-ExitError values are wrapped as a generic internal error.
func WriteError(w io.Writer, err error) error {
	ee := AsExitError(err)
	if ee == nil {
		ee = &ExitError{
			Type:    "internal",
			Code:    "INTERNAL",
			Message: errorMessage(err),
		}
	}

	errObj := map[string]any{
		"type":    ee.Type,
		"code":    ee.Code,
		"message": ee.Message,
	}
	if ee.Hint != "" {
		errObj["hint"] = ee.Hint
	}
	if len(ee.Detail) > 0 {
		errObj["detail"] = ee.Detail
	}

	return writeJSON(w, map[string]any{
		"ok":    false,
		"error": errObj,
	})
}

// backendSuccessPayload extracts the data and pagination from known envelopes.
// The data-envelope opt-in also supports paginated aggregates with object data.
func backendSuccessPayload(raw json.RawMessage, dataEnvelope bool) (data, pagination json.RawMessage) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, nil
	}
	d, hasData := obj["data"]
	if !hasData {
		return raw, nil
	}
	p := obj["pagination"]
	if isJSONObject(p) && (isJSONArray(d) || (dataEnvelope && isJSONObject(d))) {
		return d, p
	}
	if dataEnvelope && len(obj) == 1 {
		return d, nil
	}
	return raw, nil
}

func isJSONArray(raw json.RawMessage) bool {
	for _, b := range raw {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '['
	}
	return false
}

func isJSONObject(raw json.RawMessage) bool {
	for _, b := range raw {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '{'
	}
	return false
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeJSON(w io.Writer, v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	buf = append(buf, '\n')
	_, werr := w.Write(buf)
	return werr
}
