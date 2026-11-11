package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

// TestNullIsRefusedOnAConstrainedField is the direct behavioural pin, using a synthetic
// schema so every combination of (required, optional) × (enum, uint64) is present whether or
// not a spec happens to declare it today.
func TestNullIsRefusedOnAConstrainedField(t *testing.T) {
	schema := &registry.SchemaInfo{
		Type:     "object",
		Required: []string{"req_enum"},
		Properties: map[string]registry.SchemaInfo{
			"req_enum":  {Type: "string", Enum: []any{"a", "b"}},
			"opt_enum":  {Type: "string", Enum: []any{"a", "b"}},
			"opt_id":    {Type: "integer", Format: "uint64"},
			"free_text": {Type: "string"},
			"nested": {Type: "object", Properties: map[string]registry.SchemaInfo{
				"inner_enum": {Type: "string", Enum: []any{"x"}},
				"inner_id":   {Type: "integer", Format: "uint64"},
			}},
			"items": {Type: "array", Items: &registry.SchemaInfo{
				Type: "object", Properties: map[string]registry.SchemaInfo{
					"kind": {Type: "string", Enum: []any{"k"}},
				},
			}},
		},
	}
	v := bodySchemaValidator{flagFor: map[string]string{"opt_enum": "opt-enum", "opt_id": "opt-id"}}

	for _, tc := range []struct {
		name     string
		body     map[string]any
		wantCode string
		wantText string
	}{
		{
			name:     "optional enum field set to null",
			body:     map[string]any{"req_enum": "a", "opt_enum": nil},
			wantCode: enumNotAllowed,
			wantText: "--opt-enum",
		},
		{
			name:     "optional uint64 field set to null",
			body:     map[string]any{"req_enum": "a", "opt_id": nil},
			wantCode: "VALIDATION_ERROR",
			wantText: "--opt-id",
		},
		{
			name:     "nested enum field set to null",
			body:     map[string]any{"req_enum": "a", "nested": map[string]any{"inner_enum": nil}},
			wantCode: enumNotAllowed,
			wantText: "nested.inner_enum",
		},
		{
			name:     "nested uint64 field set to null",
			body:     map[string]any{"req_enum": "a", "nested": map[string]any{"inner_id": nil}},
			wantCode: "VALIDATION_ERROR",
			wantText: "nested.inner_id",
		},
		{
			name:     "enum inside an array of objects set to null",
			body:     map[string]any{"req_enum": "a", "items": []any{map[string]any{"kind": nil}}},
			wantCode: enumNotAllowed,
			wantText: "items[0].kind",
		},
		{
			// Unchanged behaviour, kept here so the required path is visibly a
			// refusal too rather than left to a different test file.
			name:     "required enum field set to null is still reported as missing",
			body:     map[string]any{"req_enum": nil},
			wantCode: "VALIDATION_ERROR",
			wantText: "missing required field(s): req_enum",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.validate(schema, tc.body, "", "")
			if err == nil {
				t.Fatalf("body %#v was accepted — a present null on a constrained field is "+
					"forwarded to the backend, which is the bypass this closes", tc.body)
			}
			if err.Code != tc.wantCode {
				t.Errorf("code = %s, want %s", err.Code, tc.wantCode)
			}
			if !strings.Contains(err.Message, tc.wantText) {
				t.Errorf("message %q should reference %q", err.Message, tc.wantText)
			}
		})
	}

	// The allow direction, and the bound on the change: a null on a property with no
	// enum and no uint64 format is still forwarded. Refusing it too would be a wider
	// contract change than the defect calls for — a backend may accept null to clear an
	// optional field — and nothing in review asked for it.
	for _, body := range []map[string]any{
		{"req_enum": "a", "free_text": nil},
		{"req_enum": "a", "nested": map[string]any{}},
		{"req_enum": "a", "opt_enum": "b", "opt_id": json.Number("18446744073709551615")},
	} {
		if err := v.validate(schema, body, "", ""); err != nil {
			t.Errorf("body %#v must still be accepted: %v", body, err)
		}
	}
}

// TestRequiredParameterRejectsAnEmptyValue is round-17 P1-C.
//
// This PR introduced rejectEmptyPathValue with an explicit rationale — `drive share revoke
// "$SHARE_ID"` with an unset shell variable would send DELETE to `{mount}/shares/` rather
// than fail — and applied it to path values only. The identical unset-variable failure was
// unguarded one and two functions away, because cobra's MarkFlagRequired only checks whether
// the flag was *given*: `--flag ""` satisfies it.
//
// Reproduced against a binary built from 2153838, with the omitted-flag control alongside:
//
//	docs content edit D1 --base-version "" …  -> PATCH went out with "If-Match": ""
//	docs content edit D1 …                    -> required flag(s) "base-version" not set
//	drive browse --space-id "" --dry-run      -> …/browse?space_id=
//
// An empty If-Match is not a valid entity-tag list, and the idiomatic server-side read
// (`if h := r.Header.Get("If-Match"); h != "" { …CAS… }`) skips the compare-and-swap
// entirely — so the concurrency gate the spec marks required is defeated on a collaborative
// document edit, and the failure mode is a lost update.
//
// The guard is on the spec's own `required`, so an optional parameter can still be sent
// empty: some backends use an empty value to mean "clear this filter", and nothing in review
// asked for that to change.
func TestRequiredParameterRejectsAnEmptyValue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		label    string
		value    string
		required bool
		wantErr  bool
	}{
		{"a required parameter given an empty string", "--space-id", "", true, true},
		{"a required parameter given a value", "--space-id", "shared:s1", true, false},
		{"an optional parameter given an empty string", "--keyword", "", false, false},
		{"an optional parameter given a value", "--keyword", "x", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectEmptyRequiredValue(tc.label, tc.value, tc.required)
			if tc.wantErr && err == nil {
				t.Fatalf("%s=%q must be refused: cobra's required check only sees whether the "+
					"flag was given, so an empty value reaches the wire", tc.label, tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("%s=%q must be accepted: %v", tc.label, tc.value, err)
			}
			if tc.wantErr && !strings.Contains(err.Message, tc.label) {
				t.Errorf("the refusal must name the flag: %s", err.Message)
			}
		})
	}
}
