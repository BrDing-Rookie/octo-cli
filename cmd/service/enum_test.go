package service

import (
	"encoding/json"

	"strings"

	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

// --- canonical comparison ---

// TestEnum_CanonicalComparison pins the type-tolerance the enum gate needs: the
// same wire value arrives as different Go types depending on whether it came
// from a promoted flag (int), from --data (float64) or from a uint64 id flag
// (json.Number), while every spec enum entry is whatever encoding/json produced
// for the spec literal. A plain == would reject valid input on the --data path.
func TestEnum_CanonicalComparison(t *testing.T) {
	intEnum := []any{float64(1), float64(2), float64(5)}
	strEnum := []any{"view", "download"}
	boolEnum := []any{true}

	allowed := []struct {
		name  string
		value any
		enum  []any
	}{
		{"promoted int flag", 2, intEnum},
		{"--data float", float64(2), intEnum},
		{"--data integral float written as 2.0", 2.0, intEnum},
		{"json.Number", json.Number("5"), intEnum},
		{"int64", int64(1), intEnum},
		{"uint64", uint64(1), intEnum},
		{"string", "download", strEnum},
		{"bool", true, boolEnum},
		{"explicitly nullable enum", nil, []any{"member", nil}},
		{"empty enum accepts anything", "whatever", nil},
	}
	for _, tc := range allowed {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if err := checkEnum("--x", tc.value, tc.enum); err != nil {
				t.Errorf("checkEnum(%#v) = %v, want nil", tc.value, err)
			}
		})
	}

	rejected := []struct {
		name  string
		value any
		enum  []any
	}{
		{"int outside the set", 9, intEnum},
		{"zero is not a member", 0, intEnum},
		{"negative", -1, intEnum},
		{"float outside the set", float64(3), intEnum},
		{"non-integral float", 1.5, intEnum},
		{"string is not a number", "1", intEnum},
		{"number is not a string", float64(1), strEnum},
		{"string outside the set", "edit", strEnum},
		{"empty string", "", strEnum},
		{"bool outside the set", false, boolEnum},
		{"literal null text is not JSON null", "null", []any{"member", nil}},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := checkEnum("--x", tc.value, tc.enum)
			if err == nil {
				t.Fatalf("checkEnum(%#v) = nil, want rejection", tc.value)
			}
			if err.Type != "validation" || err.Code != enumNotAllowed {
				t.Errorf("err = %s/%s, want validation/%s", err.Type, err.Code, enumNotAllowed)
			}
			if err.ExitCode() != 2 {
				t.Errorf("exit code = %d, want 2", err.ExitCode())
			}
			if !strings.Contains(err.Message, "--x") {
				t.Errorf("message %q should name the flag", err.Message)
			}
		})
	}
}

// TestEnum_NonScalarIsRejected pins that an object / array / null where the
// schema declares a scalar vocabulary fails locally. Forwarding it is what let
// `--data '{"im_channel_type":[1]}'` reach the backend and come back as an
// internal decode error naming a server struct — the same leak the scalar cases
// close.
func TestEnum_NonScalarIsRejected(t *testing.T) {
	for _, value := range []any{
		map[string]any{"a": 1},
		[]any{"view"},
		nil,
	} {
		err := checkEnum("--x", value, []any{"view", "download"})
		if err == nil {
			t.Errorf("checkEnum(%#v) = nil, want rejection", value)
			continue
		}
		if err.Code != enumNotAllowed {
			t.Errorf("checkEnum(%#v) code = %s, want %s", value, err.Code, enumNotAllowed)
		}
	}
}

// --- schema walk: kinds the specs do and do not exercise today ---

// TestEnum_BodySchemaWalkCoversEveryKind drives the validator against a
// synthetic schema so int / string / bool enums, array-item enums and enums
// nested inside an array of objects are all covered. bool enums have no spec
// site today; this is what keeps the branch honest if one lands.
func TestEnum_BodySchemaWalkCoversEveryKind(t *testing.T) {
	schema := &registry.SchemaInfo{
		Type: "object",
		Properties: map[string]registry.SchemaInfo{
			"mode":    {Type: "string", Enum: []any{"fast", "slow"}},
			"level":   {Type: "integer", Enum: []any{float64(1), float64(2)}},
			"strict":  {Type: "boolean", Enum: []any{true}},
			"tags":    {Type: "array", Items: &registry.SchemaInfo{Type: "string", Enum: []any{"a", "b"}}},
			"sources": {Type: "array", Items: &registry.SchemaInfo{Type: "object", Properties: map[string]registry.SchemaInfo{"kind": {Type: "integer", Enum: []any{float64(1), float64(3)}}, "mode": {Type: "string", Enum: []any{"fast", "slow"}}}}},
		},
	}
	v := bodySchemaValidator{flagFor: map[string]string{"mode": "mode", "level": "level"}}

	ok := map[string]any{
		"mode": "fast", "level": 2, "strict": true,
		"tags":    []any{"a", "b"},
		"sources": []any{map[string]any{"kind": float64(3)}},
	}
	if err := v.validate(schema, ok, "", ""); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}

	cases := []struct {
		name      string
		body      map[string]any
		wantLabel string
	}{
		{"string enum", map[string]any{"mode": "sideways"}, "--mode"},
		{"int enum", map[string]any{"level": 7}, "--level"},
		{"bool enum", map[string]any{"strict": false}, "field strict"},
		{"array item enum", map[string]any{"tags": []any{"a", "z"}}, "field tags"},
		{"enum nested in an array of objects", map[string]any{"sources": []any{map[string]any{"kind": float64(9)}}}, "--data field sources[0].kind"},
		// A nested field sharing its name with a top-level promoted flag must NOT
		// borrow that flag's label: telling an agent to fix --mode when the bad
		// value is at sources[0].mode sends it to the wrong input.
		{"nested field shadowing a top-level flag name", map[string]any{"sources": []any{map[string]any{"mode": "sideways"}}}, "--data field sources[0].mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.validate(schema, tc.body, "", "")
			if err == nil {
				t.Fatalf("body %#v was accepted, want rejection", tc.body)
			}
			if err.Code != enumNotAllowed {
				t.Fatalf("code = %s, want %s", err.Code, enumNotAllowed)
			}
			if !strings.Contains(err.Message, tc.wantLabel) {
				t.Errorf("message %q should reference %q", err.Message, tc.wantLabel)
			}
		})
	}
}

// TestEnum_StructuralErrorsKeepTheirCode pins that adding the enum gate did not
// rewrite the pre-existing required-field / shape envelope: those stay
// VALIDATION_ERROR so nothing branching on the old code breaks.
func TestEnum_StructuralErrorsKeepTheirCode(t *testing.T) {
	schema := &registry.SchemaInfo{
		Type:     "object",
		Required: []string{"q"},
		Properties: map[string]registry.SchemaInfo{
			"q":     {Type: "string"},
			"items": {Type: "array", MinItems: 1, Items: &registry.SchemaInfo{Type: "string"}},
		},
	}
	v := bodySchemaValidator{}
	err := v.validate(schema, map[string]any{}, "", "")
	if err == nil || err.Code != "VALIDATION_ERROR" {
		t.Fatalf("missing required field = %v, want VALIDATION_ERROR", err)
	}
	err = v.validate(schema, map[string]any{"q": "x", "items": []any{}}, "", "")
	if err == nil || err.Code != "VALIDATION_ERROR" {
		t.Fatalf("minItems violation = %v, want VALIDATION_ERROR", err)
	}
}
