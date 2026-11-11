package registry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeclaredDefaultsStayInternalUntilUniformMaterialization(test *testing.T) {
	for _, schema := range []SchemaInfo{
		{Type: "boolean", Default: true},
		{Type: "boolean", Default: false},
		{Type: "string", Default: "value"},
		{Type: "integer", Default: 20},
	} {
		encoded, err := json.Marshal(schema)
		if err != nil {
			test.Fatal(err)
		}
		if strings.Contains(string(encoded), `"default"`) {
			test.Fatalf("schema advertises a default without uniform wire behavior: %s", encoded)
		}
	}
}

func TestBodyBooleanDefaultsSurviveSchemaResolution(test *testing.T) {
	for _, declared := range []bool{false, true} {
		schema := resolveSchema(nil, map[string]any{"allOf": []any{map[string]any{"type": "boolean", "default": declared}}})
		if schema.Default != declared {
			test.Errorf("default=%#v; want %v", schema.Default, declared)
		}
	}
	schema := resolveSchema(nil, map[string]any{"default": false, "allOf": []any{map[string]any{"type": "boolean", "default": true}}})
	if schema.Default != false {
		test.Fatal("allOf must not replace an explicit false default")
	}
}
