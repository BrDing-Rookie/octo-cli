package mcp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestExecArgumentValidation(t *testing.T) {
	const limit = 256
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"duplicate argv", `{"name":"exec","arguments":{"args":["help"],"args":["version"]}}`},
		{"duplicate arguments object", `{"name":"exec","arguments":{"args":["help"]},"arguments":{"args":["version"]}}`},
		{"case variant parameter", `{"Name":"exec","arguments":{"args":["version"]}}`},
		{"unexpected tool parameter", `{"name":"exec","token":"fixture","arguments":{"args":["version"]}}`},
		{"unexpected argument", `{"name":"exec","arguments":{"args":["version"],"profile":"fixture"}}`},
		{"null argv", `{"name":"exec","arguments":{"args":null}}`},
		{"empty argv", `{"name":"exec","arguments":{"args":[]}}`},
		{"null list item", `{"name":"exec","arguments":{"args":["version",null]}}`},
		{"nonstring list item", `{"name":"exec","arguments":{"args":["version",7]}}`},
		{"NUL in list item", `{"name":"exec","arguments":{"args":["version\u0000"]}}`},
		{"too many arguments", `{"name":"exec","arguments":{"args":["version"` + strings.Repeat(`,""`, limit) + `]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, reply := parseToolCall(&request{ID: json.RawMessage("1"), Params: json.RawMessage(tc.raw)})
			if reply == nil || reply.Error == nil || reply.Error.Code != -32602 || args != nil {
				t.Fatal("expected JSON-RPC invalid params before invoking exec")
			}
		})
	}

	const valid = `{"name":"exec","arguments":{"args":["example","record","list","--owner","Two words","--status",""]},"_meta":{"progressToken":1}}`
	args, reply := parseToolCall(&request{Params: json.RawMessage(valid)})
	want := []string{"example", "record", "list", "--owner", "Two words", "--status", ""}
	if reply != nil || !slices.Equal(args, want) {
		t.Fatalf("valid argv = %q, want %q", args, want)
	}

	const longValid = `{"name":"exec","arguments":{"args":["version"`
	args, reply = parseToolCall(&request{Params: json.RawMessage(longValid + strings.Repeat(`,""`, limit-1) + `]}}`)})
	if reply != nil || len(args) != limit {
		t.Fatalf("argv length %d at schema limit %d, reply = %+v", len(args), limit, reply)
	}
}

func TestExecRequestRejectsAmbiguousRPCEnvelope(t *testing.T) {
	const raw = `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"exec","arguments":{"args":["version"]}}}`
	msg, reply := parseRequest([]byte(raw))
	if msg != nil || reply == nil || reply.Error == nil || reply.Error.Code != -32600 {
		t.Fatal("expected duplicate method to fail before dispatch")
	}
}
