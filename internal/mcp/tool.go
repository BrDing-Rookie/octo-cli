package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	execTool    = "exec"
	maxExecArgs = 256
)

// ExecResult preserves the underlying command's output streams and status.
type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

func listTools() map[string]any {
	return map[string]any{"tools": []map[string]any{{
		"name":        execTool,
		"description": "Run a supported Octo CLI command. HTTP uses the request Bearer and exposes registered service operations. Use schema --list or --help to discover commands. Returns stdout, stderr, and exitCode.",
		"inputSchema": map[string]any{
			"type":                 "object",
			"required":             []string{"args"},
			"additionalProperties": false,
			"properties": map[string]any{
				"args": map[string]any{
					"type":        "array",
					"items":       map[string]string{"type": "string", "pattern": `^[^\u0000]*$`},
					"minItems":    1,
					"maxItems":    maxExecArgs,
					"description": "CLI arguments after octo-cli. Pass each argument or flag value as a separate array item.",
				},
			},
		},
	}}}
}

type activeCall struct {
	id        json.RawMessage
	cancel    context.CancelFunc
	cancelled bool
}

type completedCall struct {
	key    string
	output ExecResult
}

func parseToolCall(msg *request) (args []string, reply *response) {
	params, ok := decodeObject(msg.Params, "name", "arguments", "_meta")
	var name string
	if !ok || json.Unmarshal(params["name"], &name) != nil || name == "" {
		return nil, failure(msg.ID, -32602, "Tool parameters require a name and arguments")
	}
	if meta := params["_meta"]; len(meta) != 0 && meta[0] != '{' {
		return nil, failure(msg.ID, -32602, "Tool metadata must be an object")
	}
	if name != execTool {
		return nil, failure(msg.ID, -32602, "Unknown tool")
	}
	args, ok = execArgs(params["arguments"])
	if !ok {
		return nil, failure(msg.ID, -32602, fmt.Sprintf("exec requires 1 to %d strings in args without NUL characters", maxExecArgs))
	}
	return args, nil
}

func (s *session) startCall(ctx context.Context, msg *request) *response {
	args, reply := parseToolCall(msg)
	if reply != nil {
		return reply
	}
	key := msg.key
	if _, exists := s.active[key]; exists {
		return failure(msg.ID, -32600, "Request ID is already in use")
	}
	if len(s.active) >= maxActiveCalls {
		return failure(msg.ID, -32000, "Too many active tool calls")
	}
	callCtx, cancel := context.WithCancel(ctx)
	s.active[key] = &activeCall{id: msg.ID, cancel: cancel}
	go func() {
		output := s.execute(callCtx, args)
		select {
		case s.completed <- completedCall{key: key, output: output}:
		case <-ctx.Done():
		}
	}()
	return nil
}

func execArgs(raw json.RawMessage) ([]string, bool) {
	arguments, ok := decodeObject(raw, "args")
	if !ok {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(arguments["args"]))
	if !consumeJSONToken(decoder, json.Delim('[')) {
		return nil, false
	}
	var args []string
	for decoder.More() {
		if len(args) == maxExecArgs {
			return nil, false
		}
		token, err := decoder.Token()
		arg, isString := token.(string)
		if err != nil || !isString || strings.ContainsRune(arg, 0) {
			return nil, false
		}
		args = append(args, arg)
	}
	if !consumeJSONToken(decoder, json.Delim(']')) || len(args) == 0 {
		return nil, false
	}
	return args, true
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content           []textContent `json:"content"`
	IsError           bool          `json:"isError"`
	StructuredContent *ExecResult   `json:"structuredContent,omitempty"`
}

func (s *session) finishCall(done completedCall) *response {
	call := s.active[done.key]
	delete(s.active, done.key)
	call.cancel()
	if call.cancelled {
		return nil
	}
	return execResponse(call.id, s.protocol, done.output)
}

func execResponse(id json.RawMessage, version string, exec ExecResult) *response {
	text, err := json.Marshal(exec)
	if err != nil {
		return failure(id, -32603, "Could not encode tool output")
	}
	output := toolResult{
		Content: []textContent{{Type: "text", Text: string(text)}},
		IsError: exec.ExitCode != 0,
	}
	if version >= "2025-06-18" {
		output.StructuredContent = &exec
	}
	return result(id, output)
}
