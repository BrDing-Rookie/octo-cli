package mcp

import (
	"context"
	"encoding/json"
)

const execTool = "exec"

// ExecResult preserves the underlying command's output streams and status.
type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

func listTools() map[string]any {
	return map[string]any{"tools": []map[string]any{{
		"name":        execTool,
		"description": "Run an Octo CLI command with the server's configured credentials. Use schema --list or --help to discover commands. Returns stdout, stderr, and exitCode.",
		"inputSchema": json.RawMessage(`{
			"type": "object",
			"properties": {
				"args": {
					"type": "array", "items": {"type": "string"}, "minItems": 1,
					"description": "CLI arguments after octo-cli. Pass each argument or flag value as a separate array item."
				}
			},
			"required": ["args"],
			"additionalProperties": false
		}`),
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

func (s *session) startCall(ctx context.Context, msg *request, key string) *response {
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(msg.Params, &params) != nil || params.Name == "" {
		return failure(msg.ID, -32602, "A tool name and arguments are required")
	}
	if params.Name != execTool {
		return failure(msg.ID, -32602, "Unknown tool")
	}
	args, ok := execArgs(params.Arguments)
	if !ok {
		return failure(msg.ID, -32602, "exec requires args as a nonempty array of strings")
	}
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

func execArgs(arguments map[string]json.RawMessage) ([]string, bool) {
	var values []*string
	if len(arguments) != 1 || json.Unmarshal(arguments["args"], &values) != nil || len(values) == 0 {
		return nil, false
	}
	args := make([]string, len(values))
	for i, value := range values {
		if value == nil {
			return nil, false
		}
		args[i] = *value
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
	text, err := json.Marshal(done.output)
	if err != nil {
		return failure(call.id, -32603, "Could not encode tool output")
	}
	output := toolResult{
		Content: []textContent{{Type: "text", Text: string(text)}},
		IsError: done.output.ExitCode != 0,
	}
	if s.protocol >= "2025-06-18" {
		output.StructuredContent = &done.output
	}
	return result(call.id, output)
}
