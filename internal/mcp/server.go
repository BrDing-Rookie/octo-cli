// Package mcp implements the local stdio transport for Octo CLI's MCP tool.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	protocolVersion = "2025-11-25"
	maxFrameSize    = 8 << 20
	maxActiveCalls  = 8
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *responseError  `json:"error,omitempty"`
}

type responseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func result(id json.RawMessage, value any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: value}
}

func failure(id json.RawMessage, code int, message string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &responseError{Code: code, Message: message}}
}

type session struct {
	buildVersion string
	protocol     string
	execute      func(context.Context, []string) ExecResult
	active       map[string]*activeCall
	completed    chan completedCall
}

type inputFrame struct {
	line string
	err  error
}

// Serve exchanges newline-delimited MCP messages. Closing the input cancels
// outstanding calls. The caller owns the streams and must close a blocked input
// reader if it cancels the session while keeping the process alive.
func Serve(ctx context.Context, in io.Reader, out io.Writer, version string, execute func(context.Context, []string) ExecResult) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	frames := make(chan inputFrame)
	go readFrames(ctx, in, frames)
	encoder := json.NewEncoder(out)
	s := session{
		buildVersion: version,
		execute:      execute,
		active:       make(map[string]*activeCall),
		completed:    make(chan completedCall),
	}
	for {
		var reply *response
		select {
		case <-ctx.Done():
			return nil
		case frame, ok := <-frames:
			if !ok {
				return nil
			}
			if frame.err != nil {
				return fmt.Errorf("read MCP input: %w", frame.err)
			}
			reply = s.handle(ctx, frame.line)
		case done := <-s.completed:
			reply = s.finishCall(done)
		}
		if reply != nil {
			if err := encoder.Encode(reply); err != nil {
				return fmt.Errorf("write MCP response: %w", err)
			}
		}
	}
}

func readFrames(ctx context.Context, in io.Reader, frames chan<- inputFrame) {
	defer close(frames)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), maxFrameSize)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		select {
		case frames <- inputFrame{line: line}:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil {
		select {
		case frames <- inputFrame{err: err}:
		case <-ctx.Done():
		}
	}
}

func (s *session) handle(ctx context.Context, line string) *response {
	if !utf8.ValidString(line) {
		return failure(nil, -32700, "Parse error")
	}
	var msg request
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return failure(nil, -32700, "Parse error")
		}
		return failure(nil, -32600, "Invalid request")
	}
	if msg.JSONRPC != "2.0" || msg.Method == "" {
		return failure(nil, -32600, "Invalid request")
	}
	if msg.ID == nil {
		s.notify(&msg)
		return nil
	}
	key, ok := requestKey(msg.ID)
	if !ok {
		return failure(nil, -32600, "Request ID must be a string or integer")
	}
	if len(msg.Params) != 0 && msg.Params[0] != '{' {
		return failure(msg.ID, -32602, "Parameters must be an object")
	}
	return s.request(ctx, &msg, key)
}

// requestKey keeps string and integer IDs distinct without rounding integers.
// Equivalent JSON spellings of string IDs select the same pending call.
func requestKey(id json.RawMessage) (string, bool) {
	if len(id) == 0 {
		return "", false
	}
	if id[0] == '"' {
		var value string
		if json.Unmarshal(id, &value) != nil {
			return "", false
		}
		return "s:" + value, true
	}
	if (id[0] == '-' || id[0] >= '0' && id[0] <= '9') && !bytes.ContainsAny(id, ".eE") {
		if string(id) == "-0" {
			return "n:0", true
		}
		return "n:" + string(id), true
	}
	return "", false
}

func (s *session) request(ctx context.Context, msg *request, key string) *response {
	switch msg.Method {
	case "initialize":
		return s.initialize(msg)
	case "ping":
		return result(msg.ID, struct{}{})
	}
	if s.protocol == "" {
		return failure(msg.ID, -32000, "Initialize the MCP session first")
	}
	switch msg.Method {
	case "tools/list":
		return result(msg.ID, listTools())
	case "tools/call":
		return s.startCall(ctx, msg, key)
	default:
		return failure(msg.ID, -32601, "Method not found")
	}
}

func (s *session) initialize(msg *request) *response {
	if s.protocol != "" {
		return failure(msg.ID, -32600, "Session already initialized")
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(msg.Params, &params) != nil || params.ProtocolVersion == "" {
		return failure(msg.ID, -32602, "A protocol version is required")
	}
	switch params.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18", protocolVersion:
		s.protocol = params.ProtocolVersion
	default:
		s.protocol = protocolVersion
	}
	return result(msg.ID, map[string]any{
		"protocolVersion": s.protocol,
		"serverInfo":      map[string]string{"name": "octo-cli", "version": s.buildVersion},
		"capabilities":    map[string]any{"tools": struct{}{}},
	})
}

func (s *session) notify(msg *request) {
	if msg.Method != "notifications/cancelled" {
		return
	}
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(msg.Params, &params) != nil {
		return
	}
	key, ok := requestKey(params.RequestID)
	if !ok {
		return
	}
	if call := s.active[key]; call != nil {
		call.cancelled = true
		call.cancel()
	}
}
