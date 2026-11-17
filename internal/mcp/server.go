// Package mcp serves the Octo CLI MCP tool over stdio and Streamable HTTP.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	protocolVersion = "2025-11-25"
	maxFrameSize    = 8 << 20
	maxActiveCalls  = 8
)

type request struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	key    string
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
	msg, reply := parseRequest([]byte(line))
	if reply != nil {
		return reply
	}
	if msg.ID == nil {
		s.notify(msg)
		return nil
	}
	return s.request(ctx, msg)
}

func parseRequest(frame []byte) (msg *request, reply *response) {
	if !utf8.Valid(frame) || !json.Valid(frame) {
		return nil, failure(nil, -32700, "Parse error")
	}
	fields, ok := decodeObject(frame, "jsonrpc", "id", "method", "params")
	var protocol, method string
	if !ok || json.Unmarshal(fields["jsonrpc"], &protocol) != nil || protocol != "2.0" ||
		json.Unmarshal(fields["method"], &method) != nil || method == "" {
		return nil, failure(nil, -32600, "Invalid request")
	}
	decoded := request{ID: fields["id"], Method: method, Params: fields["params"]}
	if decoded.ID == nil {
		return &decoded, nil
	}
	key, ok := requestKey(decoded.ID)
	if !ok {
		return nil, failure(nil, -32600, "Request ID must be a string or integer")
	}
	if len(decoded.Params) != 0 && decoded.Params[0] != '{' {
		return nil, failure(decoded.ID, -32602, "Parameters must be an object")
	}
	decoded.key = key
	return &decoded, nil
}

// decodeObject keeps field names case-sensitive and rejects duplicates before
// dispatch. Values remain raw so each method can validate its own schema.
func decodeObject(raw []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if !consumeJSONToken(decoder, json.Delim('{')) {
		return nil, false
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		name, isString := token.(string)
		if err != nil || !isString || !slices.Contains(allowed, name) || fields[name] != nil {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if !consumeJSONToken(decoder, json.Delim('}')) {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return fields, true
}

func consumeJSONToken(decoder *json.Decoder, want json.Token) bool {
	token, err := decoder.Token()
	return err == nil && token == want
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

func (s *session) request(ctx context.Context, msg *request) *response {
	switch msg.Method {
	case "initialize":
		if s.protocol != "" {
			return failure(msg.ID, -32600, "Session already initialized")
		}
		var reply *response
		s.protocol, reply = initialize(msg, s.buildVersion, true)
		return reply
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
		return s.startCall(ctx, msg)
	default:
		return failure(msg.ID, -32601, "Method not found")
	}
}

func initialize(msg *request, buildVersion string, allowLegacy bool) (version string, reply *response) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(msg.Params, &params) != nil || params.ProtocolVersion == "" {
		return "", failure(msg.ID, -32602, "A protocol version is required")
	}
	version = params.ProtocolVersion
	if !supportsProtocol(version, allowLegacy) {
		version = protocolVersion
	}
	return version, result(msg.ID, map[string]any{
		"protocolVersion": version,
		"serverInfo":      map[string]string{"name": "octo-cli", "version": buildVersion},
		"capabilities":    map[string]any{"tools": struct{}{}},
	})
}

func supportsProtocol(version string, allowLegacy bool) bool {
	switch version {
	case "2024-11-05":
		return allowLegacy
	case "2025-03-26", "2025-06-18", protocolVersion:
		return true
	default:
		return false
	}
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
