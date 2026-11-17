package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain_MCP(t *testing.T) {
	const token = "fixture_mcp_bearer"
	const requestBody = `{"id":9007199254740993,"text":"one argument with spaces"}`
	started := make(chan string, 2)
	cancelled := make(chan string, 2)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("gateway did not receive the configured Bearer")
		}
		switch r.URL.Path {
		case "/v1/items":
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != requestBody {
				t.Errorf("gateway body = %q, error = %v", body, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":9007199254740993,"echo":"`+token+`"}`)
		case "/v1/wait", "/v1/eof":
			started <- r.URL.Path
			<-r.Context().Done()
			cancelled <- r.URL.Path
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gateway.Close)

	cli := startMCP(t, nil, "OCTO_TOKEN="+token, "OCTO_API_BASE_URL="+gateway.URL)
	cli.discover()

	call := cli.call(2, "api", "POST", "/v1/items", "--data", requestBody, "--verbose")
	if call.IsError || call.Output.ExitCode != 0 || !strings.Contains(call.Output.Stdout, "9007199254740993") ||
		!strings.Contains(call.Output.Stderr, "POST") {
		t.Fatalf("unexpected successful command result: %+v", call.Output)
	}
	if strings.Contains(call.Output.Stdout+call.Output.Stderr+call.Content[0].Text, token) {
		t.Fatal("tool response exposed the configured Bearer")
	}

	version := cli.call(3, "version")
	if version.IsError || version.Output.Stderr != "" || !strings.Contains(version.Output.Stdout, `"version"`) {
		t.Fatalf("version inherited state from another tool call: %+v", version.Output)
	}

	missing := cli.call(4, "api", "GET", "/v1/missing")
	if !missing.IsError || missing.Output.ExitCode == 0 || !strings.Contains(missing.Output.Stderr, `"error"`) {
		t.Fatalf("expected CLI error envelope: %+v", missing.Output)
	}

	for i, args := range [][]string{
		{"api", "POST", "/v1/items", "--data=@local.json"},
		{"api", "POST", "/v1/items", "--data", "@-"},
		{"api", "GET", "/v1/missing", "--credential-file", "local-token"},
		{"api", "GET", "/v1/missing", "--profile", "other"},
		{"skills", "--install", t.TempDir()},
		{"auth", "list"},
		{"mcp"},
		{"upgrade"},
	} {
		refused := cli.call(i+10, args...)
		if !refused.IsError || refused.Output.ExitCode != 2 || refused.Output.Stdout != "" {
			t.Fatalf("%v should return a CLI validation error: %+v", args, refused.Output)
		}
	}

	cli.send(`{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"other","arguments":{"args":["version"]}}}`)
	if r := cli.receive("20"); r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("unknown tool should return invalid params: %+v", r)
	}
	cli.send(`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"exec","arguments":{"args":["version"],"token":"fixture"}}}`)
	if r := cli.receive("21"); r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("call-time token override should return invalid params: %+v", r)
	}

	cli.send(`{"jsonrpc":"2.0","id":"wait","method":"tools/call","params":{"name":"exec","arguments":{"args":["api","GET","/v1/wait"]}}}`)
	cli.await(started, "/v1/wait")
	cli.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"wait"}}`)
	cli.await(cancelled, "/v1/wait")
	cli.send(`{"jsonrpc":"2.0","id":"ping","method":"ping"}`)
	if r := cli.receive(`"ping"`); string(r.Result) != "{}" {
		t.Fatalf("ping after cancellation: %+v", r)
	}
	cli.send(`{"jsonrpc":"2.0","id":"eof","method":"tools/call","params":{"name":"exec","arguments":{"args":["api","GET","/v1/eof"]}}}`)
	cli.await(started, "/v1/eof")
	cli.close()
	cli.await(cancelled, "/v1/eof")
}

func TestMain_MCPDiscoveryWithoutCredential(t *testing.T) {
	cli := startMCP(t, nil, "OCTO_FORMAT=invalid-format")
	cli.discover()
	call := cli.call(2, "api", "GET", "/v1/items", "--format", "json")
	if !call.IsError || call.Output.ExitCode != 3 || !strings.Contains(call.Output.Stderr, "auth_error") {
		t.Fatalf("expected tool-level authentication error: %+v", call.Output)
	}
	cli.close()

	help := exec.CommandContext(t.Context(), cli.cmd.Path, "mcp")
	help.Env = cli.cmd.Env
	if out, err := help.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("serve")) {
		t.Fatalf("bare mcp command should show help: %v\n%s", err, out)
	}
}

func TestMain_MCPCredentialFileWithProfile(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "cli")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const profileConfig = `{
		"version":1,
		"profiles":{"agent":{
			"api_base_url":"https://octo.example.invalid",
			"space_id":"fixture-space",
			"token_source":{"type":"token_file","path":"profile.token"}
		}}
	}`
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(profileConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "octo.token")
	const bearer = "fixture_mcp_from_file"
	if err := os.WriteFile(tokenFile, []byte(bearer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := startMCP(t, []string{"--profile", "agent"}, "OCTO_CONFIG_DIR="+configDir, "OCTO_TOKEN_FILE="+tokenFile)
	cli.discover()
	probe := cli.call(2, "api", "GET", "/v1/items", "--dry-run")
	for _, want := range []string{"https://octo.example.invalid/v1/items", "fixture-space", "agent", "env:OCTO_TOKEN_FILE"} {
		if !strings.Contains(probe.Output.Stdout, want) {
			t.Errorf("dry-run preview should contain %q", want)
		}
	}
	if probe.IsError || strings.Contains(probe.Output.Stdout+probe.Output.Stderr, bearer) {
		t.Fatalf("unexpected dry-run result: %+v", probe.Output)
	}
	cli.close()
}

type mcpProcess struct {
	t      *testing.T
	ctx    context.Context
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *bytes.Buffer
}

func startMCP(t *testing.T, launchFlags []string, env ...string) *mcpProcess {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "octo-cli")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, append(launchFlags, "mcp", "serve")...)
	cmd.Env = hermeticEnv(append([]string{"OCTO_CONFIG_DIR=" + filepath.Join(t.TempDir(), "cli")}, env...)...)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cancel()
			_ = cmd.Wait()
		}
	})
	return &mcpProcess{t: t, ctx: ctx, cmd: cmd, in: in, out: bufio.NewReader(out), stderr: &stderr}
}

type mcpReply struct {
	JSONRPC string
	ID      json.RawMessage
	Result  json.RawMessage
	Error   *struct {
		Code    int
		Message string
	}
}

type mcpExecReply struct {
	IsError bool
	Content []struct{ Text string }
	Output  struct {
		ExitCode       int
		Stdout, Stderr string
	} `json:"structuredContent"`
}

func (p *mcpProcess) discover() {
	p.t.Helper()
	p.send(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	init := p.receive(`"init"`)
	if init.Error != nil || !bytes.Contains(init.Result, []byte(`"protocolVersion":"2025-11-25"`)) {
		p.t.Fatalf("initialize failed: %+v", init)
	}
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	p.send(`{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list"}`)
	var list struct {
		Tools []struct {
			Name        string
			InputSchema struct {
				Required []string
			}
		}
	}
	if err := json.Unmarshal(p.receive("9007199254740993").Result, &list); err != nil ||
		len(list.Tools) != 1 || list.Tools[0].Name != "exec" ||
		len(list.Tools[0].InputSchema.Required) != 1 || list.Tools[0].InputSchema.Required[0] != "args" {
		p.t.Fatalf("tools/list = %+v, error = %v, want only exec with required args", list, err)
	}
}

func (p *mcpProcess) call(id int, args ...string) mcpExecReply {
	p.t.Helper()
	request, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{
			"name": "exec", "arguments": map[string]any{"args": args},
		},
	})
	if err != nil {
		p.t.Fatal(err)
	}
	p.send(string(request))
	r := p.receive(strconv.Itoa(id))
	var result mcpExecReply
	if r.Error != nil || json.Unmarshal(r.Result, &result) != nil || len(result.Content) == 0 {
		p.t.Fatalf("tools/call did not return content: %+v", r)
	}
	return result
}

func (p *mcpProcess) send(message string) {
	p.t.Helper()
	if _, err := io.WriteString(p.in, message+"\n"); err != nil {
		p.t.Fatalf("send MCP request: %v", err)
	}
}

func (p *mcpProcess) receive(id string) mcpReply {
	p.t.Helper()
	var r mcpReply
	line, err := p.out.ReadBytes('\n')
	if err != nil {
		_ = p.in.Close()
		_ = p.cmd.Wait()
		p.t.Fatalf("read MCP response: %v; process stderr: %s", err, p.stderr.String())
	}
	if err := json.Unmarshal(line, &r); err != nil {
		p.t.Fatalf("decode MCP response frame: %v", err)
	}
	if r.JSONRPC != "2.0" || string(r.ID) != id {
		p.t.Fatalf("RPC version = %q, id = %s, want version 2.0 and id %s", r.JSONRPC, r.ID, id)
	}
	return r
}

func (p *mcpProcess) await(events <-chan string, path string) {
	p.t.Helper()
	select {
	case got := <-events:
		if got != path {
			p.t.Fatalf("gateway event for %s, want %s", got, path)
		}
	case <-p.ctx.Done():
		p.t.Fatalf("timed out waiting for a gateway event for %s", path)
	}
}

func (p *mcpProcess) close() {
	p.t.Helper()
	if err := p.in.Close(); err != nil {
		p.t.Fatal(err)
	}
	if err := p.cmd.Wait(); err != nil || p.stderr.Len() > 0 {
		p.t.Fatalf("MCP server exit: %v; stderr: %s", err, p.stderr.String())
	}
}
