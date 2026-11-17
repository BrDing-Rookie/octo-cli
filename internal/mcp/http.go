package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
)

const (
	httpEndpointPath   = "/mcp"
	httpDefaultVersion = "2025-03-26"
	httpCallTimeout    = 2 * time.Minute
	// DefaultHTTPShutdownTimeout covers a request's body read, execution and response.
	DefaultHTTPShutdownTimeout = httpCallTimeout + 30*time.Second
)

// HTTPOptions configures the two phases of stopping the listener.
type HTTPOptions struct {
	DrainDelay      time.Duration
	ShutdownTimeout time.Duration
}

// ServeHTTP serves JSON responses over stateless Streamable HTTP. The Octo
// gateway authenticates and authorizes the Bearer supplied to execute.
func ServeHTTP(ctx context.Context, listener net.Listener, version string, options HTTPOptions, execute func(ctx context.Context, bearer string, args []string) ExecResult) error {
	// A stop signal starts draining. Active requests retain their normal
	// deadlines and client disconnect handling until the grace period expires.
	requestBase, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	transport := &httpTransport{buildVersion: version, execute: execute}
	mux := http.NewServeMux()
	mux.Handle(httpEndpointPath, transport)
	mux.HandleFunc("GET /readyz", transport.ready)
	mux.HandleFunc("GET /metrics", transport.metrics)
	server := &http.Server{
		Handler:           mux,
		BaseContext:       func(net.Listener) context.Context { return requestBase },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      httpCallTimeout + 30*time.Second,
		IdleTimeout:       time.Minute,
	}
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(listener) }()
	select {
	case err := <-serving:
		return httpServeError(err)
	case <-ctx.Done():
		transport.draining.Store(true)
	}

	timer := time.NewTimer(options.DrainDelay)
	defer timer.Stop()
	select {
	case err := <-serving:
		return httpServeError(err)
	case <-timer.C:
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		cancelRequests()
		return fmt.Errorf("drain MCP HTTP requests: %w", errors.Join(err, server.Close()))
	}
	return httpServeError(<-serving)
}

func httpServeError(err error) error {
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve MCP over HTTP: %w", err)
	}
	return nil
}

type httpTransport struct {
	buildVersion string
	execute      func(context.Context, string, []string) ExecResult
	draining     atomic.Bool
	inflight     atomic.Int64
}

func (h *httpTransport) ready(w http.ResponseWriter, _ *http.Request) {
	if h.draining.Load() {
		http.Error(w, "MCP server is draining", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *httpTransport) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	const gauge = "# HELP octo_mcp_exec_inflight Number of executing HTTP MCP calls.\n" +
		"# TYPE octo_mcp_exec_inflight gauge\nocto_mcp_exec_inflight %d\n"
	_, _ = fmt.Fprintf(w, gauge, h.inflight.Load()) //nolint:errcheck // scraper may disconnect
}

func (h *httpTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// The endpoint serves native clients and backend-to-backend requests.
	// An empty browser origin allowlist protects the loopback listener.
	if len(r.Header.Values("Origin")) != 0 {
		http.Error(w, "Origin is not allowed", http.StatusForbidden)
		return
	}
	bearer := httpBearer(r.Header)
	if bearer == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="octo"`)
		http.Error(w, "An Octo Bearer token is required", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Use POST for MCP requests", http.StatusMethodNotAllowed)
		return
	}
	h.handlePost(w, r, bearer)
}

func httpBearer(header http.Header) string {
	values := header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || credential.ValidateBearer(parts[1]) != nil {
		return ""
	}
	return parts[1]
}

func (h *httpTransport) handlePost(w http.ResponseWriter, r *http.Request, bearer string) {
	version := r.Header.Get("MCP-Protocol-Version")
	if version == "" {
		version = httpDefaultVersion
	}
	if !supportsProtocol(version, false) {
		http.Error(w, "Unsupported MCP protocol version", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "MCP requests require application/json", http.StatusUnsupportedMediaType)
		return
	}
	if !acceptsJSON(strings.Join(r.Header.Values("Accept"), ",")) {
		http.Error(w, "MCP responses use application/json", http.StatusNotAcceptable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFrameSize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "MCP request body is too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Could not read MCP request", http.StatusBadRequest)
		}
		return
	}
	msg, reply := parseRequest(body)
	if reply != nil {
		writeRPC(w, http.StatusBadRequest, reply)
		return
	}
	if msg.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeRPC(w, http.StatusOK, h.dispatch(r.Context(), msg, version, bearer))
}

func acceptsJSON(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return true
	}
	for _, item := range strings.Split(accept, ",") {
		mediaType, params, err := mime.ParseMediaType(item)
		if err != nil || mediaType != "application/json" && mediaType != "application/*" && mediaType != "*/*" {
			continue
		}
		if q, ok := params["q"]; ok {
			weight, err := strconv.ParseFloat(q, 64)
			if err != nil || !(weight > 0 && weight <= 1) {
				continue
			}
		}
		return true
	}
	return false
}

func (h *httpTransport) dispatch(ctx context.Context, msg *request, version, bearer string) *response {
	switch msg.Method {
	case "initialize":
		_, reply := initialize(msg, h.buildVersion, false)
		return reply
	case "ping":
		return result(msg.ID, struct{}{})
	case "tools/list":
		return result(msg.ID, listTools())
	case "tools/call":
		args, reply := parseToolCall(msg)
		if reply != nil {
			return reply
		}
		ctx, cancel := context.WithTimeout(ctx, httpCallTimeout)
		defer cancel()
		h.inflight.Add(1)
		defer h.inflight.Add(-1)
		executed := h.execute(ctx, bearer, args)
		if ctx.Err() != nil {
			return failure(msg.ID, -32000, "Octo CLI request timed out or was cancelled")
		}
		return execResponse(msg.ID, version, executed)
	default:
		return failure(msg.ID, -32601, "Method not found")
	}
}

func writeRPC(w http.ResponseWriter, status int, reply *response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(reply) //nolint:errcheck // the client may close its connection during a response
}
