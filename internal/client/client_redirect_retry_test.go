package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestDo_MalformedRedirectDoesNotRetryPost(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/write" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Location", "/write/%zz")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	cli := newTestClient(server)
	_, err := cli.Do(context.Background(), &Request{
		Method: http.MethodPost,
		Path:   "/write",
		Body:   map[string]string{"operation": "example"},
	})
	exit := output.AsExitError(err)
	if exit == nil || exit.Type != "network" || exit.Code != "NETWORK_ERROR" || exit.ExitCode() != 1 {
		t.Fatalf("expected network error and exit code 1, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("POST requests = %d, want 1 after malformed Location", got)
	}
}

func TestDo_RetriesTransientDisconnect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			if err := conn.Close(); err != nil {
				t.Errorf("close connection: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cli := newTestClient(server)
	if _, err := cli.Do(context.Background(), &Request{Method: http.MethodGet, Path: "/retry"}); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 after transient disconnect", got)
	}
}
