package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPConcurrentExec(t *testing.T) {
	const calls = 12
	started := make(chan struct{}, calls)
	release := make(chan struct{})
	url, _, _ := startTestHTTP(t, HTTPOptions{ShutdownTimeout: 2 * time.Second}, func(ctx context.Context, _ string, _ []string) ExecResult {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return ExecResult{Stdout: "fixture"}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results := make(chan testHTTPResult, calls)
	for range calls {
		go func() { results <- callTestHTTP(ctx, url) }()
	}
	for range calls {
		select {
		case <-started:
		case got := <-results:
			t.Fatalf("call completed before all %d execs could start: %+v", calls, got)
		case <-ctx.Done():
			t.Fatal("timed out waiting for concurrent execs")
		}
	}
	assertTestHTTPMetric(t, ctx, url, calls)
	close(release)
	for range calls {
		assertTestHTTPExec(t, <-results)
	}
	assertTestHTTPMetric(t, ctx, url, 0)
}

func TestHTTPReadinessAndMetric(t *testing.T) {
	url, _, _ := startTestHTTP(t, HTTPOptions{ShutdownTimeout: 2 * time.Second},
		func(context.Context, string, []string) ExecResult { return ExecResult{} })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	assertTestHTTPMetric(t, ctx, url, 0)
	if got := testHTTPRequest(ctx, http.MethodGet, url+"/readyz", ""); got.err != nil || got.status != http.StatusOK {
		t.Fatalf("readiness while serving = %+v, want HTTP 200", got)
	}
}

func TestHTTPGracefulShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	options := HTTPOptions{DrainDelay: 500 * time.Millisecond, ShutdownTimeout: 2 * time.Second}
	url, stop, done := startTestHTTP(t, options, func(ctx context.Context, _ string, _ []string) ExecResult {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			close(canceled)
		}
		return ExecResult{Stdout: "fixture"}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response := make(chan testHTTPResult, 1)
	go func() { response <- callTestHTTP(ctx, url) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("exec did not start")
	}
	stop()
	awaitTestHTTPReadiness(t, ctx, url, http.StatusServiceUnavailable)
	assertTestHTTPMetric(t, ctx, url, 1)
	// Wait for Shutdown to close the listener while the exec is still blocked.
	awaitTestHTTPReadiness(t, ctx, url, 0)
	select {
	case <-canceled:
		t.Fatal("shutdown canceled the in-flight exec before it could finish")
	case err := <-done:
		t.Fatalf("server returned before the in-flight exec could finish: %v", err)
	default:
	}
	close(release)
	assertTestHTTPExec(t, <-response)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("server did not exit after the exec completed")
	}
}

func TestHTTPShutdownDeadlineCancelsExec(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	options := HTTPOptions{ShutdownTimeout: 50 * time.Millisecond}
	url, stop, done := startTestHTTP(t, options, func(ctx context.Context, _ string, _ []string) ExecResult {
		close(started)
		<-ctx.Done()
		close(stopped)
		return ExecResult{}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response := make(chan testHTTPResult, 1)
	go func() { response <- callTestHTTP(ctx, url) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("exec did not start")
	}
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("server shutdown error = %v, want deadline exceeded", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not exit on its shutdown deadline")
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("exec context did not cancel on the shutdown deadline")
	}
	select {
	case <-response:
	case <-ctx.Done():
		t.Fatal("HTTP call did not finish after forced shutdown")
	}
}

func startTestHTTP(t *testing.T, options HTTPOptions, execute func(context.Context, string, []string) ExecResult) (url string, stopServer context.CancelFunc, servingDone <-chan error) {
	t.Helper()
	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- ServeHTTP(ctx, listener, "test", options, execute)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("test HTTP server did not exit")
		}
	})
	return "http://" + listener.Addr().String(), stop, done
}

func awaitTestHTTPReadiness(t *testing.T, ctx context.Context, url string, status int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		got := testHTTPRequest(ctx, http.MethodGet, url+"/readyz", "")
		if status == 0 && got.err != nil && ctx.Err() == nil || got.err == nil && got.status == status {
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatalf("readiness endpoint did not reach status %d", status)
}

type testHTTPResult struct {
	status int
	body   string
	err    error
}

func callTestHTTP(ctx context.Context, url string) testHTTPResult {
	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"args":["version"]}}}`
	return testHTTPRequest(ctx, http.MethodPost, url+"/mcp", call)
}

func testHTTPRequest(ctx context.Context, method, url, body string) testHTTPResult {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return testHTTPResult{err: err}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer fixture-token")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return testHTTPResult{err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return testHTTPResult{status: resp.StatusCode, body: string(raw), err: err}
}

func assertTestHTTPMetric(t *testing.T, ctx context.Context, url string, want int) {
	t.Helper()
	got := testHTTPRequest(ctx, http.MethodGet, url+"/metrics", "")
	wantLine := fmt.Sprintf("\nocto_mcp_exec_inflight %d\n", want)
	if got.err != nil || got.status != http.StatusOK || !strings.Contains(got.body, wantLine) {
		t.Fatalf("want metric %q, got %+v", strings.TrimSpace(wantLine), got)
	}
}

func assertTestHTTPExec(t *testing.T, got testHTTPResult) {
	t.Helper()
	if got.err != nil || got.status != http.StatusOK || !strings.Contains(got.body, "fixture") ||
		!strings.Contains(got.body, `"isError":false`) {
		t.Fatalf("want successful exec response, got %+v", got)
	}
}
