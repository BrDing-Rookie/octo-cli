package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func TestRedactBearer_EncodedURL(t *testing.T) {
	for _, tc := range []struct {
		name, bearer, target, want string
	}{
		{"lowercase path", "abc/1234", "/prefixabc%2f1234suffix", "/prefix***REDACTED***suffix"},
		{"uppercase path", "abc/1234", "/prefixabc%2F1234suffix", "/prefix***REDACTED***suffix"},
		{"lowercase query", "abc/1234", "/check?note=prefixabc%2f1234suffix", "/check?note=prefix***REDACTED***suffix"},
		{"escaped path letters", "abc/1234", "/prefix%61bc%2f1234suffix%21", "/prefix***REDACTED***suffix%21"},
		{"escaped query letters", "abc/1234", "/check?note=prefix%61bc%2f1234suffix", "/check?note=prefix***REDACTED***suffix"},
		{"mixed escapes", "abc/?1234", "/prefixabc%2f%3F1234suffix", "/prefix***REDACTED***suffix"},
		{"literal token case", "abc/1234", "/prefixAbc%2f1234suffix", "/prefixAbc%2f1234suffix"},
		{"escaped token case", "abc/1234", "/prefix%41bc%2f1234suffix", "/prefix%41bc%2f1234suffix"},
		{"escaped literal percent", "abc%2f1234", "/prefixabc%252f1234suffix", "/prefix***REDACTED***suffix"},
		{"encoded literal percent", "abc%2f1234", "/prefixabc%252F1234suffix", "/prefixabc%252F1234suffix"},
		{"short encoded token", "abc", "/prefix%61bcsuffix", "/prefix***REDACTED***suffix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactBearer(tc.target, tc.bearer); got != tc.want {
				t.Errorf("RedactBearer() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBusinessDryRun_ShortEncodedQueryBearer(t *testing.T) {
	const value = "prefix%61bcsuffix"
	cli := NewBusiness(&credential.BusinessContext{
		Token: "abc", APIBaseURL: "https://example.invalid",
	}, Options{DryRun: true})
	req := &Request{
		Method: http.MethodGet,
		Path:   "/check",
		Query:  url.Values{"note": {value}},
		Body: map[string]any{
			"note":              value,
			"first%61bcsuffix":  "first",
			"second%61bcsuffix": "second",
		},
	}
	body, err := cli.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var description struct {
		URL  string
		Body map[string]string
	}
	if err := json.Unmarshal(body, &description); err != nil {
		t.Fatal(err)
	}
	const want = "https://example.invalid/check?note=prefix***REDACTED***suffix"
	if description.URL != want {
		t.Errorf("URL = %q, want %q", description.URL, want)
	}
	if len(description.Body) != 3 || description.Body["note"] != "prefix***REDACTED***suffix" ||
		description.Body["first***REDACTED***suffix"] != "first" || description.Body["second***REDACTED***suffix"] != "second" {
		t.Errorf("body diagnostics lost non-secret context or collapsed keys: %#v", description.Body)
	}
	if req.Query.Get("note") != value || len(req.SecretValues) != 0 {
		t.Fatal("diagnostics modified the caller's request")
	}
}

func TestBusinessError_PreservesKnownCodeAndMasksBearer(t *testing.T) {
	for _, tc := range []struct {
		name, bearer, code, wantCode, wantType string
		wantExit                               int
		responseSecretFields                   []string
	}{
		{"known uppercase code", "AUTH", "UNAUTHORIZED", "UNAUTHORIZED", "auth_error", 3, nil},
		{"unknown code with bearer", "AUTH", "UNAUTHENTICATED", secretMask, "api_error", 1, nil},
		{"unknown code with encoded bearer", "abc/1234", "invalid_prefix%61bc%2f1234suffix", "invalid_prefix" + secretMask + "suffix", "api_error", 1, nil},
		{"encoded bearer with response secrets", "abc/1234", "invalid_prefix%61bc%2f1234suffix", "invalid_prefix" + secretMask + "suffix", "api_error", 1, []string{"download_url"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli := NewBusiness(&credential.BusinessContext{
				Token: tc.bearer, APIBaseURL: "https://example.invalid",
			}, Options{NoRetry: true})
			cli.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Bearer "+tc.bearer {
					t.Error("redaction changed the outbound bearer")
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"error":{"code":"` + tc.code +
						`","message":"expired ` + tc.bearer + `","details":{"token":"` + tc.bearer + `","context":"keep"}}}`)),
				}, nil
			})
			_, err := cli.Do(context.Background(), &Request{
				Method: http.MethodGet, Path: "/check", ResponseSecretFields: tc.responseSecretFields,
			})
			ee := output.AsExitError(err)
			if ee == nil {
				t.Fatalf("expected a structured error, got %v", err)
			}
			if ee.Code != tc.wantCode || ee.Type != tc.wantType || ee.ExitCode() != tc.wantExit {
				t.Errorf("classification = %s/%s/exit %d, want %s/%s/exit %d",
					ee.Code, ee.Type, ee.ExitCode(), tc.wantCode, tc.wantType, tc.wantExit)
			}
			var detail struct {
				Error struct {
					Code, Message string
					Details       struct{ Token, Context string }
				}
			}
			if err := json.Unmarshal(ee.Detail, &detail); err != nil {
				t.Fatal(err)
			}
			if ee.Message != "expired "+secretMask || strings.Contains(ee.Hint, tc.bearer) ||
				detail.Error.Code != tc.wantCode || detail.Error.Message != ee.Message ||
				detail.Error.Details.Token != secretMask || detail.Error.Details.Context != "keep" {
				t.Errorf("unexpected redacted diagnostics: %+v, detail %s", ee, ee.Detail)
			}
		})
	}
}
