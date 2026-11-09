package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	authCurrentFixturePath            = "/v1/auth/tokens/_current"
	authCurrentFixtureCandidateToken  = "fixture-candidate+/=token"
	authCurrentFixtureStoredToken     = "fixture-stored+/=token"
	authCurrentFixtureMaxVersion      = "18446744073709551615"
	authCurrentFixtureVersionOverflow = "18446744073709551616"
)

type authCurrentFixtureReply struct {
	status              int
	body                string
	waitForCancellation bool
	beforeReply         func()
}

type authCurrentFixtureRequest struct {
	method        string
	target        string
	authorization string
	space         string
}

func newAuthCurrentFixture(t *testing.T, replies map[string]authCurrentFixtureReply) (server *httptest.Server, recorded func() []authCurrentFixtureRequest) {
	t.Helper()

	var mu sync.Mutex
	var requests []authCurrentFixtureRequest
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := authCurrentFixtureRequest{
			method:        r.Method,
			target:        r.URL.RequestURI(),
			authorization: r.Header.Get("Authorization"),
			space:         r.Header.Get("X-Space-Id"),
		}
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()

		if req.method != http.MethodGet || req.target != authCurrentFixturePath {
			http.NotFound(w, r)
			return
		}
		token, hasBearer := strings.CutPrefix(req.authorization, "Bearer ")
		reply, found := replies[token]
		if !hasBearer || !found {
			reply = authCurrentFixtureError(http.StatusUnauthorized, "AUTH_REQUIRED", "invalid", "")
		}
		if reply.beforeReply != nil {
			reply.beforeReply()
		}
		if reply.waitForCancellation {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.status)
		_, _ = io.WriteString(w, reply.body)
	}))
	t.Cleanup(server.Close)

	return server, func() []authCurrentFixtureRequest {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(requests)
	}
}

func authCurrentFixtureSuccess(tokenID, owner, space string) authCurrentFixtureReply {
	return authCurrentFixtureReply{
		status: http.StatusOK,
		body: fmt.Sprintf(`{"data":{
			"token":{"token_id":%q,"owner_id":%q,"space_id":%q,"name":"fixture","remark":null,
				"status":"active","expires_at":null,"is_expired":false,"version":1,
				"created_at":"2026-11-04T06:00:00Z","updated_at":"2026-11-04T06:00:00Z","last_used_at":null},
			"permissions":[{"domain":"task","actions":["task:read"]}],
			"bot_bindings":[{"bot_id":"fixture-bot","bot_name":"Fixture Bot"}]
		}}`, tokenID, owner, space),
	}
}

func (r authCurrentFixtureReply) withActions(actions string) authCurrentFixtureReply {
	r.body = strings.Replace(r.body, `["task:read"]`, actions, 1)
	return r
}

func (r authCurrentFixtureReply) withVersion(version string) authCurrentFixtureReply {
	r.body = strings.Replace(r.body, `"version":1,`, `"version":`+version+`,`, 1)
	return r
}

func authCurrentFixtureError(status int, code, reason, echo string) authCurrentFixtureReply {
	return authCurrentFixtureReply{
		status: status,
		body: fmt.Sprintf(`{"error":{"code":%q,"message":%q,"details":{"reason":%q,"echo":%q}}}`,
			code, "credential rejected "+echo, reason, url.QueryEscape(echo)),
	}
}

func TestAuthCurrentFixtureIdentities(t *testing.T) {
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		authCurrentFixtureCandidateToken: authCurrentFixtureSuccess("candidate-id", "owner", "space"),
		authCurrentFixtureStoredToken:    authCurrentFixtureSuccess("stored-id", "owner", "space"),
	})
	var wantRequests []authCurrentFixtureRequest
	for _, tc := range []struct {
		token string
		id    string
	}{
		{authCurrentFixtureCandidateToken, "candidate-id"},
		{authCurrentFixtureStoredToken, "stored-id"},
	} {
		status, body, err := requestAuthCurrentFixture(server.Client(), server.URL, tc.token)
		if err != nil || status != http.StatusOK {
			t.Fatalf("GET _current: status=%d, err=%v", status, err)
		}
		var envelope struct {
			Data struct {
				Token struct {
					ID string `json:"token_id"`
				}
				Permissions []json.RawMessage
				BotBindings []json.RawMessage `json:"bot_bindings"`
			}
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatal(err)
		}
		data := envelope.Data
		if data.Token.ID != tc.id || len(data.Permissions) != 1 || len(data.BotBindings) != 1 {
			t.Fatalf("unexpected TokenSelf for %s: %s", tc.id, body)
		}
		wantRequests = append(wantRequests, authCurrentFixtureRequest{
			method: http.MethodGet, target: authCurrentFixturePath, authorization: "Bearer " + tc.token, space: "space",
		})
	}
	if got := requests(); !slices.Equal(got, wantRequests) {
		t.Fatalf("requests = %+v, want %+v", got, wantRequests)
	}
}

func TestAuthCurrentFixtureFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply authCurrentFixtureReply
	}{
		{"unauthorized", authCurrentFixtureError(http.StatusUnauthorized, "AUTH_REQUIRED", "revoked", authCurrentFixtureCandidateToken)},
		{"forbidden", authCurrentFixtureError(http.StatusForbidden, "FORBIDDEN", "access_denied", authCurrentFixtureCandidateToken)},
		{"malformed", authCurrentFixtureReply{status: http.StatusOK, body: `{"data":`}},
		{"timeout", authCurrentFixtureReply{waitForCancellation: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{authCurrentFixtureCandidateToken: tc.reply})
			httpClient := server.Client()
			httpClient.Timeout = time.Second
			status, body, err := requestAuthCurrentFixture(httpClient, server.URL, authCurrentFixtureCandidateToken)
			if tc.reply.waitForCancellation {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("expected timeout, got %v", err)
				}
				return
			}
			if err != nil || status != tc.reply.status || body != tc.reply.body {
				t.Fatalf("GET _current: status=%d, body=%q, err=%v", status, body, err)
			}
		})
	}
}

func requestAuthCurrentFixture(client *http.Client, origin, token string) (status int, body string, err error) {
	req, err := http.NewRequest(http.MethodGet, origin+authCurrentFixturePath, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Space-Id", "space")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), err
}
