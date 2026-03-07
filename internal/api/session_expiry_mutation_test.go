package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExpiredSessionBlocksMutationsUntilSessionRecreated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleOperator

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session, got %d body=%s", resp.StatusCode, body)
	}

	// Force-expire all active in-memory sessions to simulate session TTL expiry.
	server.sessionMu.Lock()
	for token, session := range server.sessions {
		session.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
		server.sessions[token] = session
	}
	server.sessionMu.Unlock()

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"name": "expired-session-project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for mutation with expired session, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "missing or invalid credentials") {
		t.Fatalf("expected unauthorized credentials message, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session lookup, got %d body=%s", resp.StatusCode, body)
	}

	server.sessionMu.RLock()
	activeSessions := len(server.sessions)
	server.sessionMu.RUnlock()
	if activeSessions != 0 {
		t.Fatalf("expected expired session to be removed from active map, got %d active sessions", activeSessions)
	}

	// Session can be recreated and mutations resume with CSRF.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 recreating session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"name": "fresh-session-project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 mutation with fresh session, got %d body=%s", resp.StatusCode, body)
	}
}

func TestExpiredSensitiveReauthTokenRequiresRefreshForSessionMutation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin
	cfg.SensitiveActionReauthEnabled = true

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating admin session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/api-keys", map[string]any{
		"name": "session-reauth-expiry-target",
		"role": "viewer",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating target key, got %d body=%s", resp.StatusCode, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode created api key response: %v body=%s", err, body)
	}
	if strings.TrimSpace(created.ID) == "" {
		t.Fatalf("expected created key id, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/reauth", nil, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 creating reauth token, got %d body=%s", resp.StatusCode, body)
	}
	var firstReauth struct {
		Token string `json:"reauth_token"`
	}
	if err := json.Unmarshal([]byte(body), &firstReauth); err != nil {
		t.Fatalf("failed to decode first reauth response: %v body=%s", err, body)
	}
	if strings.TrimSpace(firstReauth.Token) == "" {
		t.Fatalf("expected first reauth token, body=%s", body)
	}

	// Force-expire first reauth token to validate refresh path.
	server.sensitiveMu.Lock()
	grant, exists := server.sensitiveReauth[firstReauth.Token]
	if exists {
		grant.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
		server.sensitiveReauth[firstReauth.Token] = grant
	}
	server.sensitiveMu.Unlock()

	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/api-keys/"+created.ID, nil, map[string]string{
		"X-Baseline-CSRF":    "1",
		"X-Baseline-Confirm": "revoke_api_key",
		"X-Baseline-Reason":  "session-reauth-expired",
		"X-Baseline-Reauth":  firstReauth.Token,
	})
	if resp.StatusCode != http.StatusPreconditionRequired || !strings.Contains(body, "reauth_required") {
		t.Fatalf("expected 428 reauth_required for expired session reauth token, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/reauth", nil, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 refreshing reauth token, got %d body=%s", resp.StatusCode, body)
	}
	var refreshed struct {
		Token string `json:"reauth_token"`
	}
	if err := json.Unmarshal([]byte(body), &refreshed); err != nil {
		t.Fatalf("failed to decode refreshed reauth response: %v body=%s", err, body)
	}
	if strings.TrimSpace(refreshed.Token) == "" {
		t.Fatalf("expected refreshed reauth token, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/api-keys/"+created.ID, nil, map[string]string{
		"X-Baseline-CSRF":    "1",
		"X-Baseline-Confirm": "revoke_api_key",
		"X-Baseline-Reason":  "session-reauth-refresh",
		"X-Baseline-Reauth":  refreshed.Token,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with refreshed reauth token, got %d body=%s", resp.StatusCode, body)
	}
}
