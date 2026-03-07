package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDashboardUnauthRequestsUseUnauthRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}
	cfg.RateLimitEnabled = true
	cfg.UnauthRateLimitRequests = 1
	cfg.UnauthRateLimitWindow = 1 * time.Hour
	cfg.RateLimitRequests = 100
	cfg.RateLimitWindow = 1 * time.Hour
	cfg.AuthRateLimitRequests = 100
	cfg.AuthRateLimitWindow = 1 * time.Hour

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for first unauth dashboard request, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for second unauth dashboard request, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited response body, got %s", body)
	}
	if strings.TrimSpace(resp.Header.Get("Retry-After")) == "" {
		t.Fatalf("expected Retry-After header on unauth dashboard 429")
	}
}

func TestDashboardSessionRequestsUseGeneralRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleOperator
	cfg.RateLimitEnabled = true
	cfg.RateLimitRequests = 1
	cfg.RateLimitWindow = 1 * time.Hour
	cfg.AuthRateLimitRequests = 100
	cfg.AuthRateLimitWindow = 1 * time.Hour
	cfg.UnauthRateLimitRequests = 100
	cfg.UnauthRateLimitWindow = 1 * time.Hour

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
		t.Fatalf("expected 201 creating dashboard session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for first authenticated dashboard request, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for second authenticated dashboard request, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited response body, got %s", body)
	}
}

func TestAuthRateLimitScopeOverridesGeneralAndUnauthLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimitEnabled = true
	cfg.RateLimitRequests = 1
	cfg.RateLimitWindow = 1 * time.Hour
	cfg.UnauthRateLimitRequests = 1
	cfg.UnauthRateLimitWindow = 1 * time.Hour
	cfg.AuthRateLimitRequests = 2
	cfg.AuthRateLimitWindow = 1 * time.Hour
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]Role{
		"valid-token": RoleViewer,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	for i := 0; i < 2; i++ {
		resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/register", map[string]string{
			"enrollment_token": "invalid-token",
		}, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 before auth-scope cap (iteration %d), got %d body=%s", i+1, resp.StatusCode, body)
		}
	}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/register", map[string]string{
		"enrollment_token": "invalid-token",
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on third auth endpoint hit, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited response body, got %s", body)
	}
}
