package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSummaryRequiresAuthentication(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated dashboard summary, got %d body=%s", resp.StatusCode, body)
	}
}

func TestDashboardSummaryReturnsAggregates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	headers := map[string]string{
		"Authorization": "Bearer admin-key",
	}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_dashboard",
		"name": "dashboard-project",
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan_dashboard_1",
		"project_id": "proj_dashboard",
		"commit_sha": "abc123",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "A1",
				"severity":  "block",
				"message":   "first blocking violation",
			},
			{
				"policy_id": "B1",
				"severity":  "warn",
				"message":   "warning violation",
			},
		},
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating first scan, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan_dashboard_2",
		"project_id": "proj_dashboard",
		"commit_sha": "def456",
		"status":     "pass",
		"violations": []map[string]any{
			{
				"policy_id": "A1",
				"severity":  "block",
				"message":   "second blocking violation",
			},
		},
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating second scan, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading dashboard summary, got %d body=%s", resp.StatusCode, body)
	}

	var summary struct {
		Metrics       DashboardMetrics          `json:"metrics"`
		RecentScans   []ScanSummary             `json:"recent_scans"`
		TopViolations []DashboardViolationCount `json:"top_violations"`
		RecentEvents  []AuditEvent              `json:"recent_events"`
	}
	if err := json.Unmarshal([]byte(body), &summary); err != nil {
		t.Fatalf("failed to decode dashboard summary: %v body=%s", err, body)
	}

	if summary.Metrics.Projects != 1 {
		t.Fatalf("expected projects=1, got %d", summary.Metrics.Projects)
	}
	if summary.Metrics.Scans != 2 {
		t.Fatalf("expected scans=2, got %d", summary.Metrics.Scans)
	}
	if summary.Metrics.FailingScans != 1 {
		t.Fatalf("expected failing_scans=1, got %d", summary.Metrics.FailingScans)
	}
	if summary.Metrics.BlockingViolations != 2 {
		t.Fatalf("expected blocking_violations=2, got %d", summary.Metrics.BlockingViolations)
	}
	if len(summary.RecentScans) != 2 {
		t.Fatalf("expected recent_scans length 2, got %d", len(summary.RecentScans))
	}
	if len(summary.TopViolations) == 0 {
		t.Fatal("expected top_violations to include at least one entry")
	}
	if summary.TopViolations[0].PolicyID != "A1" || summary.TopViolations[0].Count != 2 {
		t.Fatalf("expected top violation A1 count 2, got %+v", summary.TopViolations[0])
	}
	if len(summary.RecentEvents) == 0 {
		t.Fatal("expected recent_events to include at least one entry")
	}
}

func TestDashboardAndAuditAreOwnershipScopedForSessionUsers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardAuthProxyEnabled = true
	cfg.TrustProxyHeaders = true
	cfg.DashboardSessionRole = RoleOperator

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jarA, _ := cookiejar.New(nil)
	jarB, _ := cookiejar.New(nil)
	clientA := &http.Client{Jar: jarA}
	clientB := &http.Client{Jar: jarB}

	resp, body := mustRequest(t, clientA, http.MethodPost, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Forwarded-User": "dashboard-alice@example.com",
		"X-Forwarded-Role": "operator",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientB, http.MethodPost, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Forwarded-User": "dashboard-bob@example.com",
		"X-Forwarded-Role": "operator",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session B, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientA, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_dash_owner",
		"name": "owned-dashboard-project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project as session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientA, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan_dash_owner",
		"project_id": "proj_dash_owner",
		"commit_sha": "abc123",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "A1",
				"severity":  "block",
				"message":   "session-owned violation",
			},
		},
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating scan as session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientB, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading dashboard for session B, got %d body=%s", resp.StatusCode, body)
	}
	var summary struct {
		Metrics DashboardMetrics `json:"metrics"`
	}
	if err := json.Unmarshal([]byte(body), &summary); err != nil {
		t.Fatalf("failed to decode dashboard summary for session B: %v body=%s", err, body)
	}
	if summary.Metrics.Projects != 0 || summary.Metrics.Scans != 0 {
		t.Fatalf("expected ownership-scoped empty dashboard metrics for session B, got %+v", summary.Metrics)
	}

	resp, body = mustRequest(t, clientB, http.MethodGet, ts.URL+"/v1/audit/events", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading audit events for session B, got %d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "proj_dash_owner") {
		t.Fatalf("expected ownership-scoped audit response for session B, body=%s", body)
	}
}
