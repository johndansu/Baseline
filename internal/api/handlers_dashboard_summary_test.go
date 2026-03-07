package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestDashboardCapabilitiesRequiresAuthentication(t *testing.T) {
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
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/capabilities", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated dashboard capabilities, got %d body=%s", resp.StatusCode, body)
	}
}

func TestDashboardCapabilitiesRoleMatrixForAPIKeys(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"viewer-key":   RoleViewer,
		"operator-key": RoleOperator,
		"admin-key":    RoleAdmin,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	testCases := []struct {
		name             string
		token            string
		role             Role
		projectWrite     bool
		scansRun         bool
		apiKeysWrite     bool
		integrationWrite bool
		integrationSecretsWrite bool
	}{
		{
			name:             "viewer",
			token:            "viewer-key",
			role:             RoleViewer,
			projectWrite:     false,
			scansRun:         false,
			apiKeysWrite:     true,
			integrationWrite: false,
			integrationSecretsWrite: false,
		},
		{
			name:             "operator",
			token:            "operator-key",
			role:             RoleOperator,
			projectWrite:     true,
			scansRun:         true,
			apiKeysWrite:     true,
			integrationWrite: true,
			integrationSecretsWrite: false,
		},
		{
			name:             "admin",
			token:            "admin-key",
			role:             RoleAdmin,
			projectWrite:     true,
			scansRun:         true,
			apiKeysWrite:     true,
			integrationWrite: true,
			integrationSecretsWrite: true,
		},
	}

	for _, tc := range testCases {
		resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/capabilities", nil, map[string]string{
			"Authorization": "Bearer " + tc.token,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: expected 200 for dashboard capabilities, got %d body=%s", tc.name, resp.StatusCode, body)
		}

		var payload struct {
			Role         Role            `json:"role"`
			Source       string          `json:"source"`
			Capabilities map[string]bool `json:"capabilities"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("%s: failed to decode dashboard capabilities payload: %v body=%s", tc.name, err, body)
		}
		if payload.Role != tc.role {
			t.Fatalf("%s: expected role %q, got %q", tc.name, tc.role, payload.Role)
		}
		if payload.Source != "api_key" {
			t.Fatalf("%s: expected source api_key, got %q", tc.name, payload.Source)
		}
		if payload.Capabilities["projects.write"] != tc.projectWrite {
			t.Fatalf("%s: projects.write mismatch, got %v", tc.name, payload.Capabilities["projects.write"])
		}
		if payload.Capabilities["scans.run"] != tc.scansRun {
			t.Fatalf("%s: scans.run mismatch, got %v", tc.name, payload.Capabilities["scans.run"])
		}
		if payload.Capabilities["api_keys.write"] != tc.apiKeysWrite {
			t.Fatalf("%s: api_keys.write mismatch, got %v", tc.name, payload.Capabilities["api_keys.write"])
		}
		if payload.Capabilities["integrations.write"] != tc.integrationWrite {
			t.Fatalf("%s: integrations.write mismatch, got %v", tc.name, payload.Capabilities["integrations.write"])
		}
		if payload.Capabilities["integrations.secrets.write"] != tc.integrationSecretsWrite {
			t.Fatalf("%s: integrations.secrets.write mismatch, got %v", tc.name, payload.Capabilities["integrations.secrets.write"])
		}
		if !payload.Capabilities["dashboard.view"] || !payload.Capabilities["projects.read"] || !payload.Capabilities["scans.read"] || !payload.Capabilities["audit.read"] {
			t.Fatalf("%s: expected baseline read capabilities to be true, got %+v", tc.name, payload.Capabilities)
		}
	}
}

func TestDashboardCapabilitiesSessionSource(t *testing.T) {
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

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Forwarded-User": "dashboard-op@example.com",
		"X-Forwarded-Role": "operator",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/capabilities", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading dashboard capabilities as session user, got %d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Role   Role   `json:"role"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode dashboard capabilities payload: %v body=%s", err, body)
	}
	if payload.Role != RoleOperator {
		t.Fatalf("expected role operator for session principal, got %q", payload.Role)
	}
	if payload.Source != "session" {
		t.Fatalf("expected source session for session principal, got %q", payload.Source)
	}
}

func TestDashboardActivityRequiresAuthentication(t *testing.T) {
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
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/activity", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated dashboard activity, got %d body=%s", resp.StatusCode, body)
	}
}

func TestDashboardActivitySupportsPaginationAndFilters(t *testing.T) {
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
		"id":   "proj_activity",
		"name": "activity-project",
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project, got %d body=%s", resp.StatusCode, body)
	}

	for i := 1; i <= 3; i++ {
		resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
			"id":         "scan_activity_" + strconv.Itoa(i),
			"project_id": "proj_activity",
			"commit_sha": "sha_activity_" + strconv.Itoa(i),
			"status":     "pass",
		}, headers)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 creating scan %d, got %d body=%s", i, resp.StatusCode, body)
		}
		time.Sleep(1 * time.Millisecond)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/activity?type=scan&limit=2", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading activity page 1, got %d body=%s", resp.StatusCode, body)
	}

	var firstPage DashboardActivityResponse
	if err := json.Unmarshal([]byte(body), &firstPage); err != nil {
		t.Fatalf("failed to decode activity page 1: %v body=%s", err, body)
	}
	if len(firstPage.Items) != 2 {
		t.Fatalf("expected 2 scan activity items on first page, got %d", len(firstPage.Items))
	}
	if strings.TrimSpace(firstPage.NextCursor) == "" {
		t.Fatalf("expected non-empty next_cursor for first page, body=%s", body)
	}
	for _, item := range firstPage.Items {
		if item.Type != "scan" {
			t.Fatalf("expected scan-only filter to return scan items, got %+v", item)
		}
	}

	resp, body = mustRequest(
		t,
		client,
		http.MethodGet,
		ts.URL+"/v1/dashboard/activity?type=scan&limit=2&cursor="+firstPage.NextCursor,
		nil,
		headers,
	)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading activity page 2, got %d body=%s", resp.StatusCode, body)
	}

	var secondPage DashboardActivityResponse
	if err := json.Unmarshal([]byte(body), &secondPage); err != nil {
		t.Fatalf("failed to decode activity page 2: %v body=%s", err, body)
	}
	if len(secondPage.Items) == 0 {
		t.Fatalf("expected at least one scan activity item on second page, body=%s", body)
	}
	if secondPage.Items[0].ID == firstPage.Items[0].ID || secondPage.Items[0].ID == firstPage.Items[1].ID {
		t.Fatalf("expected second page items to differ from first page items: page1=%+v page2=%+v", firstPage.Items, secondPage.Items)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/activity?cursor=bad_cursor", nil, headers)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad cursor, got %d body=%s", resp.StatusCode, body)
	}
}

func TestDashboardActivityIsOwnershipScopedForSessionUsers(t *testing.T) {
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
		"X-Forwarded-User": "activity-alice@example.com",
		"X-Forwarded-Role": "operator",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientB, http.MethodPost, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Forwarded-User": "activity-bob@example.com",
		"X-Forwarded-Role": "operator",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating session B, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientA, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_activity_owner",
		"name": "owned-activity-project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project as session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientA, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan_activity_owner",
		"project_id": "proj_activity_owner",
		"commit_sha": "abc123",
		"status":     "fail",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating scan as session A, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, clientB, http.MethodGet, ts.URL+"/v1/dashboard/activity?type=scan", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading activity for session B, got %d body=%s", resp.StatusCode, body)
	}
	var payload DashboardActivityResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode dashboard activity for session B: %v body=%s", err, body)
	}
	for _, item := range payload.Items {
		if item.ProjectID == "proj_activity_owner" || item.ScanID == "scan_activity_owner" {
			t.Fatalf("expected ownership-scoped activity response for session B, got %+v", item)
		}
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
