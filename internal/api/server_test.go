package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSessionLifecycleAndProjectFlow(t *testing.T) {
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

	// Session should be missing before sign-in.
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before session creation, got %d body=%s", resp.StatusCode, body)
	}

	// Create session.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for session create, got %d body=%s", resp.StatusCode, body)
	}

	// Create project with operator session.
	projectPayload := map[string]string{
		"name":           "checkout-service",
		"default_branch": "main",
		"policy_set":     "baseline:prod",
	}
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", projectPayload, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for project create, got %d body=%s", resp.StatusCode, body)
	}

	// Read projects list.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for projects list, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "checkout-service") {
		t.Fatalf("expected created project in list, body=%s", body)
	}

	// Dashboard summary should include metrics for created project.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for dashboard summary, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "\"projects\":1") {
		t.Fatalf("expected dashboard metrics projects=1, body=%s", body)
	}

	// End session and confirm protected endpoint is denied.
	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for session delete, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after session deletion, got %d body=%s", resp.StatusCode, body)
	}
}

func TestAPIKeyRolesAreEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"viewer-key":   RoleViewer,
		"operator-key": RoleOperator,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	// Viewer can read projects.
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for viewer read, got %d body=%s", resp.StatusCode, body)
	}

	// Viewer cannot create projects.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"name": "viewer-create-attempt",
	}, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer create, got %d body=%s", resp.StatusCode, body)
	}

	// Operator can create projects.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"name": "operator-project",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for operator create, got %d body=%s", resp.StatusCode, body)
	}
}

func TestScanIngestionAndReports(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
		"viewer-key":   RoleViewer,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	// Create project as operator.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"id":   "proj_123",
		"name": "payments",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 project create, got %d body=%s", resp.StatusCode, body)
	}

	// Upload scan payload.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_123",
		"commit_sha": "abc123def",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "G1",
				"severity":  "block",
				"message":   "Plaintext secret detected",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 scan upload, got %d body=%s", resp.StatusCode, body)
	}

	var createdScan ScanSummary
	if err := json.Unmarshal([]byte(body), &createdScan); err != nil {
		t.Fatalf("failed to unmarshal scan response: %v", err)
	}
	if createdScan.ID == "" {
		t.Fatal("expected created scan id")
	}

	// Query scans by project_id.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans?project_id=proj_123", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 scans list, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "abc123def") {
		t.Fatalf("expected scan commit in list body=%s", body)
	}

	// JSON report.
	reportURL := ts.URL + "/v1/scans/" + createdScan.ID + "/report?format=json"
	resp, body = mustRequest(t, client, http.MethodGet, reportURL, nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\"scan\"") {
		t.Fatalf("expected JSON scan report, got %d body=%s", resp.StatusCode, body)
	}

	// Text report.
	reportURL = ts.URL + "/v1/scans/" + createdScan.ID + "/report?format=text"
	resp, body = mustRequest(t, client, http.MethodGet, reportURL, nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "scan_id:") {
		t.Fatalf("expected text scan report, got %d body=%s", resp.StatusCode, body)
	}

	// SARIF report.
	reportURL = ts.URL + "/v1/scans/" + createdScan.ID + "/report?format=sarif"
	resp, body = mustRequest(t, client, http.MethodGet, reportURL, nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\"version\":\"2.1.0\"") {
		t.Fatalf("expected SARIF scan report, got %d body=%s", resp.StatusCode, body)
	}

	// Audit events endpoint.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events?project_id=proj_123", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 audit events, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "scan_uploaded") {
		t.Fatalf("expected scan_uploaded event, body=%s", body)
	}
}

func TestPolicyAndRulesetEndpoints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key":  RoleAdmin,
		"viewer-key": RoleViewer,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}

	// Viewer cannot publish policy versions.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/baseline-prod/versions", map[string]any{
		"version": "v1",
		"content": map[string]any{"rule": "no-secrets"},
	}, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 viewer policy publish, got %d body=%s", resp.StatusCode, body)
	}

	// Admin publishes policy version.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/baseline-prod/versions", map[string]any{
		"version":     "v1",
		"description": "initial policy",
		"content":     map[string]any{"rule": "no-secrets"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 admin policy publish, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/policies", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "baseline-prod") {
		t.Fatalf("expected policies list with baseline-prod, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/policies/baseline-prod/latest", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\"version\":\"v1\"") {
		t.Fatalf("expected policy latest v1, got %d body=%s", resp.StatusCode, body)
	}

	// Admin publishes ruleset.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/rulesets", map[string]any{
		"version":      "2026.02.17",
		"description":  "baseline production ruleset",
		"policy_names": []string{"baseline-prod"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 ruleset publish, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/rulesets/latest", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "2026.02.17") {
		t.Fatalf("expected latest ruleset 2026.02.17, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/rulesets/2026.02.17", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\"baseline-prod\"") {
		t.Fatalf("expected ruleset by version, got %d body=%s", resp.StatusCode, body)
	}
}

func mustRequest(t *testing.T, client *http.Client, method, url string, payload any, headers map[string]string) (*http.Response, string) {
	t.Helper()

	var bodyReader *bytes.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal payload: %v", err)
		}
		bodyReader = bytes.NewReader(raw)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp, out.String()
}
