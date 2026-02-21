package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	baselinelog "github.com/baseline/baseline/internal/log"
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
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", projectPayload, map[string]string{
		"X-Baseline-CSRF": "1",
	})
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
	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Baseline-CSRF": "1",
	})
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

func TestRequestIDHeaderPropagationAndGeneration(t *testing.T) {
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

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer admin-key",
		requestIDHeader: "client-request-123",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for projects list, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.TrimSpace(resp.Header.Get(requestIDHeader)); got != "client-request-123" {
		t.Fatalf("expected echoed request id, got %q", got)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer admin-key",
		requestIDHeader: "invalid request id",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for projects list with invalid request id header, got %d body=%s", resp.StatusCode, body)
	}
	generated := strings.TrimSpace(resp.Header.Get(requestIDHeader))
	if generated == "" {
		t.Fatal("expected generated request id in response")
	}
	if generated == "invalid request id" {
		t.Fatalf("expected sanitized/generated request id, got %q", generated)
	}
}

func TestRequestLoggingIncludesStructuredFields(t *testing.T) {
	var output bytes.Buffer
	originalLogger := baselinelog.Logger
	baselinelog.Logger = slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	defer func() {
		baselinelog.Logger = originalLogger
	}()

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

	reqID := "req-log-001"
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer admin-key",
		requestIDHeader: reqID,
		"User-Agent":    "baseline-test-client",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for projects list, got %d body=%s", resp.StatusCode, body)
	}

	logged := output.String()
	expectedFields := []string{
		"msg=api_request",
		"request_id=" + reqID,
		"method=GET",
		"path=/v1/projects",
		"status=200",
	}
	for _, field := range expectedFields {
		if !strings.Contains(logged, field) {
			t.Fatalf("expected request log to contain %q, got logs:\n%s", field, logged)
		}
	}
}

func TestMutatingEndpointsRBACMatrix(t *testing.T) {
	githubUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer githubUpstream.Close()

	gitlabUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer gitlabUpstream.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
		"operator-key": RoleOperator,
		"viewer-key":   RoleViewer,
	}
	cfg.GitHubAPIToken = "gh-token"
	cfg.GitHubAPIBaseURL = githubUpstream.URL
	cfg.GitLabAPIToken = "gl-token"
	cfg.GitLabAPIBaseURL = gitlabUpstream.URL

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_rbac",
		"name": "rbac-seed-project",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding project, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/rbac-policy/versions", map[string]any{
		"version": "v-seed",
		"content": map[string]any{"rule": "seed"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding policy, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/api-keys", map[string]any{
		"name": "rbac-revoke-target",
		"role": "viewer",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding key for revoke test, got %d body=%s", resp.StatusCode, body)
	}
	var seededKey struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &seededKey); err != nil {
		t.Fatalf("failed to decode seeded key response: %v body=%s", err, body)
	}
	if strings.TrimSpace(seededKey.ID) == "" {
		t.Fatalf("expected seeded key id, body=%s", body)
	}

	type rbacCase struct {
		name           string
		method         string
		path           string
		payload        any
		viewerStatus   int
		operatorStatus int
		adminStatus    int
	}

	cases := []rbacCase{
		{
			name:           "projects_create",
			method:         http.MethodPost,
			path:           "/v1/projects",
			payload:        map[string]any{"name": "rbac-project"},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusCreated,
			adminStatus:    http.StatusCreated,
		},
		{
			name:   "scans_create",
			method: http.MethodPost,
			path:   "/v1/scans",
			payload: map[string]any{
				"project_id": "proj_rbac",
				"commit_sha": "rbac123",
				"status":     "pass",
			},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusCreated,
			adminStatus:    http.StatusCreated,
		},
		{
			name:   "policy_publish",
			method: http.MethodPost,
			path:   "/v1/policies/rbac-policy/versions",
			payload: map[string]any{
				"version": "v-rbac-2",
				"content": map[string]any{"rule": "rbac"},
			},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusCreated,
		},
		{
			name:   "ruleset_publish",
			method: http.MethodPost,
			path:   "/v1/rulesets",
			payload: map[string]any{
				"version":      "rbac-2026.02.21",
				"description":  "rbac matrix ruleset",
				"policy_names": []string{"rbac-policy"},
			},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusCreated,
		},
		{
			name:   "api_key_issue",
			method: http.MethodPost,
			path:   "/v1/api-keys",
			payload: map[string]any{
				"name": "rbac-issued",
				"role": "viewer",
			},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusCreated,
		},
		{
			name:           "github_check_run_publish",
			method:         http.MethodPost,
			path:           "/v1/integrations/github/check-runs",
			payload:        map[string]any{"owner": "acme", "repository": "rbac", "head_sha": "abc123", "name": "baseline/rbac"},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusAccepted,
			adminStatus:    http.StatusAccepted,
		},
		{
			name:   "gitlab_status_publish",
			method: http.MethodPost,
			path:   "/v1/integrations/gitlab/statuses",
			payload: map[string]any{
				"project_id": "acme/rbac",
				"sha":        "def456",
				"state":      "success",
				"name":       "baseline/rbac",
			},
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusAccepted,
			adminStatus:    http.StatusAccepted,
		},
		{
			name:           "api_key_revoke",
			method:         http.MethodDelete,
			path:           "/v1/api-keys/" + seededKey.ID,
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusOK,
		},
	}

	roles := []struct {
		name   string
		token  string
		expect func(rbacCase) int
	}{
		{
			name:  "viewer",
			token: "viewer-key",
			expect: func(tc rbacCase) int {
				return tc.viewerStatus
			},
		},
		{
			name:  "operator",
			token: "operator-key",
			expect: func(tc rbacCase) int {
				return tc.operatorStatus
			},
		},
		{
			name:  "admin",
			token: "admin-key",
			expect: func(tc rbacCase) int {
				return tc.adminStatus
			},
		},
	}

	for _, tc := range cases {
		for _, role := range roles {
			resp, body := mustRequest(t, client, tc.method, ts.URL+tc.path, tc.payload, map[string]string{
				"Authorization": "Bearer " + role.token,
			})
			expected := role.expect(tc)
			if resp.StatusCode != expected {
				t.Fatalf("%s role=%s expected status %d, got %d body=%s", tc.name, role.name, expected, resp.StatusCode, body)
			}
		}
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

func TestScanIngestionSupportsIdempotencyReplay(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"id":   "proj_idem",
		"name": "idempotency-project",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 project create, got %d body=%s", resp.StatusCode, body)
	}

	headers := map[string]string{
		"Authorization":   "Bearer operator-key",
		"Idempotency-Key": "scan-idem-001",
	}
	payload := map[string]any{
		"project_id": "proj_idem",
		"commit_sha": "abc123def",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "G1",
				"severity":  "block",
				"message":   "hardcoded secret",
			},
		},
	}
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", payload, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on first idempotent scan create, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.TrimSpace(resp.Header.Get("X-Idempotency-Replayed")); got != "" {
		t.Fatalf("did not expect replay header on first request, got %q", got)
	}
	var first ScanSummary
	if err := json.Unmarshal([]byte(body), &first); err != nil {
		t.Fatalf("failed to decode first scan response: %v", err)
	}
	if strings.TrimSpace(first.ID) == "" {
		t.Fatalf("expected first scan id to be populated")
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", payload, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on replayed scan create, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.TrimSpace(resp.Header.Get("X-Idempotency-Replayed")); got != "true" {
		t.Fatalf("expected replay header on idempotent replay, got %q", got)
	}
	var replayed ScanSummary
	if err := json.Unmarshal([]byte(body), &replayed); err != nil {
		t.Fatalf("failed to decode replayed scan response: %v", err)
	}
	if replayed.ID != first.ID {
		t.Fatalf("expected replayed scan id %q to match first scan id %q", replayed.ID, first.ID)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans?project_id=proj_idem", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 scans list, got %d body=%s", resp.StatusCode, body)
	}
	var listed struct {
		Scans []ScanSummary `json:"scans"`
	}
	if err := json.Unmarshal([]byte(body), &listed); err != nil {
		t.Fatalf("failed to decode scans list: %v", err)
	}
	if len(listed.Scans) != 1 {
		t.Fatalf("expected exactly one scan after idempotent replay, got %d", len(listed.Scans))
	}
}

func TestScanIngestionIdempotencyConflictOnDifferentPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"id":   "proj_conflict",
		"name": "conflict-project",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 project create, got %d body=%s", resp.StatusCode, body)
	}

	headers := map[string]string{
		"Authorization":   "Bearer operator-key",
		"Idempotency-Key": "scan-idem-conflict",
	}
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_conflict",
		"commit_sha": "abc123def",
		"status":     "pass",
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 first scan, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_conflict",
		"commit_sha": "zzz999999",
		"status":     "fail",
	}, headers)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 idempotency conflict, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "idempotency_conflict") {
		t.Fatalf("expected idempotency_conflict error code, body=%s", body)
	}
}

func TestScanIngestionRejectsMalformedPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"id":   "proj_malformed",
		"name": "malformed-project",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 project create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_malformed",
		"status":     "warn",
		"violations": []map[string]any{
			{
				"policy_id": "",
				"severity":  "block",
				"message":   "missing policy id",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed scan payload, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "invalid_scan_payload") {
		t.Fatalf("expected invalid_scan_payload error code, body=%s", body)
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

	// Audit stream should include policy and ruleset update references.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit events list, got %d body=%s", resp.StatusCode, body)
	}
	var policyAudit struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(body), &policyAudit); err != nil {
		t.Fatalf("failed to decode policy/ruleset audit events: %v body=%s", err, body)
	}
	policyUpdatedFound := false
	rulesetUpdatedFound := false
	for _, event := range policyAudit.Events {
		if event.EventType == "policy_updated" && event.ScanID == "baseline-prod@v1" {
			policyUpdatedFound = true
		}
		if event.EventType == "ruleset_updated" && event.ScanID == "2026.02.17" {
			rulesetUpdatedFound = true
		}
	}
	if !policyUpdatedFound || !rulesetUpdatedFound {
		t.Fatalf("expected policy/ruleset audit references, policy=%v ruleset=%v events=%v", policyUpdatedFound, rulesetUpdatedFound, policyAudit.Events)
	}

	// Duplicate policy version should be rejected deterministically.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/baseline-prod/versions", map[string]any{
		"version": "v1",
		"content": map[string]any{"rule": "no-secrets"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "\"code\":\"conflict\"") {
		t.Fatalf("expected 409 conflict for duplicate policy version, got %d body=%s", resp.StatusCode, body)
	}

	// Invalid policy payload should be rejected with stable code.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/baseline-prod/versions", map[string]any{
		"version": "v2",
		"content": map[string]any{},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_policy_payload") {
		t.Fatalf("expected 400 invalid_policy_payload, got %d body=%s", resp.StatusCode, body)
	}

	// Invalid policy name token should be rejected.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/policies/bad*name/latest", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_policy_name") {
		t.Fatalf("expected 400 invalid_policy_name, got %d body=%s", resp.StatusCode, body)
	}

	// Ruleset referencing unknown policy should be rejected.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/rulesets", map[string]any{
		"version":      "2026.02.18",
		"description":  "invalid policy ref",
		"policy_names": []string{"unknown-policy"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_ruleset_payload") {
		t.Fatalf("expected 400 invalid_ruleset_payload for unknown policy, got %d body=%s", resp.StatusCode, body)
	}

	// Duplicate ruleset version should be rejected.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/rulesets", map[string]any{
		"version":      "2026.02.17",
		"description":  "duplicate version",
		"policy_names": []string{"baseline-prod"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "\"code\":\"conflict\"") {
		t.Fatalf("expected 409 conflict for duplicate ruleset version, got %d body=%s", resp.StatusCode, body)
	}

	// Invalid ruleset version token should be rejected.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/rulesets/invalid*version", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_ruleset_version") {
		t.Fatalf("expected 400 invalid_ruleset_version, got %d body=%s", resp.StatusCode, body)
	}
}

func TestUnauthorizedResponseIncludesBearerChallenge(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"viewer-key": RoleViewer,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, _ := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Fatalf("expected Bearer challenge header, got %q", got)
	}
}

func TestUnauthenticatedRequestsAreRateLimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.RateLimitEnabled = true
	cfg.UnauthRateLimitRequests = 2
	cfg.UnauthRateLimitWindow = 1 * time.Hour

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	for i := 0; i < 2; i++ {
		resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 before unauth rate cap, got %d body=%s", resp.StatusCode, body)
		}
	}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after unauth rate cap, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited error code, body=%s", body)
	}
	if strings.TrimSpace(resp.Header.Get("Retry-After")) == "" {
		t.Fatalf("expected Retry-After header on 429 response")
	}
}

func TestAuthEndpointsUseDedicatedRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]Role{
		"valid-token": RoleViewer,
	}
	cfg.RateLimitEnabled = true
	cfg.AuthRateLimitRequests = 1
	cfg.AuthRateLimitWindow = 1 * time.Hour

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/register", map[string]string{
		"enrollment_token": "bad-token",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid enrollment token, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/register", map[string]string{
		"enrollment_token": "bad-token",
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second auth endpoint hit, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited error code, body=%s", body)
	}
}

func TestAuthenticatedRequestsAreRateLimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.RateLimitEnabled = true
	cfg.RateLimitRequests = 1
	cfg.RateLimitWindow = 1 * time.Hour

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for first authenticated request, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for second authenticated request, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limited") {
		t.Fatalf("expected rate_limited error code, body=%s", body)
	}
}

func TestSessionMutationRequiresCSRFHeader(t *testing.T) {
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
		t.Fatalf("expected 201 for session create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"name": "csrf-check",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF header, got %d body=%s", resp.StatusCode, body)
	}
}

func TestSelfServiceRegisterIssuesServerGeneratedKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]Role{
		"enroll-viewer": RoleViewer,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/register", map[string]string{
		"enrollment_token": "enroll-viewer",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 register, got %d body=%s", resp.StatusCode, body)
	}

	var registerResp struct {
		Role   Role   `json:"role"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &registerResp); err != nil {
		t.Fatalf("failed to parse register response: %v", err)
	}
	if registerResp.Role != RoleViewer || strings.TrimSpace(registerResp.APIKey) == "" {
		t.Fatalf("expected viewer role with generated key, got role=%q key=%q", registerResp.Role, registerResp.APIKey)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer " + registerResp.APIKey,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected issued key to authenticate, got %d body=%s", resp.StatusCode, body)
	}
}

func TestAPIKeyLifecycleEndpoints(t *testing.T) {
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

	// Viewer cannot create API keys.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/api-keys", map[string]string{
		"name": "viewer-created",
		"role": "viewer",
	}, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer create, got %d body=%s", resp.StatusCode, body)
	}

	// Admin creates an operator key.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/api-keys", map[string]string{
		"name": "ops-key",
		"role": "operator",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for key create, got %d body=%s", resp.StatusCode, body)
	}

	var created struct {
		ID     string `json:"id"`
		Role   Role   `json:"role"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode created key response: %v", err)
	}
	if strings.TrimSpace(created.ID) == "" || strings.TrimSpace(created.APIKey) == "" {
		t.Fatalf("expected key id and secret in create response, got id=%q key=%q", created.ID, created.APIKey)
	}
	if created.Role != RoleOperator {
		t.Fatalf("expected operator role, got %q", created.Role)
	}

	// Created key should authenticate as operator.
	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]string{
		"name": "project-via-created-key",
	}, map[string]string{
		"Authorization": "Bearer " + created.APIKey,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected created key to create project, got %d body=%s", resp.StatusCode, body)
	}

	// List keys should return metadata only (not raw secret).
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/api-keys", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for key list, got %d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(body, created.APIKey) {
		t.Fatalf("key list leaked raw secret: %s", body)
	}
	if !strings.Contains(body, created.ID) {
		t.Fatalf("expected key list to contain created key id, body=%s", body)
	}

	// Revoke managed key.
	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/api-keys/"+created.ID, nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for key revoke, got %d body=%s", resp.StatusCode, body)
	}

	// Revoked key should no longer authenticate.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer " + created.APIKey,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked key, got %d body=%s", resp.StatusCode, body)
	}

	// Audit stream should include key lifecycle events with key id references.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit events, got %d body=%s", resp.StatusCode, body)
	}
	var lifecycleAudit struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(body), &lifecycleAudit); err != nil {
		t.Fatalf("failed to decode audit events response: %v body=%s", err, body)
	}
	issuedFound := false
	revokedFound := false
	for _, event := range lifecycleAudit.Events {
		if event.EventType == "api_key_issued" && event.ScanID == created.ID {
			issuedFound = true
		}
		if event.EventType == "api_key_revoked" && event.ScanID == created.ID {
			revokedFound = true
		}
	}
	if !issuedFound || !revokedFound {
		t.Fatalf("expected lifecycle audit events with key id reference, issued=%v revoked=%v events=%v", issuedFound, revokedFound, lifecycleAudit.Events)
	}

	// Bootstrap key revocation should be rejected.
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/api-keys", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for key list before bootstrap revoke, got %d body=%s", resp.StatusCode, body)
	}
	var listed struct {
		APIKeys []APIKeyMetadata `json:"api_keys"`
	}
	if err := json.Unmarshal([]byte(body), &listed); err != nil {
		t.Fatalf("failed to decode key list: %v", err)
	}
	bootstrapID := ""
	for _, item := range listed.APIKeys {
		if item.Source == "bootstrap" && item.Role == RoleAdmin {
			bootstrapID = item.ID
			break
		}
	}
	if bootstrapID == "" {
		t.Fatalf("expected bootstrap admin key metadata in list, body=%s", body)
	}
	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/api-keys/"+bootstrapID, nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for bootstrap key revoke, got %d body=%s", resp.StatusCode, body)
	}
}

func TestOpenAPISpecRoute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"viewer-key": RoleViewer,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/openapi.yaml", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 openapi route, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "openapi: 3.0.3") {
		t.Fatalf("expected OpenAPI document body, got: %s", body)
	}
}

func TestMetricsEndpointExposesOperationalCounters(t *testing.T) {
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

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_metrics",
		"name": "metrics-project",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 project create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_metrics",
		"commit_sha": "metrics123",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "G1",
				"severity":  "block",
				"message":   "blocking failure for metrics",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 scan create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/metrics", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 metrics endpoint, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.ToLower(resp.Header.Get("Content-Type")); !strings.Contains(got, "text/plain") {
		t.Fatalf("expected text/plain metrics content-type, got %q", got)
	}

	expectedLines := []string{
		"baseline_projects_total 1",
		"baseline_scans_total 1",
		"baseline_failing_scans_total 1",
		"baseline_blocking_violations_total 1",
		"baseline_api_keys_active_total 1",
		"baseline_api_keys_revoked_total 0",
	}
	for _, line := range expectedLines {
		if !strings.Contains(body, line) {
			t.Fatalf("expected metrics output to contain %q, body=%s", line, body)
		}
	}
}

func TestMetricsEndpointMethodNotAllowed(t *testing.T) {
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
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/metrics", map[string]any{
		"unexpected": true,
	}, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for metrics POST, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "method_not_allowed") {
		t.Fatalf("expected method_not_allowed error body, got %s", body)
	}
}

func TestReadyEndpointInMemoryModeIsReady(t *testing.T) {
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
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/readyz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 readyz response for in-memory mode, got %d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode readiness payload: %v body=%s", err, body)
	}
	if payload.Status != "ready" {
		t.Fatalf("expected readiness status=ready, got %q", payload.Status)
	}
	if payload.Checks["database"].Status != "ready" {
		t.Fatalf("expected database ready in in-memory mode, checks=%v", payload.Checks)
	}
	if payload.Checks["integration_worker"].Status != "ready" {
		t.Fatalf("expected integration worker ready in in-memory mode, checks=%v", payload.Checks)
	}
}

func TestReadyEndpointPersistentStoreRequiresWorker(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readyz_requires_worker.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/readyz", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when persistent store worker is not running, got %d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode readiness payload: %v body=%s", err, body)
	}
	if payload.Status != "not_ready" {
		t.Fatalf("expected readiness status=not_ready, got %q", payload.Status)
	}
	if payload.Checks["database"].Status != "ready" {
		t.Fatalf("expected database readiness check to pass, checks=%v", payload.Checks)
	}
	if payload.Checks["integration_worker"].Status != "not_ready" {
		t.Fatalf("expected integration_worker not_ready, checks=%v", payload.Checks)
	}
}

func TestReadyEndpointPersistentStoreWithWorkerIsReady(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readyz_worker_running.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	server.startIntegrationWorker()
	defer server.stopIntegrationWorker()

	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/readyz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with persistent store and running worker, got %d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode readiness payload: %v body=%s", err, body)
	}
	if payload.Status != "ready" {
		t.Fatalf("expected readiness status=ready, got %q", payload.Status)
	}
	if payload.Checks["database"].Status != "ready" {
		t.Fatalf("expected database ready, checks=%v", payload.Checks)
	}
	if payload.Checks["integration_worker"].Status != "ready" {
		t.Fatalf("expected integration_worker ready, checks=%v", payload.Checks)
	}
}

func TestReadyEndpointReportsDatabaseFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readyz_db_failure.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	defer store.Close()

	if err := store.Close(); err != nil {
		t.Fatalf("failed to close store for failure test: %v", err)
	}

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/readyz", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when database is unavailable, got %d body=%s", resp.StatusCode, body)
	}

	var payload struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode readiness payload: %v body=%s", err, body)
	}
	if payload.Checks["database"].Status != "not_ready" {
		t.Fatalf("expected database check to be not_ready after close, checks=%v", payload.Checks)
	}
}

func TestAPIStatePersistsAcrossServerRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "baseline_api_test.db")
	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeyHashSecret = "test-api-key-hash-secret"
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	store1, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	server1, err := NewServer(cfg, store1)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts1 := httptest.NewServer(server1.Handler())
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts1.URL+"/v1/api-keys", map[string]string{
		"name": "persisted-key",
		"role": "operator",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 key create, got %d body=%s", resp.StatusCode, body)
	}
	var created struct {
		ID     string `json:"id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode key create response: %v", err)
	}
	if created.ID == "" || created.APIKey == "" {
		t.Fatalf("expected created key id + secret, got id=%q key=%q", created.ID, created.APIKey)
	}
	assertSQLiteColumnMissing(t, store1.db, "api_keys", "key_value")
	assertSQLiteColumnExists(t, store1.db, "api_keys", "key_hash")
	var hashedRowCount int
	if err := store1.db.QueryRow(`SELECT COUNT(1) FROM api_keys WHERE key_hash = ?`, hashAPIKey(created.APIKey, cfg.APIKeyHashSecret)).Scan(&hashedRowCount); err != nil {
		t.Fatalf("failed to verify persisted key hash: %v", err)
	}
	if hashedRowCount == 0 {
		t.Fatalf("expected persisted managed key hash in database")
	}
	ts1.Close()
	_ = store1.Close()

	store2, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error on restart: %v", err)
	}
	defer store2.Close()
	server2, err := NewServer(cfg, store2)
	if err != nil {
		t.Fatalf("NewServer returned error on restart: %v", err)
	}
	ts2 := httptest.NewServer(server2.Handler())
	defer ts2.Close()

	resp, body = mustRequest(t, client, http.MethodGet, ts2.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer " + created.APIKey,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected persisted key auth to work after restart, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts2.URL+"/v1/api-keys", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected api key list after restart, got %d body=%s", resp.StatusCode, body)
	}
	var listed struct {
		APIKeys []APIKeyMetadata `json:"api_keys"`
	}
	if err := json.Unmarshal([]byte(body), &listed); err != nil {
		t.Fatalf("failed to decode api key list: %v", err)
	}
	revokeID := ""
	for _, item := range listed.APIKeys {
		if item.Source != "bootstrap" && !item.Revoked {
			revokeID = item.ID
		}
		if item.Source == "managed" && item.Prefix == keyPrefix(created.APIKey) {
			revokeID = item.ID
			break
		}
	}
	if revokeID == "" {
		t.Fatalf("expected at least one managed api key after restart, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodDelete, ts2.URL+"/v1/api-keys/"+revokeID, nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected key revoke to succeed, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts2.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer " + created.APIKey,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked persisted key to fail auth, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts2.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected audit events to load from persistence, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "api_key_issued") || !strings.Contains(body, "api_key_revoked") {
		t.Fatalf("expected persisted audit events for key lifecycle, body=%s", body)
	}
}

func TestGitHubWebhookSignatureValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.GitHubWebhookSecret = "github-secret"
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	payload := map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 31,
		},
		"repository": map[string]any{
			"full_name": "acme/payments",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/integrations/github/webhook", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing github signature, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	signature := testGitHubSignature(raw, cfg.GitHubWebhookSecret)
	req, err = http.NewRequest(http.MethodPost, ts.URL+"/v1/integrations/github/webhook", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", signature)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for valid github webhook, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 audit events, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "github_webhook_received") {
		t.Fatalf("expected github webhook audit event, body=%s", body)
	}
}

func TestGitLabWebhookTokenValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.GitLabWebhookToken = "gitlab-token"
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	payload := map[string]any{
		"object_kind": "merge_request",
		"object_attributes": map[string]any{
			"action": "open",
			"iid":    12,
		},
		"project": map[string]any{
			"path_with_namespace": "acme/platform",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/integrations/gitlab/webhook", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	req.Header.Set("X-Gitlab-Token", "wrong-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid gitlab token, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, err = http.NewRequest(http.MethodPost, ts.URL+"/v1/integrations/gitlab/webhook", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitlab-Event", "Merge Request Hook")
	req.Header.Set("X-Gitlab-Token", cfg.GitLabWebhookToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for valid gitlab webhook, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 audit events, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "gitlab_webhook_received") {
		t.Fatalf("expected gitlab webhook audit event, body=%s", body)
	}
}

func TestGitHubCheckRunPublish(t *testing.T) {
	var (
		capturedPath   string
		capturedAuth   string
		capturedAccept string
		capturedBody   string
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		capturedAccept = r.Header.Get("Accept")
		var out bytes.Buffer
		_, _ = out.ReadFrom(r.Body)
		capturedBody = out.String()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1234}`))
	}))
	defer upstream.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
		"viewer-key":   RoleViewer,
	}
	cfg.GitHubAPIToken = "gh-api-token"
	cfg.GitHubAPIBaseURL = upstream.URL

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	// Viewer cannot publish.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/integrations/github/check-runs", map[string]any{
		"owner":      "acme",
		"repository": "payments",
		"head_sha":   "abc123",
		"name":       "baseline/enforce",
	}, map[string]string{
		"Authorization": "Bearer viewer-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer publish, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/integrations/github/check-runs", map[string]any{
		"owner":      "acme",
		"repository": "payments",
		"head_sha":   "abc123",
		"name":       "baseline/enforce",
		"status":     "completed",
		"conclusion": "success",
		"output": map[string]any{
			"title":   "Baseline scan",
			"summary": "All checks passed",
		},
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for github publish, got %d body=%s", resp.StatusCode, body)
	}
	if capturedPath != "/repos/acme/payments/check-runs" {
		t.Fatalf("expected github check-runs path, got %q", capturedPath)
	}
	if capturedAuth != "Bearer gh-api-token" {
		t.Fatalf("expected github auth bearer token, got %q", capturedAuth)
	}
	if !strings.Contains(strings.ToLower(capturedAccept), "application/vnd.github+json") {
		t.Fatalf("expected github accept header, got %q", capturedAccept)
	}
	if !strings.Contains(capturedBody, `"head_sha":"abc123"`) || !strings.Contains(capturedBody, `"name":"baseline/enforce"`) {
		t.Fatalf("expected head_sha/name in upstream payload, got %s", capturedBody)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit list, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "github_check_published") {
		t.Fatalf("expected github_check_published audit event, body=%s", body)
	}
}

func TestGitLabStatusPublish(t *testing.T) {
	var (
		capturedPath  string
		capturedQuery string
		capturedToken string
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		capturedToken = r.Header.Get("PRIVATE-TOKEN")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer upstream.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
	}
	cfg.GitLabAPIToken = "gl-api-token"
	cfg.GitLabAPIBaseURL = upstream.URL

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/integrations/gitlab/statuses", map[string]any{
		"project_id":  "acme/platform",
		"sha":         "def456",
		"state":       "success",
		"name":        "baseline/enforce",
		"target_url":  "https://ci.example.test/runs/1",
		"description": "checks passed",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for gitlab publish, got %d body=%s", resp.StatusCode, body)
	}
	if capturedPath != "/projects/acme/platform/statuses/def456" {
		t.Fatalf("expected gitlab status path, got %q", capturedPath)
	}
	if capturedToken != "gl-api-token" {
		t.Fatalf("expected gitlab private token, got %q", capturedToken)
	}
	if !strings.Contains(capturedQuery, "state=success") || !strings.Contains(capturedQuery, "name=baseline%2Fenforce") {
		t.Fatalf("expected state/name in gitlab query, got %q", capturedQuery)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit list, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "gitlab_status_published") {
		t.Fatalf("expected gitlab_status_published audit event, body=%s", body)
	}
}

func TestWebhookEnqueuesPersistentIntegrationJob(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "integration_jobs.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeyHashSecret = "test-api-key-hash-secret"
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.GitHubWebhookSecret = "github-secret"
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	payload := map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 77,
		},
		"repository": map[string]any{
			"full_name": "acme/repo",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/integrations/github/webhook", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", testGitHubSignature(raw, cfg.GitHubWebhookSecret))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for webhook enqueue, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	jobs, err := store.ListIntegrationJobs(10)
	if err != nil {
		t.Fatalf("ListIntegrationJobs failed: %v", err)
	}
	if len(jobs) == 0 {
		t.Fatal("expected queued integration job after webhook")
	}
	if jobs[0].Provider != "github" || jobs[0].Status != IntegrationJobPending {
		t.Fatalf("unexpected queued job state: provider=%q status=%q", jobs[0].Provider, jobs[0].Status)
	}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit events, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "integration_job_enqueued") {
		t.Fatalf("expected integration_job_enqueued audit event, body=%s", body)
	}
}

func TestIntegrationWorkerRetriesTransientFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "integration_worker.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	server.integrationPollInterval = 10 * time.Millisecond
	server.integrationRetryBase = 10 * time.Millisecond
	server.integrationRetryMax = 20 * time.Millisecond

	_, err = store.EnqueueIntegrationJob(IntegrationJob{
		Provider:    "github",
		JobType:     "webhook_event",
		ProjectRef:  "acme/repo",
		ExternalRef: "42",
		MaxAttempts: 5,
		Payload:     `{"simulate_transient_failures":1}`,
	})
	if err != nil {
		t.Fatalf("EnqueueIntegrationJob failed: %v", err)
	}

	server.startIntegrationWorker()
	defer server.stopIntegrationWorker()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		jobs, listErr := store.ListIntegrationJobs(10)
		if listErr != nil {
			t.Fatalf("ListIntegrationJobs failed: %v", listErr)
		}
		if len(jobs) > 0 && jobs[0].Status == IntegrationJobSucceeded && jobs[0].AttemptCount >= 2 {
			events, eventErr := store.LoadAuditEvents(20)
			if eventErr != nil {
				t.Fatalf("LoadAuditEvents failed: %v", eventErr)
			}
			joined := ""
			for _, event := range events {
				joined += event.EventType + "\n"
			}
			if !strings.Contains(joined, "integration_job_retry_scheduled") {
				t.Fatalf("expected retry audit event, got events:\n%s", joined)
			}
			if !strings.Contains(joined, "integration_job_succeeded") {
				t.Fatalf("expected success audit event, got events:\n%s", joined)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for integration job retry/success flow")
}

func TestServerLoadsMigratedLegacyStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_runtime.db")
	createLegacyStoreSchema(t, dbPath)

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	version := currentStoreSchemaVersionForTest(t, store.db)
	if version != currentStoreSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", currentStoreSchemaVersion, version)
	}

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer legacy-key-value",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected migrated legacy key auth to work, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected audit endpoint to load after migration, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "legacy_event") {
		t.Fatalf("expected legacy audit event after migration, body=%s", body)
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

func testGitHubSignature(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
}
