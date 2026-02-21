package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBackendE2ESuite(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleOperator
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]Role{
		"e2e-viewer-token": RoleViewer,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	sessionClient := &http.Client{Jar: jar}
	bearerClient := &http.Client{}

	// 1) Auth via dashboard session.
	resp, body := mustRequest(t, sessionClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for session start, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, sessionClient, http.MethodGet, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for session lookup, got %d body=%s", resp.StatusCode, body)
	}

	// 2) Projects flow.
	resp, body = mustRequest(t, sessionClient, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_e2e",
		"name": "e2e-project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for project create, got %d body=%s", resp.StatusCode, body)
	}

	// End session before API-key checks.
	resp, body = mustRequest(t, sessionClient, http.MethodDelete, ts.URL+"/v1/auth/session", nil, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for session delete, got %d body=%s", resp.StatusCode, body)
	}

	// 3) Self-service auth flow returns a usable key.
	resp, body = mustRequest(t, bearerClient, http.MethodPost, ts.URL+"/v1/auth/register", map[string]any{
		"enrollment_token": "e2e-viewer-token",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for self-service register, got %d body=%s", resp.StatusCode, body)
	}
	var registerResp struct {
		Role   Role   `json:"role"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &registerResp); err != nil {
		t.Fatalf("failed to decode register response: %v body=%s", err, body)
	}
	if registerResp.Role != RoleViewer || strings.TrimSpace(registerResp.APIKey) == "" {
		t.Fatalf("expected viewer key from self-service, got role=%q key=%q", registerResp.Role, registerResp.APIKey)
	}

	resp, body = mustRequest(t, bearerClient, http.MethodGet, ts.URL+"/v1/projects", nil, map[string]string{
		"Authorization": "Bearer " + registerResp.APIKey,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for viewer project read, got %d body=%s", resp.StatusCode, body)
	}

	// 4) Scans flow.
	resp, body = mustRequest(t, bearerClient, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": "proj_e2e",
		"commit_sha": "e2e-commit-123",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "D1",
				"severity":  "block",
				"message":   "e2e secret finding",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for scan upload, got %d body=%s", resp.StatusCode, body)
	}

	// 5) Policies flow.
	resp, body = mustRequest(t, bearerClient, http.MethodPost, ts.URL+"/v1/policies/e2e-policy/versions", map[string]any{
		"version": "v1",
		"content": map[string]any{"rule": "no-secrets"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for policy publish, got %d body=%s", resp.StatusCode, body)
	}

	// 6) Rulesets flow.
	resp, body = mustRequest(t, bearerClient, http.MethodPost, ts.URL+"/v1/rulesets", map[string]any{
		"version":      "e2e-ruleset-v1",
		"description":  "e2e ruleset",
		"policy_names": []string{"e2e-policy"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for ruleset publish, got %d body=%s", resp.StatusCode, body)
	}

	// 7) Audit flow includes critical lifecycle events.
	resp, body = mustRequest(t, bearerClient, http.MethodGet, ts.URL+"/v1/audit/events?limit=50", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit events, got %d body=%s", resp.StatusCode, body)
	}
	var auditResp struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(body), &auditResp); err != nil {
		t.Fatalf("failed to decode audit response: %v body=%s", err, body)
	}
	requiredEvents := map[string]bool{
		"project_registered": false,
		"scan_uploaded":      false,
		"policy_updated":     false,
		"ruleset_updated":    false,
		"api_key_issued":     false,
	}
	for _, event := range auditResp.Events {
		if _, exists := requiredEvents[event.EventType]; exists {
			requiredEvents[event.EventType] = true
		}
	}
	for eventType, found := range requiredEvents {
		if !found {
			t.Fatalf("expected audit event %q in end-to-end flow, events=%v", eventType, auditResp.Events)
		}
	}
}
