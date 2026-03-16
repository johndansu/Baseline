package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEventsPersistAndAppearInAuditLog(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
		"admin-key":    RoleAdmin,
	}

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_events.db"))
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/cli/events", map[string]any{
		"event_type":      "cli_error",
		"command":         "scan",
		"repository":      "Baseline",
		"message":         "dashboard upload failed: upload rejected with status 403",
		"status":          "upload_failed",
		"version":         "dev",
		"files_scanned":   172,
		"security_issues": 1,
		"violation_count": 2,
		"duration_ms":     3120,
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for CLI event ingest, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "\"event_type\":\"cli_error\"") {
		t.Fatalf("expected CLI event payload in response, got %s", body)
	}

	events, err := store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents returned error: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected persisted audit events")
	}
	if events[0].EventType != "cli_error" {
		t.Fatalf("expected latest event type cli_error, got %q", events[0].EventType)
	}
	if !strings.Contains(events[0].Details, "dashboard upload failed") {
		t.Fatalf("expected persisted CLI details, got %q", events[0].Details)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events?limit=5", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for audit events, got %d body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode audit events response: %v body=%s", err, body)
	}
	if len(payload.Events) == 0 {
		t.Fatal("expected audit events in response")
	}
	if payload.Events[0].Details == "" {
		t.Fatalf("expected audit event details in response, got %+v", payload.Events[0])
	}
}

func TestCLIEventsRequireAuthentication(t *testing.T) {
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
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/cli/events", map[string]any{
		"event_type": "cli_health",
		"command":    "check",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated CLI event ingest, got %d body=%s", resp.StatusCode, body)
	}
}

func TestCLIEventsListRequiresAdmin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
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
	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/cli/events?limit=20", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin CLI event list, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/cli/events?limit=20", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin CLI event list, got %d body=%s", resp.StatusCode, body)
	}
}
