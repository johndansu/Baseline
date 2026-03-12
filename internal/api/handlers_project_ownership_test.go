package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProjectsAndScansPersistAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "projects_scans_persist.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleOperator
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for session create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_persist",
		"name": "Persist Project",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for project create, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:local_dashboard"`) {
		t.Fatalf("expected created project owner_id in response body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":            "scan_persist",
		"project_id":    "proj_persist",
		"files_scanned": 169,
		"status":        "pass",
		"violations":    []map[string]any{},
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for scan create, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:local_dashboard"`) {
		t.Fatalf("expected created scan owner_id in response body=%s", body)
	}
	if !strings.Contains(body, `"files_scanned":169`) {
		t.Fatalf("expected created scan files_scanned in response body=%s", body)
	}

	ts.Close()
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close returned error: %v", err)
	}

	store2, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore(second) returned error: %v", err)
	}
	defer store2.Close()

	server2, err := NewServer(cfg, store2)
	if err != nil {
		t.Fatalf("NewServer(second) returned error: %v", err)
	}
	ts2 := httptest.NewServer(server2.Handler())
	defer ts2.Close()

	adminClient := &http.Client{}
	resp, body = mustRequest(t, adminClient, http.MethodGet, ts2.URL+"/v1/projects/proj_persist", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for persisted project get, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:local_dashboard"`) {
		t.Fatalf("expected persisted project owner_id in response body=%s", body)
	}

	resp, body = mustRequest(t, adminClient, http.MethodGet, ts2.URL+"/v1/scans/scan_persist", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for persisted scan get, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:local_dashboard"`) {
		t.Fatalf("expected persisted scan owner_id in response body=%s", body)
	}
	if !strings.Contains(body, `"files_scanned":169`) {
		t.Fatalf("expected persisted scan files_scanned in response body=%s", body)
	}
}

func TestProjectClaimTransfersVisibilityToSessionOwner(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin
	cfg.APIKeys = map[string]Role{
		"ops-key": RoleOperator,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	operatorClient := &http.Client{}
	resp, body := mustRequest(t, operatorClient, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_claim",
		"name": "Claim Project",
	}, map[string]string{
		"Authorization": "Bearer ops-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for operator project create, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"api_key:`) {
		t.Fatalf("expected api key owner before claim body=%s", body)
	}

	jar, _ := cookiejar.New(nil)
	sessionClient := &http.Client{Jar: jar}
	resp, body = mustRequest(t, sessionClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for session create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, sessionClient, http.MethodPost, ts.URL+"/v1/projects/proj_claim/claim", nil, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for project claim, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:local_dashboard"`) {
		t.Fatalf("expected claimed project owner in response body=%s", body)
	}

	resp, body = mustRequest(t, sessionClient, http.MethodGet, ts.URL+"/v1/projects/proj_claim", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for claimed project read, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, operatorClient, http.MethodGet, ts.URL+"/v1/projects/proj_claim", nil, map[string]string{
		"Authorization": "Bearer ops-key",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for old key owner after claim, got %d body=%s", resp.StatusCode, body)
	}
}

func TestProjectOwnerAssignmentRequiresAdmin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "project_owner_assign.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	userID, err := store.UpsertOIDCUser("https://issuer.example", "sub-owner-1", "owner1@example.com", "Owner One", time.Now().UTC())
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
		"ops-key":   RoleOperator,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_assign",
		"name": "Assignable Project",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for admin project create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPatch, ts.URL+"/v1/projects/proj_assign/owner", map[string]any{
		"user_id": userID,
	}, map[string]string{
		"Authorization": "Bearer ops-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for operator owner assignment, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPatch, ts.URL+"/v1/projects/proj_assign/owner", map[string]any{
		"user_id": userID,
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin owner assignment, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"owner_id":"user:`+strings.ToLower(userID)+`"`) {
		t.Fatalf("expected assigned owner_id in response body=%s", body)
	}
}
