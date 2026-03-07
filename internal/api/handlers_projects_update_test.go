package api

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProjectsUpdateWithOperatorSession(t *testing.T) {
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

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":             "proj_update_1",
		"name":           "checkout",
		"repository_url": "https://github.com/example/checkout",
		"default_branch": "main",
		"policy_set":     "baseline:prod",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for project create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPut, ts.URL+"/v1/projects/proj_update_1", map[string]any{
		"name":           "checkout-v2",
		"repository_url": "https://github.com/example/checkout-v2",
		"default_branch": "release",
		"policy_set":     "baseline:strict",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for project update, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "checkout-v2") {
		t.Fatalf("expected updated project name in response body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/projects/proj_update_1", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for project get, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "baseline:strict") {
		t.Fatalf("expected updated project policy_set in response body=%s", body)
	}
}

func TestProjectsUpdateForbiddenForViewer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleViewer

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	server.dataMu.Lock()
	server.projects = append(server.projects, Project{
		ID:            "proj_viewer_1",
		Name:          "viewer-project",
		DefaultBranch: "main",
		PolicySet:     "baseline:prod",
	})
	server.dataMu.Unlock()

	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for session create, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPut, ts.URL+"/v1/projects/proj_viewer_1", map[string]any{
		"name": "blocked-update",
	}, map[string]string{
		"X-Baseline-CSRF": "1",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer update, got %d body=%s", resp.StatusCode, body)
	}
}

