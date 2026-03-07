package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadEndpointsRBACMatrix(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
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

	// Seed baseline objects so detail/list read endpoints are meaningful.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "proj_authz_matrix",
		"name": "authz-matrix-project",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding project, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan_authz_matrix",
		"project_id": "proj_authz_matrix",
		"commit_sha": "authz-matrix-commit",
		"status":     "fail",
		"violations": []map[string]any{
			{
				"policy_id": "D1",
				"severity":  "block",
				"message":   "authz matrix secret violation fixture",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding scan, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/authz-matrix-policy/versions", map[string]any{
		"version": "v1",
		"content": map[string]any{"rule": "authz-matrix"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding policy, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/rulesets", map[string]any{
		"version":      "authz-matrix-ruleset-v1",
		"description":  "authz matrix ruleset seed",
		"policy_names": []string{"authz-matrix-policy"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 seeding ruleset, got %d body=%s", resp.StatusCode, body)
	}

	type endpointCase struct {
		name           string
		path           string
		unauthStatus   int
		viewerStatus   int
		operatorStatus int
		adminStatus    int
	}

	cases := []endpointCase{
		{
			name:           "auth_me",
			path:           "/v1/auth/me",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "dashboard_summary",
			path:           "/v1/dashboard",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "dashboard_capabilities",
			path:           "/v1/dashboard/capabilities",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "dashboard_activity",
			path:           "/v1/dashboard/activity?limit=10",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "projects_list",
			path:           "/v1/projects",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "project_detail",
			path:           "/v1/projects/proj_authz_matrix",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusNotFound,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "scans_list",
			path:           "/v1/scans",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "scan_detail",
			path:           "/v1/scans/scan_authz_matrix",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusNotFound,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "scan_report_json",
			path:           "/v1/scans/scan_authz_matrix/report?format=json",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusNotFound,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "policies_list",
			path:           "/v1/policies",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "policy_latest",
			path:           "/v1/policies/authz-matrix-policy/latest",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "ruleset_latest",
			path:           "/v1/rulesets/latest",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "audit_events",
			path:           "/v1/audit/events?limit=5",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "api_keys_list",
			path:           "/v1/api-keys",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusOK,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
		{
			name:           "me_api_keys_list",
			path:           "/v1/me/api-keys",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusForbidden,
		},
		{
			name:           "users_list",
			path:           "/v1/users",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusForbidden,
			adminStatus:    http.StatusServiceUnavailable,
		},
		{
			name:           "integration_jobs_list",
			path:           "/v1/integrations/jobs?limit=5",
			unauthStatus:   http.StatusUnauthorized,
			viewerStatus:   http.StatusForbidden,
			operatorStatus: http.StatusOK,
			adminStatus:    http.StatusOK,
		},
	}

	roles := []struct {
		name   string
		token  string
		expect func(endpointCase) int
	}{
		{
			name:  "unauthenticated",
			token: "",
			expect: func(tc endpointCase) int {
				return tc.unauthStatus
			},
		},
		{
			name:  "viewer",
			token: "viewer-key",
			expect: func(tc endpointCase) int {
				return tc.viewerStatus
			},
		},
		{
			name:  "operator",
			token: "operator-key",
			expect: func(tc endpointCase) int {
				return tc.operatorStatus
			},
		},
		{
			name:  "admin",
			token: "admin-key",
			expect: func(tc endpointCase) int {
				return tc.adminStatus
			},
		},
	}

	for _, tc := range cases {
		for _, role := range roles {
			headers := map[string]string{}
			if strings.TrimSpace(role.token) != "" {
				headers["Authorization"] = "Bearer " + role.token
			}
			resp, body := mustRequest(t, client, http.MethodGet, ts.URL+tc.path, nil, headers)
			expected := role.expect(tc)
			if resp.StatusCode != expected {
				t.Fatalf("%s role=%s expected status %d, got %d body=%s", tc.name, role.name, expected, resp.StatusCode, body)
			}
		}
	}
}

func TestDashboardCapabilitiesAuthzFlagsMatchEndpointRBAC(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
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

	testCases := []struct {
		name          string
		token         string
		canWriteKeys  bool
		canWriteProj  bool
		canRunScans   bool
		canWriteInteg bool
		canWriteSec   bool
	}{
		{
			name:          "viewer",
			token:         "viewer-key",
			canWriteKeys:  true,
			canWriteProj:  false,
			canRunScans:   false,
			canWriteInteg: false,
			canWriteSec:   false,
		},
		{
			name:          "operator",
			token:         "operator-key",
			canWriteKeys:  true,
			canWriteProj:  true,
			canRunScans:   true,
			canWriteInteg: true,
			canWriteSec:   false,
		},
		{
			name:          "admin",
			token:         "admin-key",
			canWriteKeys:  true,
			canWriteProj:  true,
			canRunScans:   true,
			canWriteInteg: true,
			canWriteSec:   true,
		},
	}

	for _, tc := range testCases {
		resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard/capabilities", nil, map[string]string{
			"Authorization": "Bearer " + tc.token,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: expected 200 loading capabilities, got %d body=%s", tc.name, resp.StatusCode, body)
		}
		var payload struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("%s: failed to decode capabilities response: %v body=%s", tc.name, err, body)
		}

		assertCapability := func(key string, expected bool) {
			got := payload.Capabilities[key]
			if got != expected {
				t.Fatalf("%s: capability %q mismatch: expected %v got %v", tc.name, key, expected, got)
			}
		}
		assertCapability("api_keys.write", tc.canWriteKeys)
		assertCapability("projects.write", tc.canWriteProj)
		assertCapability("scans.run", tc.canRunScans)
		assertCapability("integrations.write", tc.canWriteInteg)
		assertCapability("integrations.secrets.write", tc.canWriteSec)
	}
}
