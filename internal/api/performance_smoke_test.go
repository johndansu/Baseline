package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHighReadEndpointsPerformanceSmoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.RateLimitEnabled = false

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	fixture := seedContractFixture(t, client, ts.URL)

	testCases := []struct {
		name           string
		path           string
		expectedStatus int
		headers        map[string]string
	}{
		{
			name:           "dashboard_summary",
			path:           "/v1/dashboard",
			expectedStatus: http.StatusOK,
			headers: map[string]string{
				"Authorization": "Bearer admin-key",
			},
		},
		{
			name:           "projects_list",
			path:           "/v1/projects",
			expectedStatus: http.StatusOK,
			headers: map[string]string{
				"Authorization": "Bearer admin-key",
			},
		},
		{
			name:           "scans_list_by_project",
			path:           "/v1/scans?project_id=" + fixture.projectID,
			expectedStatus: http.StatusOK,
			headers: map[string]string{
				"Authorization": "Bearer admin-key",
			},
		},
		{
			name:           "audit_events_by_project",
			path:           "/v1/audit/events?project_id=" + fixture.projectID + "&limit=20",
			expectedStatus: http.StatusOK,
			headers: map[string]string{
				"Authorization": "Bearer admin-key",
			},
		},
		{
			name:           "metrics_endpoint",
			path:           "/metrics",
			expectedStatus: http.StatusOK,
			headers: map[string]string{
				"Authorization": "Bearer admin-key",
			},
		},
	}

	const iterations = 120
	const maxPerEndpointDuration = 15 * time.Second

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			for i := 0; i < iterations; i++ {
				resp, body := mustRequest(t, client, http.MethodGet, ts.URL+tc.path, nil, tc.headers)
				if resp.StatusCode != tc.expectedStatus {
					t.Fatalf("request %d expected %d got %d body=%s", i, tc.expectedStatus, resp.StatusCode, body)
				}
			}
			elapsed := time.Since(started)
			if elapsed > maxPerEndpointDuration {
				t.Fatalf("performance smoke threshold exceeded: endpoint=%s iterations=%d elapsed=%s threshold=%s", tc.path, iterations, elapsed, maxPerEndpointDuration)
			}
		})
	}
}
