package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var dashboardRequestPattern = regexp.MustCompile(`(?:request|requestText)\(\s*["']([^"']+)["']\s*,\s*["']([A-Za-z]+)["']`)

func TestDashboardAssetUsesImplementedRoutesAndMethods(t *testing.T) {
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

	content := string(mustLoadDashboardAsset("assets/dashboard.js"))
	matches := dashboardRequestPattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		t.Fatal("expected request calls in dashboard asset")
	}

	seen := map[string]struct{}{}
	spec := loadOpenAPISpec(t)
	client := &http.Client{}

	for _, match := range matches {
		rawPath := strings.TrimSpace(match[1])
		method := strings.ToUpper(strings.TrimSpace(match[2]))
		if rawPath == "" || method == "" {
			t.Fatalf("invalid request call in dashboard asset: path=%q method=%q", rawPath, method)
		}

		key := method + " " + rawPath
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		basePath := rawPath
		if idx := strings.Index(basePath, "?"); idx >= 0 {
			basePath = basePath[:idx]
		}
		ops, exists := spec.Paths[basePath]
		if !exists {
			t.Fatalf("dashboard route not declared in OpenAPI: %s", basePath)
		}
		if _, methodExists := ops[strings.ToLower(method)]; !methodExists {
			t.Fatalf("dashboard method not declared in OpenAPI: %s %s", method, basePath)
		}

		payload, headers := dashboardAssetRequestFixture(rawPath, method)
		resp, body := mustRequest(t, client, method, ts.URL+rawPath, payload, headers)
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Fatalf("dashboard route call is not implemented: %s %s status=%d body=%s", method, rawPath, resp.StatusCode, body)
		}
	}
}

func dashboardAssetRequestFixture(path, method string) (any, map[string]string) {
	headers := map[string]string{}
	if strings.HasPrefix(path, "/v1/") {
		headers["Authorization"] = "Bearer admin-key"
	}
	switch {
	case path == "/v1/auth/session" && method == http.MethodDelete:
		headers["X-Baseline-CSRF"] = "1"
		return nil, headers
	case path == "/v1/auth/session" && method == http.MethodPost:
		return map[string]any{}, headers
	case path == "/v1/projects" && method == http.MethodPost:
		return map[string]any{
			"name":           "dashboard-integration-project",
			"default_branch": "main",
			"policy_set":     "baseline:prod",
		}, headers
	default:
		return nil, headers
	}
}
