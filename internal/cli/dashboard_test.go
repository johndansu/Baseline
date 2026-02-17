package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDashboardConfigDefaults(t *testing.T) {
	cfg, err := parseDashboardConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseDashboardConfig returned error: %v", err)
	}

	if cfg.Addr != "127.0.0.1:8091" {
		t.Fatalf("expected default addr 127.0.0.1:8091, got %q", cfg.Addr)
	}
	if cfg.APIBaseURL != "http://127.0.0.1:8080" {
		t.Fatalf("expected default api URL http://127.0.0.1:8080, got %q", cfg.APIBaseURL)
	}
}

func TestParseDashboardConfigUsesAPIAddrEnv(t *testing.T) {
	cfg, err := parseDashboardConfig(nil, func(key string) string {
		if key == "BASELINE_API_ADDR" {
			return ":9090"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("parseDashboardConfig returned error: %v", err)
	}
	if cfg.APIBaseURL != "http://127.0.0.1:9090" {
		t.Fatalf("expected api URL from BASELINE_API_ADDR, got %q", cfg.APIBaseURL)
	}
}

func TestParseDashboardConfigFlags(t *testing.T) {
	cfg, err := parseDashboardConfig(
		[]string{"--addr", "127.0.0.1:9091", "--api", "https://baseline.example.com/api"},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("parseDashboardConfig returned error: %v", err)
	}
	if cfg.Addr != "127.0.0.1:9091" {
		t.Fatalf("expected addr override, got %q", cfg.Addr)
	}
	if cfg.APIBaseURL != "https://baseline.example.com/api" {
		t.Fatalf("expected api override, got %q", cfg.APIBaseURL)
	}
}

func TestParseDashboardConfigRejectsUnknownFlag(t *testing.T) {
	_, err := parseDashboardConfig([]string{"--bad-flag"}, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("expected unknown flag error, got %v", err)
	}
}

func TestParseDashboardConfigHelpFlag(t *testing.T) {
	_, err := parseDashboardConfig([]string{"--help"}, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected help error")
	}
	if err != errDashboardHelp {
		t.Fatalf("expected errDashboardHelp, got %v", err)
	}
}

func TestDashboardHandlerIndex(t *testing.T) {
	handler, err := newDashboardHandler(
		dashboardConfig{Addr: "127.0.0.1:8091", APIBaseURL: "http://127.0.0.1:8080"},
		nil,
	)
	if err != nil {
		t.Fatalf("newDashboardHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Baseline Dashboard") {
		t.Fatalf("expected dashboard title in response body, got: %s", body)
	}
	if !strings.Contains(body, "http://127.0.0.1:8080") {
		t.Fatalf("expected API URL in response body, got: %s", body)
	}
}

func TestDashboardProxyForwardsAuthAndPath(t *testing.T) {
	var capturedPath string
	var capturedQuery string
	var capturedAuth string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	handler, err := newDashboardHandler(
		dashboardConfig{Addr: "127.0.0.1:8091", APIBaseURL: upstream.URL},
		upstream.Client(),
	)
	if err != nil {
		t.Fatalf("newDashboardHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/proxy/v1/projects?project_id=proj_1", nil)
	req.Header.Set("X-Baseline-API-Key", "secret-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if capturedPath != "/v1/projects" {
		t.Fatalf("expected forwarded path /v1/projects, got %q", capturedPath)
	}
	if capturedQuery != "project_id=proj_1" {
		t.Fatalf("expected forwarded query project_id=proj_1, got %q", capturedQuery)
	}
	if capturedAuth != "Bearer secret-key" {
		t.Fatalf("expected bearer auth header, got %q", capturedAuth)
	}
}

func TestDashboardProxyAllowsDashboardSummaryPath(t *testing.T) {
	var capturedPath string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"metrics":{"projects":0}}`)
	}))
	defer upstream.Close()

	handler, err := newDashboardHandler(
		dashboardConfig{Addr: "127.0.0.1:8091", APIBaseURL: upstream.URL},
		upstream.Client(),
	)
	if err != nil {
		t.Fatalf("newDashboardHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/proxy/v1/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if capturedPath != "/v1/dashboard" {
		t.Fatalf("expected forwarded path /v1/dashboard, got %q", capturedPath)
	}
}

func TestDashboardProxyRejectsDisallowedPath(t *testing.T) {
	handler, err := newDashboardHandler(
		dashboardConfig{Addr: "127.0.0.1:8091", APIBaseURL: "http://127.0.0.1:8080"},
		nil,
	)
	if err != nil {
		t.Fatalf("newDashboardHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/proxy/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 for disallowed path, got %d", rec.Code)
	}
}
