package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/api"
	"github.com/baseline/baseline/internal/types"
)

func TestParseScanArgs(t *testing.T) {
	opts, err := parseScanArgs([]string{
		"--api", "http://127.0.0.1:8080",
		"--project-id", "proj_123",
		"--api-key", "test-key",
		"--scan-id", "scan_123",
		"--commit-sha", "abc123",
	})
	if err != nil {
		t.Fatalf("parseScanArgs returned error: %v", err)
	}
	if opts.APIBaseURL != "http://127.0.0.1:8080" || opts.ProjectID != "proj_123" || opts.APIKey != "test-key" || opts.ScanID != "scan_123" || opts.CommitSHA != "abc123" {
		t.Fatalf("unexpected parsed options: %+v", opts)
	}
}

func TestMatchProjectForScanUpload(t *testing.T) {
	projects := []api.Project{
		{ID: "proj_a", Name: "Other", RepositoryURL: "https://github.com/example/other.git"},
		{ID: "proj_b", Name: "Baseline", RepositoryURL: "git@github.com:johndansu/Baseline.git"},
	}

	matched, err := matchProjectForScanUpload(projects, "Baseline", "https://github.com/johndansu/Baseline.git")
	if err != nil {
		t.Fatalf("matchProjectForScanUpload returned error: %v", err)
	}
	if matched.ID != "proj_b" {
		t.Fatalf("expected proj_b, got %+v", matched)
	}
}

func TestUploadScanResultsPostsScan(t *testing.T) {
	oldAPIKey := os.Getenv("BASELINE_API_KEY")
	defer os.Setenv("BASELINE_API_KEY", oldAPIKey)
	if err := os.Setenv("BASELINE_API_KEY", "test-key"); err != nil {
		t.Fatalf("set env: %v", err)
	}

	var projectLookupAuth string
	var postedAuth string
	var postedPayload map[string]any
	var postedIdempotency string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			projectLookupAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[{"id":"proj_baseline","name":"Baseline","repository_url":"https://github.com/johndansu/Baseline.git"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/scans":
			postedAuth = r.Header.Get("Authorization")
			postedIdempotency = r.Header.Get("Idempotency-Key")
			if err := json.NewDecoder(r.Body).Decode(&postedPayload); err != nil {
				t.Fatalf("decode posted payload: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan_uploaded","project_id":"proj_baseline"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	results := types.ScanResults{
		FilesScanned: 10,
		Violations: []types.PolicyViolation{
			{PolicyID: types.PolicyNoSecrets, Severity: types.SeverityBlock, Message: "secret found"},
		},
	}

	uploaded, err := uploadScanResults(scanCommandOptions{
		APIBaseURL: server.URL,
		CommitSHA:  "abc123",
	}, results)
	if err != nil {
		t.Fatalf("uploadScanResults returned error: %v", err)
	}

	if uploaded.ProjectID != "proj_baseline" || uploaded.ScanID != "scan_uploaded" {
		t.Fatalf("unexpected uploaded details: %+v", uploaded)
	}
	if projectLookupAuth != "Bearer test-key" || postedAuth != "Bearer test-key" {
		t.Fatalf("expected bearer auth on requests, got lookup=%q post=%q", projectLookupAuth, postedAuth)
	}
	if !strings.HasPrefix(postedIdempotency, "scan-upload:") {
		t.Fatalf("expected idempotency key prefix, got %q", postedIdempotency)
	}
	if postedPayload["project_id"] != "proj_baseline" {
		t.Fatalf("expected project_id proj_baseline, got %#v", postedPayload["project_id"])
	}
	if postedPayload["status"] != "fail" {
		t.Fatalf("expected status fail, got %#v", postedPayload["status"])
	}
}

func TestDefaultScanUploadBaseURL(t *testing.T) {
	t.Setenv("BASELINE_API_KEY", "test-key")
	t.Setenv("BASELINE_API_ADDR", ":9090")
	if got := defaultScanUploadBaseURL(); got != "http://127.0.0.1:9090" {
		t.Fatalf("expected derived base URL, got %q", got)
	}

	t.Setenv("BASELINE_SCAN_API_URL", "https://baseline.example.com")
	if got := defaultScanUploadBaseURL(); got != "https://baseline.example.com" {
		t.Fatalf("expected explicit scan API URL, got %q", got)
	}
}
