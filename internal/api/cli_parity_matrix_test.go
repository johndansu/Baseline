package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/report"
	"github.com/baseline/baseline/internal/types"
)

type parityFixture struct {
	id         string
	status     string
	projectID  string
	commitSHA  string
	violations []ScanViolation
}

func TestCLIDashboardParityMatrix(t *testing.T) {
	fixtures := []parityFixture{
		{
			id:        "FX-01",
			status:    "pass",
			projectID: "proj_fx_01",
			commitSHA: "fx-01-clean",
		},
		{
			id:        "FX-02",
			status:    "fail",
			projectID: "proj_fx_02",
			commitSHA: "fx-02-secrets",
			violations: []ScanViolation{
				{
					PolicyID: types.PolicyNoSecrets,
					Severity: types.SeverityBlock,
					Message:  "Potential secret detected in src/config.go:12. Remove plaintext secrets from code and config.",
				},
			},
		},
		{
			id:        "FX-06",
			status:    "fail",
			projectID: "proj_fx_06",
			commitSHA: "fx-06-multi",
			violations: []ScanViolation{
				{
					PolicyID: types.PolicyTestSuite,
					Severity: types.SeverityBlock,
					Message:  "No test suite found. Repository must contain automated tests.",
				},
				{
					PolicyID: types.PolicyNoSecrets,
					Severity: types.SeverityBlock,
					Message:  "Potential secret detected in app/settings.py:31. Remove plaintext secrets from code and config.",
				},
				{
					PolicyID: types.PolicyEnvVariables,
					Severity: types.SeverityBlock,
					Message:  "No environment variable template found. Repository must document required environment variables.",
				},
			},
		},
		{
			id:        "FX-03",
			status:    "fail",
			projectID: "proj_fx_03",
			commitSHA: "fx-03-missing-tests",
			violations: []ScanViolation{
				{
					PolicyID: types.PolicyTestSuite,
					Severity: types.SeverityBlock,
					Message:  "No test suite found. Repository must contain automated tests.",
				},
			},
		},
		{
			id:        "FX-04",
			status:    "fail",
			projectID: "proj_fx_04",
			commitSHA: "fx-04-missing-env-template",
			violations: []ScanViolation{
				{
					PolicyID: types.PolicyEnvVariables,
					Severity: types.SeverityBlock,
					Message:  "No environment variable template found. Repository must document required environment variables.",
				},
			},
		},
		{
			id:        "FX-05",
			status:    "pass",
			projectID: "proj_fx_05",
			commitSHA: "fx-05-docker-latest-warn",
			violations: []ScanViolation{
				{
					PolicyID: types.PolicyDeploymentConfig,
					Severity: types.SeverityWarn,
					Message:  "Dockerfile uses the latest tag. Use specific version tags for reproducible builds.",
				},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}
	headers := map[string]string{"Authorization": "Bearer admin-key"}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.id, func(t *testing.T) {
			resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
				"id":   fx.projectID,
				"name": "parity-" + strings.ToLower(fx.id),
			}, headers)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("%s: expected project create 201, got %d body=%s", fx.id, resp.StatusCode, body)
			}

			resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
				"id":         "scan-" + strings.ToLower(fx.id),
				"project_id": fx.projectID,
				"commit_sha": fx.commitSHA,
				"status":     fx.status,
				"violations": fx.violations,
			}, headers)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("%s: expected scan create 201, got %d body=%s", fx.id, resp.StatusCode, body)
			}

			var created ScanSummary
			if err := json.Unmarshal([]byte(body), &created); err != nil {
				t.Fatalf("%s: failed to decode created scan: %v body=%s", fx.id, err, body)
			}

			cliResults := types.ScanResults{
				Violations: toPolicyViolations(fx.violations),
			}

			// Compare JSON report parity.
			cliJSON, err := captureCLIJSON(t, cliResults)
			if err != nil {
				t.Fatalf("%s: captureCLIJSON returned error: %v", fx.id, err)
			}
			resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+created.ID+"/report?format=json", nil, headers)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: expected API JSON report 200, got %d body=%s", fx.id, resp.StatusCode, body)
			}
			assertNormalizedViolationsEqual(t, fx.id, extractCLIJSONViolations(t, cliJSON), extractAPIJSONViolations(t, []byte(body)))

			// Compare text report parity via normalized violation entries.
			cliText := captureCLIText(t, cliResults)
			resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+created.ID+"/report?format=text", nil, headers)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: expected API text report 200, got %d body=%s", fx.id, resp.StatusCode, body)
			}
			assertTextContainsViolations(t, fx.id, cliText, body, cliResults.Violations)

			// Compare SARIF parity for findings.
			cliSARIF, err := captureCLISARIF(t, cliResults)
			if err != nil {
				t.Fatalf("%s: captureCLISARIF returned error: %v", fx.id, err)
			}
			resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+created.ID+"/report?format=sarif", nil, headers)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: expected API SARIF report 200, got %d body=%s", fx.id, resp.StatusCode, body)
			}
			cliFindings := extractSARIFFindings(t, cliSARIF)
			apiFindings := extractSARIFFindings(t, []byte(body))
			sort.Strings(cliFindings)
			sort.Strings(apiFindings)
			if strings.Join(cliFindings, "\n") != strings.Join(apiFindings, "\n") {
				t.Fatalf("%s: SARIF parity mismatch\nCLI:\n%s\nAPI:\n%s", fx.id, strings.Join(cliFindings, "\n"), strings.Join(apiFindings, "\n"))
			}

			// Compare blocking semantics parity (CLI exit intent vs API scan status).
			hasBlocking := hasBlockingViolation(cliResults.Violations)
			expectedStatus := "pass"
			if hasBlocking {
				expectedStatus = "fail"
			}
			if created.Status != expectedStatus {
				t.Fatalf("%s: expected API status %q for blocking=%v, got %q", fx.id, expectedStatus, hasBlocking, created.Status)
			}
		})
	}
}

func TestCLIDashboardParityPolicyCatalogFX07(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}
	headers := map[string]string{"Authorization": "Bearer admin-key"}

	policyIDs := knownPolicyIDs()
	for _, policyID := range policyIDs {
		resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/policies/"+policyID+"/versions", map[string]any{
			"version":     "v1",
			"description": "parity catalog seed",
			"content": map[string]any{
				"policy_id": policyID,
			},
			"metadata": map[string]any{
				"source": "parity_test",
			},
		}, headers)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("FX-07: expected 201 creating policy %s, got %d body=%s", policyID, resp.StatusCode, body)
		}
	}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/policies", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FX-07: expected 200 for policy list, got %d body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Policies []PolicySummary `json:"policies"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("FX-07: failed to decode policy list payload: %v body=%s", err, body)
	}
	got := map[string]struct{}{}
	for _, item := range payload.Policies {
		got[strings.TrimSpace(item.Name)] = struct{}{}
	}
	for _, policyID := range policyIDs {
		if _, ok := got[policyID]; !ok {
			t.Fatalf("FX-07: expected policy %s in catalog, got=%v", policyID, got)
		}
	}
}

func TestCLIDashboardParityReportFormatsFX08(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}
	headers := map[string]string{"Authorization": "Bearer admin-key"}

	const projectID = "proj_fx_08"
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   projectID,
		"name": "parity-fx08",
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("FX-08: expected 201 creating project, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"id":         "scan-fx-08",
		"project_id": projectID,
		"commit_sha": "fx-08-report-format",
		"status":     "fail",
		"violations": []ScanViolation{
			{
				PolicyID: types.PolicyNoSecrets,
				Severity: types.SeverityBlock,
				Message:  "Potential secret detected in service/config.ts:14. Remove plaintext secrets from code and config.",
			},
		},
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("FX-08: expected 201 creating scan, got %d body=%s", resp.StatusCode, body)
	}

	var scan ScanSummary
	if err := json.Unmarshal([]byte(body), &scan); err != nil {
		t.Fatalf("FX-08: failed to decode created scan payload: %v body=%s", err, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+scan.ID+"/report?format=json", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FX-08: expected 200 for JSON report, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); !strings.Contains(got, "application/json") {
		t.Fatalf("FX-08: expected JSON content type, got %q", got)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(strings.ToLower(got), ".json") {
		t.Fatalf("FX-08: expected JSON content-disposition with .json filename, got %q", got)
	}
	if len(extractAPIJSONViolations(t, []byte(body))) != 1 {
		t.Fatalf("FX-08: expected 1 JSON violation entry, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+scan.ID+"/report?format=text", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FX-08: expected 200 for text report, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); !strings.Contains(got, "text/plain") {
		t.Fatalf("FX-08: expected text/plain content type, got %q", got)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(strings.ToLower(got), ".txt") {
		t.Fatalf("FX-08: expected text content-disposition with .txt filename, got %q", got)
	}
	if !strings.Contains(body, "scan_id: "+scan.ID) || !strings.Contains(body, "violations: 1") {
		t.Fatalf("FX-08: text report missing required sections, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+scan.ID+"/report?format=sarif", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FX-08: expected 200 for SARIF report, got %d body=%s", resp.StatusCode, body)
	}
	if got := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); !strings.Contains(got, "application/sarif+json") {
		t.Fatalf("FX-08: expected SARIF content type, got %q", got)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(strings.ToLower(got), ".sarif") {
		t.Fatalf("FX-08: expected SARIF content-disposition with .sarif filename, got %q", got)
	}
	findings := extractSARIFFindings(t, []byte(body))
	if len(findings) != 1 {
		t.Fatalf("FX-08: expected 1 SARIF finding, got %d findings=%v", len(findings), findings)
	}
}

func captureCLIJSON(t *testing.T, results types.ScanResults) ([]byte, error) {
	t.Helper()
	return captureStdoutBytes(t, func() error {
		return report.OutputJSON(results)
	})
}

func captureCLISARIF(t *testing.T, results types.ScanResults) ([]byte, error) {
	t.Helper()
	return captureStdoutBytes(t, func() error {
		return report.OutputSARIF(results)
	})
}

func captureCLIText(t *testing.T, results types.ScanResults) string {
	t.Helper()
	data, err := captureStdoutBytes(t, func() error {
		report.OutputText(results)
		return nil
	})
	if err != nil {
		t.Fatalf("captureCLIText failed: %v", err)
	}
	return string(data)
}

func captureStdoutBytes(t *testing.T, fn func() error) ([]byte, error) {
	t.Helper()
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = originalStdout
	if runErr != nil {
		return nil, runErr
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func toPolicyViolations(in []ScanViolation) []types.PolicyViolation {
	out := make([]types.PolicyViolation, 0, len(in))
	for _, item := range in {
		out = append(out, types.PolicyViolation{
			PolicyID: strings.TrimSpace(item.PolicyID),
			Message:  strings.TrimSpace(item.Message),
			Severity: strings.ToLower(strings.TrimSpace(item.Severity)),
		})
	}
	return out
}

func extractCLIJSONViolations(t *testing.T, data []byte) []ScanViolation {
	t.Helper()
	var payload struct {
		Violations []struct {
			PolicyID string `json:"policy_id"`
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"violations"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to decode CLI JSON report: %v body=%s", err, string(data))
	}
	out := make([]ScanViolation, 0, len(payload.Violations))
	for _, item := range payload.Violations {
		out = append(out, ScanViolation{
			PolicyID: strings.TrimSpace(item.PolicyID),
			Message:  strings.TrimSpace(item.Message),
			Severity: strings.ToLower(strings.TrimSpace(item.Severity)),
		})
	}
	return out
}

func extractAPIJSONViolations(t *testing.T, data []byte) []ScanViolation {
	t.Helper()
	var payload struct {
		Scan struct {
			Violations []ScanViolation `json:"violations"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to decode API JSON scan report: %v body=%s", err, string(data))
	}
	out := make([]ScanViolation, 0, len(payload.Scan.Violations))
	for _, item := range payload.Scan.Violations {
		out = append(out, ScanViolation{
			PolicyID: strings.TrimSpace(item.PolicyID),
			Message:  strings.TrimSpace(item.Message),
			Severity: strings.ToLower(strings.TrimSpace(item.Severity)),
		})
	}
	return out
}

func assertNormalizedViolationsEqual(t *testing.T, fixtureID string, expected, actual []ScanViolation) {
	t.Helper()
	expectedNorm := normalizeViolationSet(expected)
	actualNorm := normalizeViolationSet(actual)
	if strings.Join(expectedNorm, "\n") != strings.Join(actualNorm, "\n") {
		t.Fatalf("%s: JSON parity mismatch\nCLI:\n%s\nAPI:\n%s", fixtureID, strings.Join(expectedNorm, "\n"), strings.Join(actualNorm, "\n"))
	}
}

func normalizeViolationSet(in []ScanViolation) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		out = append(out, fmt.Sprintf("%s|%s|%s",
			strings.TrimSpace(item.PolicyID),
			strings.ToLower(strings.TrimSpace(item.Severity)),
			strings.TrimSpace(item.Message),
		))
	}
	sort.Strings(out)
	return out
}

func assertTextContainsViolations(t *testing.T, fixtureID, cliText, apiText string, violations []types.PolicyViolation) {
	t.Helper()
	for _, v := range violations {
		token := fmt.Sprintf("[%s] %s (%s)", strings.TrimSpace(v.PolicyID), strings.TrimSpace(v.Message), strings.ToLower(strings.TrimSpace(v.Severity)))
		if !strings.Contains(cliText, token) {
			t.Fatalf("%s: CLI text report missing token %q\nCLI report:\n%s", fixtureID, token, cliText)
		}
		if !strings.Contains(apiText, token) {
			t.Fatalf("%s: API text report missing token %q\nAPI report:\n%s", fixtureID, token, apiText)
		}
	}
}

func extractSARIFFindings(t *testing.T, data []byte) []string {
	t.Helper()
	var payload struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to decode SARIF payload: %v body=%s", err, string(data))
	}
	findings := make([]string, 0, 16)
	for _, run := range payload.Runs {
		for _, result := range run.Results {
			findings = append(findings, fmt.Sprintf("%s|%s|%s",
				strings.TrimSpace(result.RuleID),
				strings.ToLower(strings.TrimSpace(result.Level)),
				strings.TrimSpace(result.Message.Text),
			))
		}
	}
	return findings
}

func hasBlockingViolation(violations []types.PolicyViolation) bool {
	for _, v := range violations {
		if strings.EqualFold(strings.TrimSpace(v.Severity), types.SeverityBlock) {
			return true
		}
	}
	return false
}

func knownPolicyIDs() []string {
	return []string{
		types.PolicyProtectedBranch,
		types.PolicyCIPipeline,
		types.PolicyTestSuite,
		types.PolicyNoSecrets,
		types.PolicyDependencyMgmt,
		types.PolicyDocumentation,
		types.PolicySecurityScanning,
		types.PolicyDeploymentConfig,
		types.PolicyInfraAsCode,
		types.PolicyEnvVariables,
		types.PolicyBackupRecovery,
		types.PolicyLoggingMonitoring,
		types.PolicyRollbackPlan,
	}
}
