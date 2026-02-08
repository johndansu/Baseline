package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/types"
)

func TestGetRemediationAdvice(t *testing.T) {
	testCases := []struct {
		policyID string
		contains string
	}{
		{types.PolicyProtectedBranch, "main branch"},
		{types.PolicyCIPipeline, "CI pipeline"},
		{types.PolicyTestSuite, "tests"},
		{types.PolicyNoSecrets, "secrets"},
		{types.PolicyDocumentation, "README"},
		{types.PolicyRollbackPlan, "rollback"},
		{"UNKNOWN", "not available"},
	}

	for _, tc := range testCases {
		t.Run(tc.policyID, func(t *testing.T) {
			advice := GetRemediationAdvice(tc.policyID)
			if !strings.Contains(strings.ToLower(advice), strings.ToLower(tc.contains)) {
				t.Errorf("Expected advice for %s to contain '%s', got: %s",
					tc.policyID, tc.contains, advice)
			}
		})
	}
}

func TestGeneratePRBody(t *testing.T) {
	violations := []types.PolicyViolation{
		{PolicyID: "B1", Message: "No CI", Severity: types.SeverityBlock},
		{PolicyID: "C1", Message: "No tests", Severity: types.SeverityWarn},
	}
	files := []string{".github/workflows/ci.yml", "main_test.go"}

	body := GeneratePRBody(violations, files)

	// Check required sections
	if !strings.Contains(body, "Baseline Production Infrastructure") {
		t.Error("PR body missing title section")
	}
	if !strings.Contains(body, "[B1]") {
		t.Error("PR body missing violation B1")
	}
	if !strings.Contains(body, "[C1]") {
		t.Error("PR body missing violation C1")
	}
	if !strings.Contains(body, ".github/workflows/ci.yml") {
		t.Error("PR body missing CI file")
	}
	if !strings.Contains(body, "human review") {
		t.Error("PR body missing human review note")
	}
}

func TestJSONReportFormat(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := types.ScanResults{
		FilesScanned:   5,
		SecurityIssues: 1,
		Violations: []types.PolicyViolation{
			{PolicyID: "B1", Message: "No CI", Severity: types.SeverityBlock},
		},
	}

	err := OutputJSON(results)
	
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("OutputJSON returned error: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify it's valid JSON
	var report JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("OutputJSON produced invalid JSON: %v\nOutput: %s", err, output)
	}

	// Verify content
	if report.FilesScanned != 5 {
		t.Errorf("Expected FilesScanned 5, got %d", report.FilesScanned)
	}
	if report.SecurityIssues != 1 {
		t.Errorf("Expected SecurityIssues 1, got %d", report.SecurityIssues)
	}
	if len(report.Violations) != 1 {
		t.Errorf("Expected 1 violation, got %d", len(report.Violations))
	}
	if report.Violations[0].PolicyID != "B1" {
		t.Errorf("Expected violation PolicyID 'B1', got '%s'", report.Violations[0].PolicyID)
	}
}

func TestViolationReport(t *testing.T) {
	vr := ViolationReport{
		PolicyID: "A1",
		Message:  "Test message",
		Severity: "warn",
	}

	// Test JSON marshaling
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatalf("Failed to marshal ViolationReport: %v", err)
	}

	var unmarshaled ViolationReport
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal ViolationReport: %v", err)
	}

	if unmarshaled.PolicyID != vr.PolicyID {
		t.Errorf("PolicyID mismatch: got %s, want %s", unmarshaled.PolicyID, vr.PolicyID)
	}
}
