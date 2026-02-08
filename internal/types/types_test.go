package types

import "testing"

func TestPolicyViolation(t *testing.T) {
	v := PolicyViolation{
		PolicyID: PolicyCIPipeline,
		Message:  "No CI pipeline found",
		Severity: SeverityBlock,
	}

	if v.PolicyID != "B1" {
		t.Errorf("Expected PolicyID 'B1', got '%s'", v.PolicyID)
	}

	if v.Severity != "block" {
		t.Errorf("Expected Severity 'block', got '%s'", v.Severity)
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityBlock != "block" {
		t.Errorf("Expected SeverityBlock to be 'block', got '%s'", SeverityBlock)
	}

	if SeverityWarn != "warn" {
		t.Errorf("Expected SeverityWarn to be 'warn', got '%s'", SeverityWarn)
	}
}

func TestExitCodes(t *testing.T) {
	if ExitSuccess != 0 {
		t.Errorf("Expected ExitSuccess to be 0, got %d", ExitSuccess)
	}

	if ExitBlockingViolation != 20 {
		t.Errorf("Expected ExitBlockingViolation to be 20, got %d", ExitBlockingViolation)
	}

	if ExitSystemError != 50 {
		t.Errorf("Expected ExitSystemError to be 50, got %d", ExitSystemError)
	}
}

func TestPolicyIDConstants(t *testing.T) {
	testCases := []struct {
		name     string
		constant string
		expected string
	}{
		{"PolicyProtectedBranch", PolicyProtectedBranch, "A1"},
		{"PolicyCIPipeline", PolicyCIPipeline, "B1"},
		{"PolicyTestSuite", PolicyTestSuite, "C1"},
		{"PolicyNoSecrets", PolicyNoSecrets, "D1"},
		{"PolicyDependencyMgmt", PolicyDependencyMgmt, "E1"},
		{"PolicyDocumentation", PolicyDocumentation, "F1"},
		{"PolicySecurityScanning", PolicySecurityScanning, "G1"},
		{"PolicyDeploymentConfig", PolicyDeploymentConfig, "H1"},
		{"PolicyInfraAsCode", PolicyInfraAsCode, "I1"},
		{"PolicyEnvVariables", PolicyEnvVariables, "J1"},
		{"PolicyBackupRecovery", PolicyBackupRecovery, "K1"},
		{"PolicyLoggingMonitoring", PolicyLoggingMonitoring, "L1"},
		{"PolicyRollbackPlan", PolicyRollbackPlan, "R1"},
		{"PolicySystemError", PolicySystemError, "SYSTEM_ERROR"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("Expected %s to be '%s', got '%s'", tc.name, tc.expected, tc.constant)
			}
		})
	}
}

func TestScanResults(t *testing.T) {
	results := ScanResults{
		FilesScanned:   10,
		SecurityIssues: 2,
		Violations: []PolicyViolation{
			{PolicyID: "A1", Message: "Test", Severity: SeverityWarn},
			{PolicyID: "B1", Message: "Test2", Severity: SeverityBlock},
		},
	}

	if results.FilesScanned != 10 {
		t.Errorf("Expected FilesScanned 10, got %d", results.FilesScanned)
	}

	if len(results.Violations) != 2 {
		t.Errorf("Expected 2 violations, got %d", len(results.Violations))
	}
}
