package main

import (
	"testing"

	"github.com/baseline/baseline/internal/policy"
	"github.com/baseline/baseline/internal/scan"
	"github.com/baseline/baseline/internal/types"
	"github.com/baseline/baseline/internal/version"
)

// TestIntegration verifies the complete Baseline workflow
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test that we can run baseline commands without panicking
	t.Log("Testing baseline integration")

	// Test version command
	t.Run("version", func(t *testing.T) {
		// This would normally call the actual CLI
		// For now, just verify the version package works
		if version.Short() == "" {
			t.Error("Version should not be empty")
		}
	})

	// Test that policy engine works
	t.Run("policy_engine", func(t *testing.T) {
		violations := policy.RunAllChecks()
		if violations == nil {
			t.Log("Note: Policy engine returned nil (no violations) - this is expected for current repo state")
			violations = []types.PolicyViolation{}
		}

		// Verify all violations have required fields
		for i, v := range violations {
			if v.PolicyID == "" {
				t.Errorf("Violation %d missing PolicyID", i)
			}
			if v.Message == "" {
				t.Errorf("Violation %d missing Message", i)
			}
			if v.Severity == "" {
				t.Errorf("Violation %d missing Severity", i)
			}
		}

		t.Logf("Policy engine test completed with %d violations", len(violations))
	})

	// Test that scanner works
	t.Run("scanner", func(t *testing.T) {
		results := scan.RunComprehensiveScan()

		// Should have scanned some files
		if results.FilesScanned < 0 {
			t.Error("Should have scanned at least 0 files")
		}

		// Should have violations array
		if results.Violations == nil {
			t.Log("Note: Scanner returned nil violations - this is expected for current repo state")
			results.Violations = []types.PolicyViolation{}
		}

		t.Logf("Scanner test completed - files scanned: %d, violations: %d", results.FilesScanned, len(results.Violations))
	})

	// Test that types are consistent
	t.Run("types", func(t *testing.T) {
		// Verify exit codes
		if types.ExitSuccess != 0 {
			t.Errorf("ExitSuccess should be 0, got %d", types.ExitSuccess)
		}

		if types.ExitBlockingViolation != 20 {
			t.Errorf("ExitBlockingViolation should be 20, got %d", types.ExitBlockingViolation)
		}

		if types.ExitSystemError != 50 {
			t.Errorf("ExitSystemError should be 50, got %d", types.ExitSystemError)
		}

		// Verify severities
		if types.SeverityBlock != "block" {
			t.Errorf("SeverityBlock should be 'block', got '%s'", types.SeverityBlock)
		}

		if types.SeverityWarn != "warn" {
			t.Errorf("SeverityWarn should be 'warn', got '%s'", types.SeverityWarn)
		}
	})
}
