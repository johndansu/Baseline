package main

import (
	"os"
	"testing"
)

func TestPrintUsage(t *testing.T) {
	// Capture stdout to test printUsage
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	w.Close()
	os.Stdout = oldStdout

	// For now, just verify function runs without panic
	// In a full test suite, we'd capture and verify output
}

func TestPolicyViolation(t *testing.T) {
	violation := PolicyViolation{
		policyID: "TEST",
		message:  "Test violation",
		severity: "block",
	}

	if violation.policyID != "TEST" {
		t.Errorf("Expected policyID 'TEST', got '%s'", violation.policyID)
	}

	if violation.message != "Test violation" {
		t.Errorf("Expected message 'Test violation', got '%s'", violation.message)
	}

	if violation.severity != "block" {
		t.Errorf("Expected severity 'block', got '%s'", violation.severity)
	}
}
