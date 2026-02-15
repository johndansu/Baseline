package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCLIHelpOutput(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/baseline", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected help command to succeed, got error: %v\noutput: %s", err, string(output))
	}

	help := string(output)
	requiredSections := []string{
		"baseline - Production Policy & Enforcement Engine",
		"Usage:",
		"Commands:",
		"Exit Codes:",
	}

	for _, section := range requiredSections {
		if !strings.Contains(help, section) {
			t.Fatalf("help output missing section %q\noutput: %s", section, help)
		}
	}
}
