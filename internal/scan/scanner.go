// Package scan provides repository scanning functionality.
package scan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/baseline/baseline/internal/policy"
	"github.com/baseline/baseline/internal/types"
)

// RunComprehensiveScan performs a full repository scan and returns results.
func RunComprehensiveScan() types.ScanResults {
	results := types.ScanResults{}

	// Count Go files
	goFiles, err := filepath.Glob("*.go")
	if err == nil {
		results.FilesScanned += len(goFiles)
	}

	// Count config files
	configFiles := []string{
		".env", ".env.local", ".env.development", ".env.production",
		"config.yml", "config.yaml", "config.json",
		"secrets.yml", "secrets.yaml", "secrets.json",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			results.FilesScanned++
		}
	}

	// Run all policy checks
	results.Violations = policy.RunAllChecks()

	// Count security issues
	for _, violation := range results.Violations {
		if strings.HasPrefix(violation.PolicyID, "D") || 
		   strings.HasPrefix(violation.PolicyID, "G") ||
		   violation.PolicyID == types.PolicySystemError {
			results.SecurityIssues++
		}
	}

	return results
}
