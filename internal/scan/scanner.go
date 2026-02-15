// Package scan provides repository scanning functionality.
package scan

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/baseline/baseline/internal/policy"
	"github.com/baseline/baseline/internal/types"
)

var ignoredDirs = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	".idea":        {},
	".vscode":      {},
	"node_modules": {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	"bin":          {},
}

// RunComprehensiveScan performs a full repository scan and returns results.
func RunComprehensiveScan() types.ScanResults {
	results := types.ScanResults{
		Violations: make([]types.PolicyViolation, 0),
	}

	cwd, err := os.Getwd()
	if err == nil {
		_ = filepath.WalkDir(cwd, func(current string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}

			if d.IsDir() {
				if _, skip := ignoredDirs[strings.ToLower(d.Name())]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			rel, relErr := filepath.Rel(cwd, current)
			if relErr != nil {
				return nil
			}

			if shouldCountFile(filepath.ToSlash(rel)) {
				results.FilesScanned++
			}
			return nil
		})
	}

	results.Violations = policy.RunAllChecks()
	if results.Violations == nil {
		results.Violations = []types.PolicyViolation{}
	}

	for _, violation := range results.Violations {
		if strings.HasPrefix(violation.PolicyID, "D") ||
			strings.HasPrefix(violation.PolicyID, "G") ||
			violation.PolicyID == types.PolicySystemError {
			results.SecurityIssues++
		}
	}

	return results
}

func shouldCountFile(file string) bool {
	lower := strings.ToLower(file)
	base := path.Base(lower)

	if strings.HasPrefix(base, ".env") {
		return true
	}

	if base == "dockerfile" || base == "jenkinsfile" || base == "makefile" {
		return true
	}

	switch path.Ext(base) {
	case ".go", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf",
		".md", ".sh", ".txt", ".xml":
		return true
	default:
		return false
	}
}
