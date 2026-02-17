// Package report provides report generation in multiple formats.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/baseline/baseline/internal/types"
)

// JSONReport represents the JSON output format.
type JSONReport struct {
	Repository     string            `json:"repository"`
	FilesScanned   int               `json:"files_scanned"`
	SecurityIssues int               `json:"security_issues"`
	Violations     []ViolationReport `json:"violations"`
}

// ViolationReport represents a single violation in the report.
type ViolationReport struct {
	PolicyID string `json:"policy_id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

var messageLocationPattern = regexp.MustCompile(` in ([^:\s]+):([0-9]+)\b`)

// OutputJSON generates a JSON report to stdout.
func OutputJSON(results types.ScanResults) error {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "unknown"
	}

	report := JSONReport{
		Repository:     filepath.Base(cwd),
		FilesScanned:   results.FilesScanned,
		SecurityIssues: results.SecurityIssues,
		Violations:     make([]ViolationReport, len(results.Violations)),
	}

	for i, v := range results.Violations {
		report.Violations[i] = ViolationReport{
			PolicyID: v.PolicyID,
			Message:  v.Message,
			Severity: v.Severity,
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// OutputSARIF generates a SARIF report to stdout.
func OutputSARIF(results types.ScanResults) error {
	rulesByID := map[string]sarifRule{}
	sarifResults := make([]sarifResult, 0, len(results.Violations))

	for _, violation := range results.Violations {
		if _, exists := rulesByID[violation.PolicyID]; !exists {
			rulesByID[violation.PolicyID] = sarifRule{
				ID: violation.PolicyID,
				ShortDescription: sarifText{
					Text: violation.PolicyID + " policy violation",
				},
				Properties: map[string]string{
					"severity": violation.Severity,
				},
			}
		}

		result := sarifResult{
			RuleID:  violation.PolicyID,
			Level:   sarifLevel(violation.Severity),
			Message: sarifText{Text: violation.Message},
		}

		if uri, line, ok := parseViolationLocation(violation.Message); ok {
			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}
			if line > 0 {
				location.PhysicalLocation.Region = &sarifRegion{StartLine: line}
			}
			result.Locations = []sarifLocation{location}
		}

		sarifResults = append(sarifResults, result)
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Baseline",
						InformationURI: "https://github.com/baseline/baseline",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// OutputText generates a human-readable text report to stdout.
func OutputText(results types.ScanResults) {
	cwd, err := os.Getwd()
	repoName := "unknown"
	if err == nil {
		repoName = filepath.Base(cwd)
	}

	fmt.Printf("Repository: %s\n", repoName)
	fmt.Printf("Files scanned: %d\n", results.FilesScanned)
	fmt.Printf("Security issues: %d\n", results.SecurityIssues)
	fmt.Printf("Policy violations: %d\n", len(results.Violations))

	if len(results.Violations) > 0 {
		fmt.Println("Violations:")
		for _, v := range results.Violations {
			fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
		}
	} else {
		fmt.Println("No violations found")
	}
}

// GeneratePRBody creates a pull request description for generated scaffolds.
func GeneratePRBody(violations []types.PolicyViolation, files []string) string {
	body := "## Baseline Production Infrastructure\n\n"
	body += "This PR adds missing production infrastructure identified by Baseline.\n\n"

	body += "### Violations Fixed:\n"
	for _, v := range violations {
		body += fmt.Sprintf("- **[%s]** %s (%s)\n", v.PolicyID, v.Message, v.Severity)
	}

	body += "\n### Files Generated:\n"
	for _, file := range files {
		body += fmt.Sprintf("- `%s`\n", file)
	}

	body += "\n### Review Notes:\n"
	body += "- All generated files are AI-scaffolded and require human review\n"
	body += "- Test the CI pipeline to ensure it works correctly\n"
	body += "- Verify environment variables match your setup\n"
	body += "- Update documentation as needed\n"

	body += "\n---\n"
	body += "Generated by Baseline - Production Policy & Enforcement Engine"

	return body
}

// GetRemediationAdvice returns guidance for fixing a specific policy violation.
func GetRemediationAdvice(policyID string) string {
	remediationMap := map[string]string{
		types.PolicyProtectedBranch:   "Create a main branch and protect it from direct pushes",
		types.PolicyCIPipeline:        "Add a CI pipeline configuration (.github/workflows/ci.yml)",
		types.PolicyTestSuite:         "Create automated tests in *_test.go files",
		types.PolicyNoSecrets:         "Remove secrets and use environment variables or vault",
		types.PolicyDependencyMgmt:    "Add go.mod and go.sum files for dependency management",
		types.PolicyDocumentation:     "Create README.md with project documentation",
		types.PolicySecurityScanning:  "Replace unsafe functions with safer alternatives",
		types.PolicyDeploymentConfig:  "Add deployment configuration (Dockerfile, k8s, etc.)",
		types.PolicyInfraAsCode:       "Add infrastructure as code (Terraform, CloudFormation)",
		types.PolicyEnvVariables:      "Create .env.example with environment variable documentation",
		types.PolicyBackupRecovery:    "Create backup and recovery documentation",
		types.PolicyLoggingMonitoring: "Add logging and monitoring configuration",
		types.PolicyRollbackPlan:      "Create rollback plan documentation (ROLLBACK.md or scripts/rollback.sh)",
	}

	if advice, exists := remediationMap[policyID]; exists {
		return advice
	}
	return "Remediation advice not available for this policy"
}

func sarifLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case strings.ToLower(types.SeverityBlock):
		return "error"
	case strings.ToLower(types.SeverityWarn):
		return "warning"
	default:
		return "note"
	}
}

func parseViolationLocation(message string) (string, int, bool) {
	matches := messageLocationPattern.FindStringSubmatch(strings.TrimSpace(message))
	if len(matches) != 3 {
		return "", 0, false
	}
	line, err := strconv.Atoi(matches[2])
	if err != nil || line <= 0 {
		return filepath.ToSlash(matches[1]), 0, true
	}
	return filepath.ToSlash(matches[1]), line, true
}
