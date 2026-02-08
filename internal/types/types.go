// Package types defines shared data structures used across Baseline.
package types

// PolicyViolation represents a single policy check failure.
type PolicyViolation struct {
	PolicyID string
	Message  string
	Severity string
}

// ScanResults holds the complete results of a repository scan.
type ScanResults struct {
	FilesScanned   int
	SecurityIssues int
	Violations     []PolicyViolation
}

// Severity levels for policy violations.
const (
	SeverityBlock = "block"
	SeverityWarn  = "warn"
)

// Exit codes for CLI commands.
const (
	ExitSuccess          = 0
	ExitBlockingViolation = 20
	ExitSystemError      = 50
)

// Policy IDs as constants for type safety.
const (
	PolicyProtectedBranch    = "A1"
	PolicyCIPipeline         = "B1"
	PolicyTestSuite          = "C1"
	PolicyNoSecrets          = "D1"
	PolicyDependencyMgmt     = "E1"
	PolicyDocumentation      = "F1"
	PolicySecurityScanning   = "G1"
	PolicyDeploymentConfig   = "H1"
	PolicyInfraAsCode        = "I1"
	PolicyEnvVariables       = "J1"
	PolicyBackupRecovery     = "K1"
	PolicyLoggingMonitoring  = "L1"
	PolicyRollbackPlan       = "R1"
	PolicySystemError        = "SYSTEM_ERROR"
)
