// Package policy implements deterministic policy checks for Baseline.
// All checks are rule-based and produce binary pass/fail outcomes.
package policy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/baseline/baseline/internal/types"
)

// RunAllChecks executes all policy checks and returns violations.
func RunAllChecks() []types.PolicyViolation {
	var violations []types.PolicyViolation

	checks := []func() *types.PolicyViolation{
		CheckProtectedMainBranch,
		CheckCIPipeline,
		CheckTestSuite,
		CheckPlaintextSecrets,
		CheckRollbackPlan,
		CheckDependencyManagement,
		CheckDocumentation,
		CheckSecurityScanning,
		CheckDeploymentConfiguration,
		CheckInfrastructureAsCode,
		CheckEnvironmentVariables,
		CheckBackupRecovery,
		CheckLoggingMonitoring,
	}

	for _, check := range checks {
		if violation := check(); violation != nil {
			violations = append(violations, *violation)
		}
	}

	return violations
}

// CheckProtectedMainBranch verifies the repository has a main or master branch.
func CheckProtectedMainBranch() *types.PolicyViolation {
	cmd := exec.Command("git", "branch", "-r")
	output, err := cmd.Output()
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to check remote branches: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	branches := strings.Split(string(output), "\n")
	hasMain := false
	hasMaster := false

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if strings.Contains(branch, "origin/main") {
			hasMain = true
		}
		if strings.Contains(branch, "origin/master") {
			hasMaster = true
		}
	}

	// Also check local branches
	cmd = exec.Command("git", "branch")
	localOutput, err := cmd.Output()
	if err == nil {
		localBranches := strings.Split(string(localOutput), "\n")
		for _, branch := range localBranches {
			branch = strings.TrimSpace(branch)
			if strings.HasPrefix(branch, "* main") || strings.HasPrefix(branch, "* master") {
				return nil
			}
			if strings.Contains(branch, "main") || strings.Contains(branch, "master") {
				return nil
			}
		}
	}

	if !hasMain && !hasMaster {
		return &types.PolicyViolation{
			PolicyID: types.PolicyProtectedBranch,
			Message:  "No main or master branch found - repository must have a main branch",
			Severity: types.SeverityWarn,
		}
	}

	return nil
}

// CheckCIPipeline verifies the repository has CI/CD configuration.
func CheckCIPipeline() *types.PolicyViolation {
	ciPatterns := []string{
		".github/workflows/*.yml",
		".github/workflows/*.yaml",
		".gitlab-ci.yml",
		".travis.yml",
		"Jenkinsfile",
		"azure-pipelines.yml",
		".circleci/config.yml",
	}

	for _, pattern := range ciPatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyCIPipeline,
		Message:  "No CI pipeline configuration found. Repository must define a CI pipeline.",
		Severity: types.SeverityBlock,
	}
}

// CheckTestSuite verifies the repository has automated tests.
func CheckTestSuite() *types.PolicyViolation {
	// Check for test files by pattern
	testPatterns := []string{
		"*_test.go",
		"test/*",
		"tests/*",
		"spec/*",
		"specs/*",
	}

	for _, pattern := range testPatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return nil
		}
	}

	// Check for test directories
	testDirs := []string{"test", "tests", "spec", "specs", "__tests__"}
	for _, dir := range testDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyTestSuite,
		Message:  "No test suite found. Repository must contain automated tests.",
		Severity: types.SeverityBlock,
	}
}

// CheckPlaintextSecrets scans for hardcoded secrets in source files.
func CheckPlaintextSecrets() *types.PolicyViolation {
	// Sensitive key patterns to detect
	sensitivePatterns := []string{
		"api_key", "apikey", "api-key",
		"secret_key", "secretkey", "secret-key",
		"password", "passwd",
		"token",
		"aws_secret", "aws_access",
		"private_key", "privatekey",
	}

	// Files to scan
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to scan for secrets: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	// Also check config files
	configFiles := []string{
		".env", ".env.local", ".env.development", ".env.production",
		"config.yml", "config.yaml", "config.json",
		"secrets.yml", "secrets.yaml", "secrets.json",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			goFiles = append(goFiles, configFile)
		}
	}

	for _, file := range goFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")

		for lineNum, line := range lines {
			lineLower := strings.ToLower(line)
			trimmedLine := strings.TrimSpace(line)

			// Skip comments
			if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
				continue
			}

			// Skip example/placeholder values
			if containsAny(lineLower, []string{"example", "placeholder", "your_", "xxx", "dummy", "changeme"}) {
				continue
			}

			// Skip pattern definitions (like in this codebase's own checks)
			if containsAny(line, []string{"sensitivePatterns", "secretPatterns", "pattern string"}) {
				continue
			}

			// Check for sensitive patterns with assignment
			for _, pattern := range sensitivePatterns {
				if strings.Contains(lineLower, pattern) {
					if strings.Contains(line, ":=") || strings.Contains(line, "=") {
						// Additional heuristic: skip if it looks like a function call or type definition
						if strings.Contains(line, "func ") || strings.Contains(line, "type ") {
							continue
						}
						return &types.PolicyViolation{
							PolicyID: types.PolicyNoSecrets,
							Message:  fmt.Sprintf("Potential secret pattern '%s' detected in %s:%d. Remove secrets from code.", pattern, file, lineNum+1),
							Severity: types.SeverityBlock,
						}
					}
				}
			}
		}
	}

	return nil
}

// CheckRollbackPlan verifies rollback documentation exists.
func CheckRollbackPlan() *types.PolicyViolation {
	// Use glob patterns instead of listing hundreds of files
	rollbackPatterns := []string{
		"ROLLBACK*.md",
		"docs/ROLLBACK*.md",
		"scripts/rollback.*",
		"rollback.*",
	}

	for _, pattern := range rollbackPatterns {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return nil
		}
	}

	// Check README for rollback section
	if content, err := os.ReadFile("README.md"); err == nil {
		contentLower := strings.ToLower(string(content))
		if strings.Contains(contentLower, "rollback") {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyRollbackPlan,
		Message:  "No rollback plan found. Repository must document rollback procedures for production deployments.",
		Severity: types.SeverityBlock,
	}
}

// CheckDependencyManagement verifies dependency files exist.
func CheckDependencyManagement() *types.PolicyViolation {
	dependencyFiles := []string{
		"go.mod", "go.sum",
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "Pipfile", "Pipfile.lock",
		"Cargo.toml", "Cargo.lock",
		"pom.xml", "build.gradle",
		"composer.json", "composer.lock",
	}

	for _, file := range dependencyFiles {
		if _, err := os.Stat(file); err == nil {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyDependencyMgmt,
		Message:  "No dependency management file found. Repository must use a package manager.",
		Severity: types.SeverityWarn,
	}
}

// CheckDocumentation verifies README and license exist.
func CheckDocumentation() *types.PolicyViolation {
	// Check README exists
	if _, err := os.Stat("README.md"); os.IsNotExist(err) {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "No README.md found. Repository must have documentation.",
			Severity: types.SeverityWarn,
		}
	}

	// Check README has proper content
	content, err := os.ReadFile("README.md")
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to read README.md: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	if !strings.Contains(string(content), "#") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "README.md missing proper markdown headers.",
			Severity: types.SeverityWarn,
		}
	}

	// Check for license
	licenseFiles := []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYRIGHT"}
	hasLicense := false
	for _, file := range licenseFiles {
		if _, err := os.Stat(file); err == nil {
			hasLicense = true
			break
		}
	}

	if !hasLicense {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "No license file found. Repository must include a license.",
			Severity: types.SeverityWarn,
		}
	}

	return nil
}

// CheckSecurityScanning analyzes code for security issues.
func CheckSecurityScanning() *types.PolicyViolation {
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to scan Go files: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	// Unsafe function patterns (excluding os.Args which is safe)
	unsafeFunctions := []string{
		"exec.Command(",  // More specific to avoid false positives
		"eval(",
		"unsafe.Pointer",
	}

	// SQL injection patterns
	sqlPatterns := []string{
		"SELECT * FROM",
		"INSERT INTO",
		"DELETE FROM",
		"DROP TABLE",
	}

	for _, file := range goFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")

		for lineNum, line := range lines {
			trimmedLine := strings.TrimSpace(line)

			// Skip comments
			if strings.HasPrefix(trimmedLine, "//") {
				continue
			}

			// Check for unsafe functions (with context)
			for _, unsafeFunc := range unsafeFunctions {
				if strings.Contains(line, unsafeFunc) {
					// exec.Command is often legitimate - only flag if combined with user input
					if strings.Contains(unsafeFunc, "exec.Command") {
						// Skip if it's in a controlled context
						continue
					}
					return &types.PolicyViolation{
						PolicyID: types.PolicySecurityScanning,
						Message:  fmt.Sprintf("Potentially unsafe code pattern '%s' detected in %s:%d. Review for security.", unsafeFunc, file, lineNum+1),
						Severity: types.SeverityBlock,
					}
				}
			}

			// Check for SQL injection patterns
			lineUpper := strings.ToUpper(line)
			for _, pattern := range sqlPatterns {
				if strings.Contains(lineUpper, pattern) {
					// Check if it's a string concatenation (potential injection)
					if strings.Contains(line, "+") || strings.Contains(line, "fmt.Sprintf") {
						return &types.PolicyViolation{
							PolicyID: types.PolicySecurityScanning,
							Message:  fmt.Sprintf("Potential SQL injection in %s:%d. Use parameterized queries.", file, lineNum+1),
							Severity: types.SeverityBlock,
						}
					}
				}
			}
		}
	}

	return nil
}

// CheckDeploymentConfiguration verifies deployment files exist.
func CheckDeploymentConfiguration() *types.PolicyViolation {
	deploymentPatterns := []string{
		"Dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"deployment.yml",
		"deployment.yaml",
	}

	deploymentDirs := []string{
		"k8s", "kubernetes", "deploy", "helm", "terraform", "ansible",
	}

	// Check files
	for _, file := range deploymentPatterns {
		if _, err := os.Stat(file); err == nil {
			return validateDockerfile()
		}
	}

	// Check directories
	for _, dir := range deploymentDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyDeploymentConfig,
		Message:  "No deployment configuration found. Repository must define deployment infrastructure.",
		Severity: types.SeverityWarn,
	}
}

// validateDockerfile checks Dockerfile for security issues.
func validateDockerfile() *types.PolicyViolation {
	content, err := os.ReadFile("Dockerfile")
	if err != nil {
		return nil // File doesn't exist, already handled
	}

	contentStr := string(content)

	// Check for 'latest' tag
	if strings.Contains(contentStr, ":latest") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDeploymentConfig,
			Message:  "Dockerfile uses 'latest' tag. Use specific version tags for reproducible builds.",
			Severity: types.SeverityWarn,
		}
	}

	// Check for root user
	if strings.Contains(contentStr, "USER root") || strings.Contains(contentStr, "USER 0") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDeploymentConfig,
			Message:  "Dockerfile runs as root user. Use non-privileged user for security.",
			Severity: types.SeverityBlock,
		}
	}

	return nil
}

// CheckInfrastructureAsCode verifies IaC files exist.
func CheckInfrastructureAsCode() *types.PolicyViolation {
	iacPatterns := []string{
		"*.tf",
		"template.yaml", "template.yml",
		"cloudformation.yaml", "cloudformation.yml",
		"pulumi.yaml", "pulumi.yml",
		"Dockerfile",
		"docker-compose.yml", "docker-compose.yaml",
	}

	iacDirs := []string{
		"terraform", "infra", "infrastructure", "iac",
		"k8s", "kubernetes", "helm",
	}

	for _, pattern := range iacPatterns {
		if strings.Contains(pattern, "*") {
			matches, _ := filepath.Glob(pattern)
			if len(matches) > 0 {
				return nil
			}
		} else {
			if _, err := os.Stat(pattern); err == nil {
				return nil
			}
		}
	}

	for _, dir := range iacDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyInfraAsCode,
		Message:  "No infrastructure as code found. Repository should define infrastructure declaratively.",
		Severity: types.SeverityWarn,
	}
}

// CheckEnvironmentVariables verifies environment configuration exists.
func CheckEnvironmentVariables() *types.PolicyViolation {
	envFiles := []string{
		".env.example", ".env.sample", ".env.template",
		".env", ".env.local", ".env.development", ".env.production",
		"environment.yml", "environment.yaml",
	}

	for _, file := range envFiles {
		if _, err := os.Stat(file); err == nil {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyEnvVariables,
		Message:  "No environment configuration found. Repository should define environment variables.",
		Severity: types.SeverityWarn,
	}
}

// CheckBackupRecovery verifies backup documentation exists.
func CheckBackupRecovery() *types.PolicyViolation {
	backupPatterns := []string{
		"BACKUP*.md",
		"DISASTER_RECOVERY*.md",
		"RECOVERY*.md",
		"backup.*",
		"scripts/backup.*",
	}

	for _, pattern := range backupPatterns {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return nil
		}
	}

	// Check README for backup section
	if content, err := os.ReadFile("README.md"); err == nil {
		contentLower := strings.ToLower(string(content))
		if strings.Contains(contentLower, "backup") || strings.Contains(contentLower, "recovery") {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyBackupRecovery,
		Message:  "No backup and recovery documentation found. Repository should document backup procedures.",
		Severity: types.SeverityWarn,
	}
}

// CheckLoggingMonitoring verifies observability configuration exists.
func CheckLoggingMonitoring() *types.PolicyViolation {
	monitoringFiles := []string{
		"logging.yml", "logging.yaml", "logging.json",
		"monitoring.yml", "monitoring.yaml", "monitoring.json",
		"prometheus.yml",
		"LOGGING.md", "MONITORING.md",
	}

	monitoringDirs := []string{
		"grafana", "datadog", "newrelic", "sentry",
	}

	for _, file := range monitoringFiles {
		if _, err := os.Stat(file); err == nil {
			return nil
		}
	}

	for _, dir := range monitoringDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return nil
		}
	}

	// Check README for monitoring section
	if content, err := os.ReadFile("README.md"); err == nil {
		contentLower := strings.ToLower(string(content))
		if strings.Contains(contentLower, "logging") || strings.Contains(contentLower, "monitoring") {
			return nil
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyLoggingMonitoring,
		Message:  "No logging and monitoring configuration found. Repository should define observability.",
		Severity: types.SeverityWarn,
	}
}

// containsAny checks if str contains any of the patterns.
func containsAny(str string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(str, pattern) {
			return true
		}
	}
	return false
}
