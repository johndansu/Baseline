// Package policy implements deterministic policy checks for Baseline.
// All checks are rule-based and produce binary pass/fail outcomes.
package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/baseline/baseline/internal/types"
)

const maxScannableFileSize = 1 << 20 // 1 MiB

var (
	ignoredDirs = map[string]struct{}{
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

	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*["']?([^\s"'#]+)`)
	knownTokenPattern       = regexp.MustCompile(`(?i)\b(ghp_[a-z0-9]{36}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b`)
	sqlKeywordPattern       = regexp.MustCompile(`(?i)\b(select|insert|update|delete|drop)\b`)
)

type repoSnapshot struct {
	root     string
	files    []string
	lowerSet map[string]struct{}
}

// RunAllChecks executes all policy checks and returns violations.
func RunAllChecks() []types.PolicyViolation {
	cwd, err := os.Getwd()
	if err != nil {
		return []types.PolicyViolation{
			{
				PolicyID: types.PolicySystemError,
				Message:  fmt.Sprintf("Unable to determine current directory: %v", err),
				Severity: types.SeverityBlock,
			},
		}
	}

	snapshot, err := buildRepoSnapshot(cwd)
	if err != nil {
		return []types.PolicyViolation{
			{
				PolicyID: types.PolicySystemError,
				Message:  fmt.Sprintf("Unable to scan repository files: %v", err),
				Severity: types.SeverityBlock,
			},
		}
	}

	checks := []func(repoSnapshot) *types.PolicyViolation{
		checkProtectedMainBranch,
		checkCIPipeline,
		checkTestSuite,
		checkPlaintextSecrets,
		checkRollbackPlan,
		checkDependencyManagement,
		checkDocumentation,
		checkSecurityScanning,
		checkDeploymentConfiguration,
		checkInfrastructureAsCode,
		checkEnvironmentVariables,
		checkBackupRecovery,
		checkLoggingMonitoring,
	}

	violations := make([]types.PolicyViolation, 0, len(checks))
	for _, check := range checks {
		if violation := check(snapshot); violation != nil {
			violations = append(violations, *violation)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].PolicyID == violations[j].PolicyID {
			return violations[i].Message < violations[j].Message
		}
		return violations[i].PolicyID < violations[j].PolicyID
	})

	return violations
}

// CheckProtectedMainBranch verifies the repository has a main or master branch.
func CheckProtectedMainBranch() *types.PolicyViolation {
	return runSnapshotCheck(checkProtectedMainBranch)
}

func checkProtectedMainBranch(_ repoSnapshot) *types.PolicyViolation {
	branches, err := listGitBranches()
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to check git branches: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	primaryBranch := ""
	for _, branch := range branches {
		normalized := strings.ToLower(strings.TrimSpace(branch))
		normalized = strings.TrimPrefix(normalized, "* ")
		if normalized == "" {
			continue
		}

		if normalized == "main" || normalized == "master" ||
			strings.HasSuffix(normalized, "/main") || strings.HasSuffix(normalized, "/master") {
			if strings.Contains(normalized, "master") {
				primaryBranch = "master"
			} else {
				primaryBranch = "main"
			}
			break
		}
	}

	if primaryBranch == "" {
		return &types.PolicyViolation{
			PolicyID: types.PolicyProtectedBranch,
			Message:  "No main or master branch found - repository must include a protected primary branch",
			Severity: types.SeverityBlock,
		}
	}

	protected, err := verifyProtectedBranchRequirement(primaryBranch)
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to verify branch protection requirements: %v", err),
			Severity: types.SeverityBlock,
		}
	}
	if !protected {
		return &types.PolicyViolation{
			PolicyID: types.PolicyProtectedBranch,
			Message:  fmt.Sprintf("Primary branch '%s' is not verified as PR-only/protected. Add branch protection evidence (e.g. branch-protection-setup.md with pull request + restrict pushes) or repository settings config.", primaryBranch),
			Severity: types.SeverityBlock,
		}
	}

	return nil
}

// CheckCIPipeline verifies the repository has CI/CD configuration.
func CheckCIPipeline() *types.PolicyViolation {
	return runSnapshotCheck(checkCIPipeline)
}

func checkCIPipeline(snapshot repoSnapshot) *types.PolicyViolation {
	workflowFiles := matchingFiles(snapshot, ".github/workflows/*.yml", ".github/workflows/*.yaml")
	circleFiles := matchingFiles(snapshot, ".circleci/*.yml", ".circleci/*.yaml")
	otherPipelineFiles := []string{
		".gitlab-ci.yml",
		".travis.yml",
		"jenkinsfile",
		"azure-pipelines.yml",
		".circleci/config.yml",
		".circleci/config.yaml",
	}

	hasPipeline := len(workflowFiles) > 0 || len(circleFiles) > 0 || snapshot.hasAny(otherPipelineFiles...)
	if !hasPipeline {
		return &types.PolicyViolation{
			PolicyID: types.PolicyCIPipeline,
			Message:  "No CI pipeline configuration found. Repository must define a CI pipeline.",
			Severity: types.SeverityBlock,
		}
	}

	// Validate stronger CI obligations where config is parseable locally.
	if len(workflowFiles) > 0 {
		hasPRTrigger := false
		hasTestExecution := false
		for _, workflow := range workflowFiles {
			fullPath := filepath.Join(snapshot.root, filepath.FromSlash(workflow))
			content, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			lower := strings.ToLower(string(content))
			if containsPRTrigger(lower) {
				hasPRTrigger = true
			}
			if containsCITestExecution(lower) {
				hasTestExecution = true
			}
		}

		if !hasPRTrigger {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "CI workflows must run on pull_request for protected branches.",
				Severity: types.SeverityBlock,
			}
		}
		if !hasTestExecution {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "CI workflows are present but do not appear to run automated tests.",
				Severity: types.SeverityBlock,
			}
		}

		return nil
	}

	if len(circleFiles) > 0 {
		hasTestExecution := false
		for _, file := range circleFiles {
			fullPath := filepath.Join(snapshot.root, filepath.FromSlash(file))
			content, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			if containsCITestExecution(strings.ToLower(string(content))) {
				hasTestExecution = true
				break
			}
		}
		if !hasTestExecution {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "CI configuration found but test execution could not be verified.",
				Severity: types.SeverityBlock,
			}
		}
	}

	return nil
}

// CheckTestSuite verifies the repository has automated tests.
func CheckTestSuite() *types.PolicyViolation {
	return runSnapshotCheck(checkTestSuite)
}

func checkTestSuite(snapshot repoSnapshot) *types.PolicyViolation {
	for _, file := range snapshot.files {
		lower := strings.ToLower(file)
		base := path.Base(lower)

		if strings.HasSuffix(base, "_test.go") ||
			strings.HasSuffix(base, ".test.js") ||
			strings.HasSuffix(base, ".spec.js") ||
			strings.HasSuffix(base, ".test.ts") ||
			strings.HasSuffix(base, ".spec.ts") ||
			strings.Contains(lower, "/__tests__/") {
			return nil
		}
	}

	if snapshot.hasDir("test", "tests", "spec", "specs", "__tests__") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyTestSuite,
		Message:  "No test suite found. Repository must contain automated tests.",
		Severity: types.SeverityBlock,
	}
}

// CheckPlaintextSecrets scans for hardcoded secrets in source files.
func CheckPlaintextSecrets() *types.PolicyViolation {
	return runSnapshotCheck(checkPlaintextSecrets)
}

func checkPlaintextSecrets(snapshot repoSnapshot) *types.PolicyViolation {
	for _, file := range snapshot.files {
		if !isSecretScanCandidate(file) {
			continue
		}

		if violation := findSecretInFile(snapshot.root, file); violation != nil {
			return violation
		}
	}

	return nil
}

// CheckRollbackPlan verifies rollback documentation exists.
func CheckRollbackPlan() *types.PolicyViolation {
	return runSnapshotCheck(checkRollbackPlan)
}

func checkRollbackPlan(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAnyGlob("ROLLBACK*.md", "docs/ROLLBACK*.md", "scripts/rollback.*", "rollback.*") {
		return nil
	}

	if readmeContains(snapshot.root, "rollback") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyRollbackPlan,
		Message:  "No rollback plan found. Repository must document rollback procedures for production deployments.",
		Severity: types.SeverityBlock,
	}
}

// CheckDependencyManagement verifies dependency files exist.
func CheckDependencyManagement() *types.PolicyViolation {
	return runSnapshotCheck(checkDependencyManagement)
}

func checkDependencyManagement(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAny(
		"go.mod", "go.sum",
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"requirements.txt", "pipfile", "pipfile.lock", "poetry.lock",
		"cargo.toml", "cargo.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"composer.json", "composer.lock",
	) {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyDependencyMgmt,
		Message:  "No dependency management file found. Repository must use a package manager.",
		Severity: types.SeverityBlock,
	}
}

// CheckDocumentation verifies README and license exist.
func CheckDocumentation() *types.PolicyViolation {
	return runSnapshotCheck(checkDocumentation)
}

func checkDocumentation(snapshot repoSnapshot) *types.PolicyViolation {
	if !snapshot.has("readme.md") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "No README.md found. Repository must have documentation.",
			Severity: types.SeverityBlock,
		}
	}

	readmeContent, err := os.ReadFile(filepath.Join(snapshot.root, "README.md"))
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to read README.md: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	if !strings.Contains(string(readmeContent), "#") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "README.md is missing markdown headers.",
			Severity: types.SeverityBlock,
		}
	}

	if !snapshot.hasAny("license", "license.md", "license.txt", "copying", "copyright") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDocumentation,
			Message:  "No license file found. Repository must include a license.",
			Severity: types.SeverityBlock,
		}
	}

	return nil
}

// CheckSecurityScanning analyzes code for security issues.
func CheckSecurityScanning() *types.PolicyViolation {
	return runSnapshotCheck(checkSecurityScanning)
}

func checkSecurityScanning(snapshot repoSnapshot) *types.PolicyViolation {
	for _, file := range snapshot.files {
		if !isSecurityScanCandidate(file) {
			continue
		}

		if violation := findSecurityIssueInFile(snapshot.root, file); violation != nil {
			return violation
		}
	}

	return nil
}

// CheckDeploymentConfiguration verifies deployment files exist.
func CheckDeploymentConfiguration() *types.PolicyViolation {
	return runSnapshotCheck(checkDeploymentConfiguration)
}

func checkDeploymentConfiguration(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAny(
		"dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"deployment.yml",
		"deployment.yaml",
		"k8s/deployment.yml",
		"k8s/deployment.yaml",
	) {
		if snapshot.has("dockerfile") {
			if violation := validateDockerfile(snapshot.root); violation != nil {
				return violation
			}
		}
		return nil
	}

	if snapshot.hasDir("k8s", "kubernetes", "deploy", "helm", "terraform", "ansible") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyDeploymentConfig,
		Message:  "No deployment configuration found. Repository must define deployment infrastructure.",
		Severity: types.SeverityBlock,
	}
}

// CheckInfrastructureAsCode verifies IaC files exist.
func CheckInfrastructureAsCode() *types.PolicyViolation {
	return runSnapshotCheck(checkInfrastructureAsCode)
}

func checkInfrastructureAsCode(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAny(
		"dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"template.yaml",
		"template.yml",
		"cloudformation.yaml",
		"cloudformation.yml",
		"pulumi.yaml",
		"pulumi.yml",
		"helm/chart.yaml",
	) || snapshot.hasAnyGlob("*.tf", "infra/*.tf", "terraform/*.tf", "infrastructure/*.tf") {
		return nil
	}

	if snapshot.hasDir("terraform", "infra", "infrastructure", "iac", "k8s", "kubernetes", "helm") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyInfraAsCode,
		Message:  "No infrastructure as code found. Repository should define infrastructure declaratively.",
		Severity: types.SeverityBlock,
	}
}

// CheckEnvironmentVariables verifies environment configuration exists.
func CheckEnvironmentVariables() *types.PolicyViolation {
	return runSnapshotCheck(checkEnvironmentVariables)
}

func checkEnvironmentVariables(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAny(".env.example", ".env.sample", ".env.template", "environment.yml", "environment.yaml") {
		return nil
	}

	if snapshot.hasAny(".env", ".env.local", ".env.development", ".env.production") {
		return &types.PolicyViolation{
			PolicyID: types.PolicyEnvVariables,
			Message:  "Runtime .env files exist but no safe template found. Add .env.example or .env.template.",
			Severity: types.SeverityBlock,
		}
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyEnvVariables,
		Message:  "No environment configuration found. Repository should define environment variables.",
		Severity: types.SeverityBlock,
	}
}

// CheckBackupRecovery verifies backup documentation exists.
func CheckBackupRecovery() *types.PolicyViolation {
	return runSnapshotCheck(checkBackupRecovery)
}

func checkBackupRecovery(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAnyGlob("BACKUP*.md", "DISASTER_RECOVERY*.md", "RECOVERY*.md", "backup.*", "scripts/backup.*") {
		return nil
	}

	if readmeContains(snapshot.root, "backup", "recovery") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyBackupRecovery,
		Message:  "No backup and recovery documentation found. Repository should document backup procedures.",
		Severity: types.SeverityBlock,
	}
}

// CheckLoggingMonitoring verifies observability configuration exists.
func CheckLoggingMonitoring() *types.PolicyViolation {
	return runSnapshotCheck(checkLoggingMonitoring)
}

func checkLoggingMonitoring(snapshot repoSnapshot) *types.PolicyViolation {
	if snapshot.hasAny(
		"logging.yml", "logging.yaml", "logging.json",
		"monitoring.yml", "monitoring.yaml", "monitoring.json",
		"prometheus.yml", "log-config.yml",
		"logging.md", "monitoring.md",
	) {
		return nil
	}

	if snapshot.hasDir("grafana", "datadog", "newrelic", "sentry", "observability", "monitoring") {
		return nil
	}

	if readmeContains(snapshot.root, "logging", "monitoring", "observability") {
		return nil
	}

	return &types.PolicyViolation{
		PolicyID: types.PolicyLoggingMonitoring,
		Message:  "No logging and monitoring configuration found. Repository should define observability.",
		Severity: types.SeverityBlock,
	}
}

func runSnapshotCheck(check func(repoSnapshot) *types.PolicyViolation) *types.PolicyViolation {
	cwd, err := os.Getwd()
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to determine current directory: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	snapshot, err := buildRepoSnapshot(cwd)
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to scan repository files: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	return check(snapshot)
}

func buildRepoSnapshot(root string) (repoSnapshot, error) {
	snapshot := repoSnapshot{
		root:     root,
		files:    make([]string, 0, 256),
		lowerSet: make(map[string]struct{}),
	}

	err := filepath.WalkDir(root, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if current == root {
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

		rel, err := filepath.Rel(root, current)
		if err != nil {
			return nil
		}

		normalized := filepath.ToSlash(rel)
		snapshot.files = append(snapshot.files, normalized)
		snapshot.lowerSet[strings.ToLower(normalized)] = struct{}{}
		return nil
	})
	if err != nil {
		return repoSnapshot{}, err
	}

	sort.Strings(snapshot.files)
	return snapshot, nil
}

func (s repoSnapshot) has(file string) bool {
	normalized := strings.ToLower(filepath.ToSlash(file))
	_, ok := s.lowerSet[normalized]
	return ok
}

func (s repoSnapshot) hasAny(files ...string) bool {
	for _, file := range files {
		if s.has(file) {
			return true
		}
	}
	return false
}

func (s repoSnapshot) hasAnyGlob(patterns ...string) bool {
	for _, pattern := range patterns {
		normalizedPattern := strings.ToLower(filepath.ToSlash(pattern))
		for _, file := range s.files {
			matched, err := path.Match(normalizedPattern, strings.ToLower(file))
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

func matchingFiles(snapshot repoSnapshot, patterns ...string) []string {
	out := make([]string, 0)
	for _, pattern := range patterns {
		normalizedPattern := strings.ToLower(filepath.ToSlash(pattern))
		for _, file := range snapshot.files {
			matched, err := path.Match(normalizedPattern, strings.ToLower(file))
			if err == nil && matched {
				out = append(out, file)
			}
		}
	}
	return out
}

func (s repoSnapshot) hasDir(dirs ...string) bool {
	for _, dir := range dirs {
		prefix := strings.ToLower(strings.TrimSuffix(filepath.ToSlash(dir), "/")) + "/"
		for _, file := range s.files {
			if strings.HasPrefix(strings.ToLower(file), prefix) {
				return true
			}
		}
	}
	return false
}

func validateDockerfile(root string) *types.PolicyViolation {
	content, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		return nil
	}

	hasUserInstruction := false
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		upper := strings.ToUpper(trimmed)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(upper, "FROM ") && strings.Contains(lower, ":latest") {
			return &types.PolicyViolation{
				PolicyID: types.PolicyDeploymentConfig,
				Message:  "Dockerfile uses the latest tag. Use specific version tags for reproducible builds.",
				Severity: types.SeverityWarn,
			}
		}

		if strings.HasPrefix(upper, "USER ") {
			hasUserInstruction = true
			fields := strings.Fields(lower)
			if len(fields) >= 2 && (fields[1] == "root" || fields[1] == "0") {
				return &types.PolicyViolation{
					PolicyID: types.PolicyDeploymentConfig,
					Message:  "Dockerfile runs as root user. Use non-privileged user for security.",
					Severity: types.SeverityBlock,
				}
			}
		}
	}

	if !hasUserInstruction {
		return &types.PolicyViolation{
			PolicyID: types.PolicyDeploymentConfig,
			Message:  "Dockerfile is missing a USER instruction. Configure a non-root runtime user.",
			Severity: types.SeverityBlock,
		}
	}

	return nil
}

func findSecretInFile(root, file string) *types.PolicyViolation {
	fullPath := filepath.Join(root, filepath.FromSlash(file))
	info, err := os.Stat(fullPath)
	if err != nil || info.Size() > maxScannableFileSize {
		return nil
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}

	if bytes.IndexByte(content, 0) != -1 {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isCommentLine(file, line) {
			continue
		}

		matches := secretAssignmentPattern.FindAllStringSubmatchIndex(line, -1)
		for _, match := range matches {
			// Match indexes are: fullStart, fullEnd, keyStart, keyEnd, valueStart, valueEnd.
			if len(match) < 6 || match[2] < 0 || match[4] < 0 {
				continue
			}
			keyStart := match[2]
			valueStart := match[4]
			valueEnd := match[5]

			// Skip placeholder fragments such as "<token:role>" in docs/help text.
			if keyStart > 0 && line[keyStart-1] == '<' {
				continue
			}

			rawValue := strings.TrimSpace(line[valueStart:valueEnd])
			if isDynamicSecretExpression(rawValue) {
				continue
			}

			value := strings.Trim(rawValue, `"'`)
			if valueLooksPlaceholder(value) {
				continue
			}

			return &types.PolicyViolation{
				PolicyID: types.PolicyNoSecrets,
				Message:  fmt.Sprintf("Potential secret detected in %s:%d. Remove plaintext secrets from code and config.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}

		if knownTokenPattern.MatchString(line) && !valueLooksPlaceholder(line) {
			return &types.PolicyViolation{
				PolicyID: types.PolicyNoSecrets,
				Message:  fmt.Sprintf("Known credential token pattern detected in %s:%d.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}
	}

	return nil
}

func findSecurityIssueInFile(root, file string) *types.PolicyViolation {
	fullPath := filepath.Join(root, filepath.FromSlash(file))
	info, err := os.Stat(fullPath)
	if err != nil || info.Size() > maxScannableFileSize {
		return nil
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}

	if bytes.IndexByte(content, 0) != -1 {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(file, trimmed) {
			continue
		}

		lower := strings.ToLower(line)

		if strings.Contains(line, "unsafe.Pointer") {
			// Ignore references to the literal pattern in detector code/docs.
			if strings.Contains(line, "\"unsafe.Pointer\"") || strings.Contains(line, "`unsafe.Pointer`") {
				continue
			}
			return &types.PolicyViolation{
				PolicyID: types.PolicySecurityScanning,
				Message:  fmt.Sprintf("Unsafe pointer usage detected in %s:%d.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}

		if strings.Contains(line, "exec.Command(") && containsAny(lower, []string{
			"os.args", "os.getenv", "flag.", "fmt.sprintf", "input", "request", "+",
		}) {
			return &types.PolicyViolation{
				PolicyID: types.PolicySecurityScanning,
				Message:  fmt.Sprintf("Potential command injection pattern detected in %s:%d.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}

		if strings.Contains(lower, "eval(") || strings.Contains(lower, "system(") {
			if strings.Contains(line, "\"eval(\"") || strings.Contains(line, "`eval(`") ||
				strings.Contains(line, "\"system(\"") || strings.Contains(line, "`system(`") {
				continue
			}
			return &types.PolicyViolation{
				PolicyID: types.PolicySecurityScanning,
				Message:  fmt.Sprintf("Potentially unsafe runtime execution pattern detected in %s:%d.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}

		if (strings.Contains(line, "+") || strings.Contains(line, "fmt.Sprintf")) &&
			isLikelySQLStatement(lower) {
			return &types.PolicyViolation{
				PolicyID: types.PolicySecurityScanning,
				Message:  fmt.Sprintf("Potential SQL injection in %s:%d. Use parameterized queries.", file, lineNumber),
				Severity: types.SeverityBlock,
			}
		}
	}

	return nil
}

func readmeContains(root string, terms ...string) bool {
	content, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		return false
	}

	lower := strings.ToLower(string(content))
	for _, term := range terms {
		if strings.Contains(lower, strings.ToLower(term)) {
			return true
		}
	}

	return false
}

func isSecretScanCandidate(file string) bool {
	lower := strings.ToLower(file)
	base := path.Base(lower)

	if strings.Contains(lower, "/testdata/") || strings.HasSuffix(lower, "_test.go") {
		return false
	}

	if strings.HasPrefix(base, ".env") || base == "dockerfile" {
		return true
	}

	switch path.Ext(base) {
	case ".go", ".js", ".ts", ".py", ".rb", ".java", ".kt", ".swift",
		".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh":
		return true
	default:
		return false
	}
}

func isSecurityScanCandidate(file string) bool {
	lower := strings.ToLower(file)
	base := path.Base(lower)

	if strings.Contains(lower, "/testdata/") || strings.Contains(lower, "/vendor/") ||
		strings.HasSuffix(base, "_test.go") {
		return false
	}

	switch path.Ext(base) {
	case ".go", ".js", ".ts", ".py", ".rb", ".java", ".kt", ".swift", ".php", ".sh":
		return true
	default:
		return false
	}
}

func isCommentLine(file, line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	if strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, ";") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") {
		return true
	}

	ext := strings.ToLower(path.Ext(file))
	if ext == ".sql" && strings.HasPrefix(trimmed, "--") {
		return true
	}

	return false
}

func valueLooksPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}

	if strings.Contains(value, "<") || strings.Contains(value, ">") {
		return true
	}

	if strings.HasPrefix(value, "$") || strings.HasPrefix(value, "${") {
		return true
	}

	lower := strings.ToLower(value)
	placeholderTokens := []string{
		"example",
		"placeholder",
		"changeme",
		"dummy",
		"your_",
		"replace_me",
		"xxxx",
		"<secret>",
		"<redacted>",
	}

	for _, token := range placeholderTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}

	return len(lower) < 8
}

func listGitBranches() ([]string, error) {
	cmd := exec.Command("git", "branch", "-a", "--format=%(refname:short)")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

func verifyProtectedBranchRequirement(primaryBranch string) (bool, error) {
	docCandidates := []string{
		"branch-protection-setup.md",
		"docs/branch-protection.md",
		".github/branch-protection.md",
	}
	for _, candidate := range docCandidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(content))
		if strings.Contains(lower, primaryBranch) &&
			strings.Contains(lower, "pull request") &&
			(strings.Contains(lower, "restrict pushes") || strings.Contains(lower, "require pull request reviews before merging")) {
			return true, nil
		}
	}

	// Support repository settings manifests managed as code.
	settingsCandidates := []string{
		".github/settings.yml",
		".github/settings.yaml",
		".github/branch-protection.yml",
		".github/branch-protection.yaml",
	}
	for _, candidate := range settingsCandidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(content))
		if strings.Contains(lower, primaryBranch) &&
			(strings.Contains(lower, "required_pull_request_reviews") || strings.Contains(lower, "require_pull_request")) &&
			(strings.Contains(lower, "restrict_pushes") || strings.Contains(lower, "enforce_admins")) {
			return true, nil
		}
	}

	return false, nil
}

func containsPRTrigger(contentLower string) bool {
	return strings.Contains(contentLower, "pull_request:") ||
		strings.Contains(contentLower, "pull_request\n") ||
		strings.Contains(contentLower, "on: [pull_request") ||
		strings.Contains(contentLower, "on:[pull_request")
}

func containsCITestExecution(contentLower string) bool {
	testIndicators := []string{
		"go test",
		"npm test",
		"pnpm test",
		"yarn test",
		"pytest",
		"tox",
		"mvn test",
		"gradle test",
		"cargo test",
		"dotnet test",
		"phpunit",
		"make test",
	}
	for _, indicator := range testIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}
	return false
}

func isDynamicSecretExpression(rawValue string) bool {
	trimmed := strings.TrimSpace(rawValue)
	if trimmed == "" {
		return true
	}

	quoted := (strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"")) ||
		(strings.HasPrefix(trimmed, "'") && strings.HasSuffix(trimmed, "'"))
	if quoted {
		return false
	}

	// Skip expressions and function calls; D1 should flag hardcoded literal values.
	return strings.ContainsAny(trimmed, "()[]{}|&")
}

func isLikelySQLStatement(lowerLine string) bool {
	line := strings.ToLower(strings.TrimSpace(lowerLine))
	if line == "" {
		return false
	}

	if strings.Contains(line, "select ") && strings.Contains(line, " from ") {
		return true
	}
	if strings.Contains(line, "insert ") && strings.Contains(line, " into ") {
		return true
	}
	if strings.Contains(line, "update ") && strings.Contains(line, " set ") {
		return true
	}
	if strings.Contains(line, "delete ") && strings.Contains(line, " from ") {
		return true
	}
	if strings.Contains(line, "drop ") && strings.Contains(line, " table ") {
		return true
	}

	// Fallback for common SQL in format strings.
	return sqlKeywordPattern.MatchString(line) &&
		(strings.Contains(line, " where ") || strings.Contains(line, " values ") || strings.Contains(line, " join "))
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
