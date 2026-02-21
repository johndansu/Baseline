// Package policy implements deterministic policy checks for Baseline.
// All checks are rule-based and produce binary pass/fail outcomes.
package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/baseline/baseline/internal/types"
	"gopkg.in/yaml.v3"
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
	githubRemotePattern     = regexp.MustCompile(`github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$`)
)

var (
	githubAPIBaseURL      = "https://api.github.com"
	gitRemoteOriginReader = defaultGitRemoteOriginReader
	httpClientFactory     = func() *http.Client { return &http.Client{Timeout: 5 * time.Second} }
)

type githubWorkflow struct {
	On   any                          `yaml:"on"`
	Jobs map[string]githubWorkflowJob `yaml:"jobs"`
}

type githubWorkflowJob struct {
	Steps []githubWorkflowStep `yaml:"steps"`
}

type githubWorkflowStep struct {
	Run string `yaml:"run"`
}

type githubBranchProtectionResponse struct {
	RequiredPullRequestReviews any `json:"required_pull_request_reviews"`
	EnforceAdmins              struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	Restrictions any `json:"restrictions"`
}

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

// CheckProtectedMainBranch verifies the repository has a protected primary branch.
func CheckProtectedMainBranch() *types.PolicyViolation {
	return runSnapshotCheck(checkProtectedMainBranch)
}

func checkProtectedMainBranch(_ repoSnapshot) *types.PolicyViolation {
	primaryBranch, err := detectPrimaryBranch()
	if err != nil {
		return &types.PolicyViolation{
			PolicyID: types.PolicySystemError,
			Message:  fmt.Sprintf("Unable to detect primary branch: %v", err),
			Severity: types.SeverityBlock,
		}
	}

	if primaryBranch == "" {
		return &types.PolicyViolation{
			PolicyID: types.PolicyProtectedBranch,
			Message:  "No primary branch detected - repository must include a protected primary branch",
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
			Message:  fmt.Sprintf("Primary branch '%s' is not verified as PR-only/protected. Configure enforceable branch protection (required pull requests and restricted direct pushes).", primaryBranch),
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
		hasPRWorkflow := false
		hasPRWorkflowWithTests := false
		parseableWorkflow := false

		for _, workflow := range workflowFiles {
			fullPath := filepath.Join(snapshot.root, filepath.FromSlash(workflow))
			content, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}

			workflowHasPR, workflowHasTests, err := parseGitHubWorkflowRequirements(content)
			if err != nil {
				continue
			}
			parseableWorkflow = true
			if workflowHasPR {
				hasPRWorkflow = true
				if workflowHasTests {
					hasPRWorkflowWithTests = true
				}
			}
		}

		if !parseableWorkflow {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "GitHub Actions workflow exists but could not be parsed. Ensure workflow YAML is valid and includes pull_request test jobs.",
				Severity: types.SeverityBlock,
			}
		}
		if !hasPRWorkflow {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "CI workflows must run on pull_request for protected branches.",
				Severity: types.SeverityBlock,
			}
		}
		if !hasPRWorkflowWithTests {
			return &types.PolicyViolation{
				PolicyID: types.PolicyCIPipeline,
				Message:  "CI workflows must execute automated tests within pull_request-triggered jobs.",
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

func detectPrimaryBranch() (string, error) {
	if branch := detectPrimaryBranchFromEnvironment(); branch != "" {
		return branch, nil
	}

	if branch := readGitOriginHEADBranch(); branch != "" {
		return branch, nil
	}

	branches, branchErr := listGitBranches()
	if branchErr == nil {
		if branch := detectPrimaryBranchFromBranchList(branches); branch != "" {
			return branch, nil
		}
	}

	branch, apiErr := detectPrimaryBranchViaGitHubAPI()
	if apiErr != nil && branchErr != nil {
		return "", fmt.Errorf("git branch inspection failed: %v; GitHub default branch lookup failed: %v", branchErr, apiErr)
	}
	if branch != "" {
		return branch, nil
	}

	if branchErr != nil {
		return "", branchErr
	}

	return "", nil
}

func detectPrimaryBranchFromEnvironment() string {
	priorityCandidates := []string{
		os.Getenv("BASELINE_PRIMARY_BRANCH"),
		os.Getenv("GITHUB_BASE_REF"),
		os.Getenv("CI_DEFAULT_BRANCH"),
	}
	for _, candidate := range priorityCandidates {
		if branch := normalizeGitBranchName(candidate); branch != "" {
			return branch
		}
	}

	refProtected := strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_REF_PROTECTED")), "true")
	ref := strings.TrimSpace(os.Getenv("GITHUB_REF"))
	if strings.HasPrefix(ref, "refs/heads/") {
		if branch := normalizeGitBranchName(strings.TrimPrefix(ref, "refs/heads/")); branch != "" {
			if refProtected || isPreferredPrimaryBranch(branch) {
				return branch
			}
		}
	}

	refType := strings.TrimSpace(os.Getenv("GITHUB_REF_TYPE"))
	refName := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	if strings.EqualFold(refType, "branch") {
		if branch := normalizeGitBranchName(refName); branch != "" {
			if refProtected || isPreferredPrimaryBranch(branch) {
				return branch
			}
		}
	}

	return ""
}

func readGitOriginHEADBranch() string {
	cmd := exec.Command("git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return normalizeGitBranchName(string(output))
}

func detectPrimaryBranchFromBranchList(branches []string) string {
	unique := make(map[string]string)
	for _, raw := range branches {
		branch := normalizeGitBranchName(raw)
		if branch == "" {
			continue
		}
		lower := strings.ToLower(branch)
		if _, exists := unique[lower]; !exists {
			unique[lower] = branch
		}
	}

	for _, preferred := range []string{"main", "master", "trunk", "default"} {
		if branch, ok := unique[preferred]; ok {
			return branch
		}
	}

	if len(unique) == 1 {
		for _, branch := range unique {
			return branch
		}
	}

	return ""
}

func normalizeGitBranchName(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "* ")
	if value == "" {
		return ""
	}

	if strings.Contains(value, "->") {
		parts := strings.Split(value, "->")
		value = strings.TrimSpace(parts[len(parts)-1])
	}

	prefixes := []string{
		"refs/heads/",
		"refs/remotes/",
		"remotes/",
		"heads/",
	}
	for _, prefix := range prefixes {
		value = strings.TrimPrefix(value, prefix)
	}

	value = strings.TrimPrefix(value, "origin/")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	lower := strings.ToLower(value)
	if lower == "head" || strings.HasPrefix(lower, "pull/") {
		return ""
	}

	return value
}

func isPreferredPrimaryBranch(branch string) bool {
	switch strings.ToLower(strings.TrimSpace(branch)) {
	case "main", "master", "trunk", "default":
		return true
	default:
		return false
	}
}

func detectPrimaryBranchViaGitHubAPI() (string, error) {
	remoteURL, err := gitRemoteOriginReader()
	if err != nil {
		return "", nil
	}

	owner, repo, ok := parseGitHubRepoFromRemote(remoteURL)
	if !ok {
		return "", nil
	}

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/repos/%s/%s",
		strings.TrimRight(githubAPIBaseURL, "/"),
		neturl.PathEscape(owner),
		neturl.PathEscape(repo)), nil)
	if err != nil {
		return "", fmt.Errorf("unable to build GitHub repository metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClientFactory().Do(req)
	if err != nil {
		if token == "" {
			return "", nil
		}
		return "", fmt.Errorf("unable to query GitHub repository metadata API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var payload struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", fmt.Errorf("unable to parse GitHub repository metadata response: %w", err)
		}
		return normalizeGitBranchName(payload.DefaultBranch), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		if token == "" {
			return "", nil
		}
		return "", fmt.Errorf("GitHub repository metadata API returned %d; verify GITHUB_TOKEN/GH_TOKEN permissions", resp.StatusCode)
	default:
		if resp.StatusCode >= 500 && token != "" {
			return "", fmt.Errorf("GitHub repository metadata API returned %d", resp.StatusCode)
		}
	}

	return "", nil
}

func verifyProtectedBranchRequirement(primaryBranch string) (bool, error) {
	protected, decided, err := verifyProtectedBranchViaGitHubAPI(primaryBranch)
	if err != nil {
		return false, err
	}
	if decided {
		return protected, nil
	}

	return verifyProtectedBranchFromConfig(primaryBranch)
}

func verifyProtectedBranchViaGitHubAPI(primaryBranch string) (protected bool, decided bool, err error) {
	remoteURL, err := gitRemoteOriginReader()
	if err != nil {
		return false, false, nil
	}

	owner, repo, ok := parseGitHubRepoFromRemote(remoteURL)
	if !ok {
		return false, false, nil
	}

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection",
		strings.TrimRight(githubAPIBaseURL, "/"),
		neturl.PathEscape(owner),
		neturl.PathEscape(repo),
		neturl.PathEscape(primaryBranch)), nil)
	if err != nil {
		return false, true, fmt.Errorf("unable to build branch protection request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClientFactory().Do(req)
	if err != nil {
		if token == "" {
			return false, false, nil
		}
		return false, true, fmt.Errorf("unable to query GitHub branch protection API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var payload githubBranchProtectionResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			return false, true, fmt.Errorf("unable to parse GitHub branch protection response: %w", err)
		}
		hasPRRequirement := payload.RequiredPullRequestReviews != nil
		hasPushRestriction := payload.EnforceAdmins.Enabled || payload.Restrictions != nil
		return hasPRRequirement && hasPushRestriction, true, nil
	case http.StatusNotFound:
		return false, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		if token == "" {
			// For public repos this endpoint often requires authentication.
			return false, false, nil
		}
		return false, true, fmt.Errorf("GitHub branch protection API returned %d; verify GITHUB_TOKEN/GH_TOKEN permissions", resp.StatusCode)
	default:
		if token == "" {
			return false, false, nil
		}
		return false, true, fmt.Errorf("GitHub branch protection API returned %d", resp.StatusCode)
	}
}

func parseGitHubRepoFromRemote(remoteURL string) (owner string, repo string, ok bool) {
	trimmed := strings.TrimSpace(remoteURL)
	if trimmed == "" {
		return "", "", false
	}

	matches := githubRemotePattern.FindStringSubmatch(trimmed)
	if len(matches) != 3 {
		return "", "", false
	}
	owner = strings.TrimSpace(matches[1])
	repo = strings.TrimSpace(matches[2])
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

func verifyProtectedBranchFromConfig(primaryBranch string) (bool, error) {
	settingsCandidates := []string{
		".github/settings.yml",
		".github/settings.yaml",
	}
	for _, candidate := range settingsCandidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		protected, parseErr := branchProtectionDeclaredInSettings(content, primaryBranch)
		if parseErr != nil {
			return false, fmt.Errorf("invalid branch protection settings in %s: %w", candidate, parseErr)
		}
		if protected {
			return true, nil
		}
	}

	branchProtectionCandidates := []string{
		".github/branch-protection.yml",
		".github/branch-protection.yaml",
	}
	for _, candidate := range branchProtectionCandidates {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		protected, parseErr := branchProtectionDeclaredInGenericYAML(content, primaryBranch)
		if parseErr != nil {
			return false, fmt.Errorf("invalid branch protection config in %s: %w", candidate, parseErr)
		}
		if protected {
			return true, nil
		}
	}

	return false, nil
}

func branchProtectionDeclaredInSettings(content []byte, primaryBranch string) (bool, error) {
	var settings struct {
		Branches []struct {
			Name       string         `yaml:"name"`
			Protection map[string]any `yaml:"protection"`
		} `yaml:"branches"`
	}
	if err := yaml.Unmarshal(content, &settings); err != nil {
		return false, err
	}

	for _, branch := range settings.Branches {
		if !strings.EqualFold(strings.TrimSpace(branch.Name), strings.TrimSpace(primaryBranch)) {
			continue
		}

		hasPRRequirement := keyPresent(branch.Protection, "required_pull_request_reviews") ||
			keyPresent(branch.Protection, "require_pull_request")
		hasPushRestriction := keyPresent(branch.Protection, "restrict_pushes") ||
			keyPresent(branch.Protection, "restrictions") ||
			boolTrue(branch.Protection["enforce_admins"])
		return hasPRRequirement && hasPushRestriction, nil
	}

	return false, nil
}

func branchProtectionDeclaredInGenericYAML(content []byte, primaryBranch string) (bool, error) {
	lower := strings.ToLower(string(content))
	branchToken := strings.ToLower(strings.TrimSpace(primaryBranch))
	if branchToken == "" {
		return false, errors.New("empty primary branch")
	}

	if !strings.Contains(lower, branchToken) {
		return false, nil
	}
	hasPRRequirement := strings.Contains(lower, "required_pull_request_reviews") ||
		strings.Contains(lower, "require_pull_request")
	hasPushRestriction := strings.Contains(lower, "restrict_pushes") ||
		strings.Contains(lower, "restrictions") ||
		strings.Contains(lower, "enforce_admins: true")
	return hasPRRequirement && hasPushRestriction, nil
}

func defaultGitRemoteOriginReader() (string, error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func parseGitHubWorkflowRequirements(content []byte) (hasPRTrigger bool, hasTests bool, err error) {
	var workflow githubWorkflow
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return false, false, err
	}

	hasPRTrigger = workflowHasPullRequestTrigger(workflow.On)
	if !hasPRTrigger {
		return false, false, nil
	}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if containsCITestExecution(strings.ToLower(step.Run)) {
				return true, true, nil
			}
		}
	}

	return true, false, nil
}

func workflowHasPullRequestTrigger(raw any) bool {
	switch v := raw.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "pull_request")
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(s), "pull_request") {
				return true
			}
		}
	case map[string]any:
		for key := range v {
			if strings.EqualFold(strings.TrimSpace(key), "pull_request") {
				return true
			}
		}
	case map[any]any:
		for key := range v {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprint(key)), "pull_request") {
				return true
			}
		}
	}
	return false
}

func keyPresent(values map[string]any, key string) bool {
	if len(values) == 0 {
		return false
	}
	_, ok := values[key]
	return ok
}

func boolTrue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case map[string]any:
		if v, ok := typed["enabled"].(bool); ok {
			return v
		}
	}
	return false
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
