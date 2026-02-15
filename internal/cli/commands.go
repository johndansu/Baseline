// Package cli implements command handlers for the Baseline CLI.
package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/baseline/baseline/internal/ai"
	"github.com/baseline/baseline/internal/api"
	"github.com/baseline/baseline/internal/log"
	"github.com/baseline/baseline/internal/policy"
	"github.com/baseline/baseline/internal/report"
	"github.com/baseline/baseline/internal/scan"
	"github.com/baseline/baseline/internal/types"
	"github.com/baseline/baseline/internal/version"
)

// HandleVersion prints version information.
func HandleVersion() {
	fmt.Println(version.String())
}

// HandleCheck runs policy checks on the repository.
func HandleCheck() {
	if err := requireGitRepo(); err != nil {
		log.Error("Git repository check failed", "error", err)
		fmt.Printf("Error: %v\n", err)
		os.Exit(types.ExitBlockingViolation)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Error("Failed to get current directory", "error", err)
		fmt.Printf("Error: Unable to get current directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	log.Info("Starting repository check", "repository", filepath.Base(cwd))
	fmt.Printf("Checking repository: %s\n", filepath.Base(cwd))
	violations := policy.RunAllChecks()

	if len(violations) > 0 {
		log.Warn("Policy violations found", "count", len(violations))
		fmt.Println("\nPolicy violations found:")
		for _, v := range violations {
			fmt.Printf("  [%s] %s\n", v.PolicyID, v.Message)
		}
		fmt.Printf("\nExit code: %d (blocking violations)\n", types.ExitBlockingViolation)
		os.Exit(types.ExitBlockingViolation)
	}

	log.Info("No policy violations detected")
	fmt.Printf("Exit code: %d (no violations)\n", types.ExitSuccess)
	os.Exit(types.ExitSuccess)
}

// HandleEnforce enforces policies and blocks on violations.
func HandleEnforce() {
	if err := requireGitRepo(); err != nil {
		log.Error("Git repository check failed", "error", err)
		fmt.Printf("ENFORCEMENT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Error("Failed to get current directory", "error", err)
		fmt.Printf("ENFORCEMENT FAILED: Unable to get current directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	log.Info("Starting policy enforcement", "repository", filepath.Base(cwd))
	fmt.Printf("Enforcing policies on repository: %s\n", filepath.Base(cwd))
	violations := policy.RunAllChecks()

	if len(violations) > 0 {
		fmt.Printf("\nENFORCEMENT BLOCKED: Policy violations found:\n")
		for _, v := range violations {
			fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
		}
		fmt.Printf("\nEnforcement failed. Fix violations before proceeding.\n")
		os.Exit(types.ExitBlockingViolation)
	}

	fmt.Printf("Enforcement passed. No policy violations detected.\n")
	os.Exit(types.ExitSuccess)
}

// HandleScan performs a comprehensive repository scan.
func HandleScan() {
	if err := requireGitRepo(); err != nil {
		fmt.Printf("SCAN FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("SCAN FAILED: Unable to get current directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Scanning repository: %s\n", filepath.Base(cwd))
	fmt.Println()

	results := scan.RunComprehensiveScan()

	fmt.Println("=== SCAN RESULTS ===")
	fmt.Printf("Repository: %s\n", filepath.Base(cwd))
	fmt.Printf("Files scanned: %d\n", results.FilesScanned)
	fmt.Printf("Security issues found: %d\n", results.SecurityIssues)
	fmt.Printf("Policy violations: %d\n", len(results.Violations))

	if len(results.Violations) > 0 {
		fmt.Println("\nPolicy violations:")
		for _, v := range results.Violations {
			fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
		}
		fmt.Printf("\nExit code: %d (blocking violations)\n", types.ExitBlockingViolation)
		os.Exit(types.ExitBlockingViolation)
	}

	fmt.Println("\nNo critical policy violations detected")
	fmt.Printf("Exit code: %d (scan completed)\n", types.ExitSuccess)
	os.Exit(types.ExitSuccess)
}

// HandleInit initializes Baseline configuration.
func HandleInit() {
	if err := requireGitRepo(); err != nil {
		fmt.Printf("INIT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("INIT FAILED: Unable to get current directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Initializing Baseline in repository: %s\n", filepath.Base(cwd))

	if err := os.MkdirAll(".baseline", 0755); err != nil {
		fmt.Printf("INIT FAILED: Unable to create .baseline directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	configContent := `# Baseline Configuration
# This file configures Baseline policy enforcement

policy_set = "baseline:prod"
enforcement_mode = "audit"
`
	configFile := ".baseline/config.yaml"

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		fmt.Printf("INIT FAILED: Unable to create config file: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Created Baseline configuration: %s\n", configFile)
	fmt.Printf("Policy set: baseline:prod\n")
	fmt.Printf("Enforcement mode: audit\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Run 'baseline check' to verify policy compliance\n")
	fmt.Printf("2. Run 'baseline scan' to analyze repository state\n")
	fmt.Printf("3. Fix any violations found\n")
	os.Exit(types.ExitSuccess)
}

// HandleReport generates scan results in specified format.
func HandleReport(args []string) {
	if err := requireGitRepo(); err != nil {
		fmt.Printf("REPORT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	outputFormat := "text"
	for _, arg := range args {
		if arg == "--json" {
			outputFormat = "json"
			break
		}
	}

	results := scan.RunComprehensiveScan()

	if outputFormat == "json" {
		if err := report.OutputJSON(results); err != nil {
			fmt.Printf("REPORT FAILED: %v\n", err)
			os.Exit(types.ExitSystemError)
		}
	} else {
		report.OutputText(results)
	}

	os.Exit(types.ExitSuccess)
}

// HandleGenerate generates missing infrastructure using AI.
func HandleGenerate() {
	if err := requireGitRepo(); err != nil {
		fmt.Printf("GENERATE FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("GENERATE FAILED: Unable to get current directory: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Generating missing infrastructure for repository: %s\n", filepath.Base(cwd))

	// Initialize AI generator
	gen := ai.NewDefaultGenerator()

	// Check Ollama availability
	if err := gen.CheckAvailability(); err != nil {
		fmt.Printf("GENERATE FAILED: %v\n", err)
		fmt.Printf("Please ensure Ollama is running with: ollama serve\n")
		os.Exit(types.ExitSystemError)
	}

	fmt.Println("Ollama connected successfully")

	// Run policy checks to identify violations
	violations := policy.RunAllChecks()

	if len(violations) == 0 {
		fmt.Println("No violations found - repository is compliant")
		os.Exit(types.ExitSuccess)
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
	}
	fmt.Println()

	generatedFiles := generateFixes(gen, violations)

	fmt.Printf("\nGeneration complete: %d files created\n", generatedFiles)

	if generatedFiles > 0 {
		fmt.Println("\nNext steps:")
		fmt.Println("1. Review the generated files")
		fmt.Println("2. Run 'baseline check' to verify compliance")
		fmt.Println("3. Commit the changes to your repository")
		fmt.Println("4. Push and create a pull request for review")
		os.Exit(types.ExitSuccess)
	} else {
		fmt.Println("No files were generated")
		os.Exit(types.ExitSystemError)
	}
}

// HandlePR creates a pull request with generated scaffolds.
func HandlePR() {
	if err := requireGitRepo(); err != nil {
		fmt.Printf("PR FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	// Check git remote
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("PR FAILED: No git remote 'origin' found: %v\n", err)
		fmt.Printf("Please set up a git remote before creating pull requests\n")
		os.Exit(types.ExitSystemError)
	}

	remoteURL := strings.TrimSpace(string(output))
	if !strings.Contains(remoteURL, "github.com") {
		fmt.Printf("PR FAILED: Only GitHub repositories are supported\n")
		fmt.Printf("Found remote: %s\n", remoteURL)
		os.Exit(types.ExitSystemError)
	}

	// Initialize AI generator
	gen := ai.NewDefaultGenerator()

	if err := gen.CheckAvailability(); err != nil {
		fmt.Printf("PR FAILED: %v\n", err)
		fmt.Printf("Please ensure Ollama is running with: ollama serve\n")
		os.Exit(types.ExitSystemError)
	}

	fmt.Println("Ollama connected successfully")

	violations := policy.RunAllChecks()

	if len(violations) == 0 {
		fmt.Println("No violations found - repository is compliant")
		fmt.Println("No pull request needed")
		os.Exit(types.ExitSuccess)
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
	}
	fmt.Println()

	// Create branch and generate fixes
	branchName := "baseline/fix-violations"
	if err := createOrCheckoutBranch(branchName); err != nil {
		fmt.Printf("PR FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	generatedFilesList := generateFixesWithList(gen, violations)

	if len(generatedFilesList) == 0 {
		fmt.Println("No files were generated")
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("\nGeneration complete: %d files created\n", len(generatedFilesList))

	// Stage, commit, and push
	if err := commitAndPush(branchName, generatedFilesList); err != nil {
		fmt.Printf("PR FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	// Create PR using GitHub CLI
	prBody := report.GeneratePRBody(violations, generatedFilesList)
	cmd = exec.Command("gh", "pr", "create",
		"--title", "Add missing production infrastructure",
		"--body", prBody,
		"--head", branchName)

	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Unable to create PR automatically: %v\n", err)
		fmt.Println("Please create a pull request manually:")
		fmt.Printf("  Branch: %s\n", branchName)
		fmt.Printf("  Title: Add missing production infrastructure\n")
		fmt.Println("  Description: See generated files for details")
		os.Exit(types.ExitSuccess)
	}

	fmt.Println("✓ Pull request created successfully!")
	fmt.Printf("\nNext steps:\n")
	fmt.Println("1. Review the pull request")
	fmt.Println("2. Run tests to ensure everything works")
	fmt.Println("3. Merge the pull request when ready")
	os.Exit(types.ExitSuccess)
}

// HandleExplain provides explanation for a policy violation.
func HandleExplain(args []string) {
	if len(args) < 1 {
		fmt.Printf("Usage: baseline explain <policy_id>\n")
		fmt.Printf("Example: baseline explain G1\n")
		os.Exit(1)
	}

	policyID := args[0]

	fmt.Printf("=== POLICY EXPLANATION ===\n")
	fmt.Printf("Policy ID: %s\n", policyID)
	fmt.Println()

	// Check current status
	violations := policy.RunAllChecks()

	var foundViolation *types.PolicyViolation
	for _, v := range violations {
		if v.PolicyID == policyID {
			foundViolation = &v
			break
		}
	}

	if foundViolation != nil {
		fmt.Printf("Current Status: VIOLATION\n")
		fmt.Printf("Message: %s\n", foundViolation.Message)
		fmt.Printf("Severity: %s\n", foundViolation.Severity)
		fmt.Println()
		fmt.Printf("Remediation: %s\n", report.GetRemediationAdvice(policyID))
	} else {
		fmt.Printf("Current Status: COMPLIANT\n")
		fmt.Printf("This policy is currently satisfied.\n")
	}
}

// HandleAPI serves the optional Baseline API.
func HandleAPI(args []string) {
	if err := loadAPIEnvFiles(); err != nil {
		fmt.Printf("API FAILED: unable to load API env file: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	if len(args) < 1 {
		fmt.Println("Usage: baseline api serve [--addr <host:port>] [--ai-enabled]")
		fmt.Println("       baseline api keygen")
		fmt.Println("       baseline api verify-prod [--strict]")
		fmt.Println("Environment:")
		fmt.Println("  BASELINE_API_KEY=<key> or BASELINE_API_KEYS=<key:role,key:role>")
		fmt.Println("  BASELINE_API_SELF_SERVICE_ENABLED=true")
		fmt.Println("  BASELINE_API_ENROLLMENT_TOKENS=<token:role,token:role>")
		fmt.Println("  BASELINE_API_ENROLLMENT_TOKEN_TTL_MINUTES=1440")
		fmt.Println("  BASELINE_API_ENROLLMENT_TOKEN_MAX_USES=1")
		fmt.Println("  BASELINE_API_ADDR=:8080")
		fmt.Println("  BASELINE_API_DB_PATH=baseline_api.db")
		fmt.Println("  BASELINE_API_TIMEOUT_MS=5000")
		fmt.Println("  BASELINE_API_MAX_BODY_BYTES=1048576")
		fmt.Println("  BASELINE_API_SHUTDOWN_TIMEOUT_MS=10000")
		fmt.Println("  BASELINE_API_CORS_ALLOWED_ORIGINS=https://dashboard.example.com")
		fmt.Println("  BASELINE_API_TRUST_PROXY_HEADERS=false")
		fmt.Println("  BASELINE_API_DASHBOARD_SESSION_ENABLED=true")
		fmt.Println("  BASELINE_API_DASHBOARD_SESSION_ROLE=viewer")
		fmt.Println("  BASELINE_API_DASHBOARD_SESSION_TTL_MINUTES=720")
		fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_ENABLED=false")
		fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER=X-Forwarded-User")
		fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_ROLE_HEADER=X-Forwarded-Role")
		fmt.Println("  BASELINE_API_AI_ENABLED=false")
		fmt.Println("Config file auto-load order: BASELINE_API_ENV_FILE, .env.production, .env, api.env")
		os.Exit(1)
	}

	if args[0] == "keygen" {
		key, err := generateAPIKey()
		if err != nil {
			fmt.Printf("API FAILED: unable to generate API key: %v\n", err)
			os.Exit(types.ExitSystemError)
		}
		fmt.Println(key)
		os.Exit(types.ExitSuccess)
	}

	if args[0] == "verify-prod" {
		strict := false
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--strict":
				strict = true
			default:
				fmt.Printf("API FAILED: unknown flag %s\n", args[i])
				os.Exit(types.ExitSystemError)
			}
		}

		cfg := api.ConfigFromEnv()
		result := verifyAPIProdConfig(cfg, os.Getenv)
		fmt.Println("=== BASELINE API PRODUCTION VERIFICATION ===")
		fmt.Printf("Address: %s\n", cfg.Addr)
		fmt.Printf("Database: %s\n", cfg.DBPath)
		fmt.Println()

		if len(result.Errors) > 0 {
			fmt.Println("Blocking issues:")
			for _, issue := range result.Errors {
				fmt.Printf("  - %s\n", issue)
			}
			fmt.Println()
		}

		if len(result.Warnings) > 0 {
			fmt.Println("Warnings:")
			for _, issue := range result.Warnings {
				fmt.Printf("  - %s\n", issue)
			}
			fmt.Println()
		}

		if len(result.Errors) == 0 && len(result.Warnings) == 0 {
			fmt.Println("PASS: Baseline API config is production-ready.")
			os.Exit(types.ExitSuccess)
		}

		if strict && len(result.Warnings) > 0 {
			fmt.Println("STRICT MODE: warnings are treated as blocking.")
			os.Exit(types.ExitBlockingViolation)
		}

		if len(result.Errors) > 0 {
			fmt.Println("FAIL: resolve blocking issues before production deployment.")
			os.Exit(types.ExitBlockingViolation)
		}

		fmt.Println("PASS WITH WARNINGS: review and address warnings before production deployment.")
		os.Exit(types.ExitSuccess)
	}

	if args[0] != "serve" {
		fmt.Printf("API FAILED: unknown subcommand %s\n", args[0])
		os.Exit(types.ExitSystemError)
	}

	cfg := api.ConfigFromEnv()
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				fmt.Println("API FAILED: --addr requires a value")
				os.Exit(types.ExitSystemError)
			}
			cfg.Addr = args[i+1]
			i++
		case "--ai-enabled":
			cfg.AIEnabled = true
		default:
			fmt.Printf("API FAILED: unknown flag %s\n", args[i])
			os.Exit(types.ExitSystemError)
		}
	}

	server, err := api.NewServer(cfg, nil)
	if err != nil {
		fmt.Printf("API FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Baseline API server listening on %s\n", cfg.Addr)
	fmt.Printf("Web dashboard available at %s/dashboard\n", dashboardListenURL(cfg.Addr))
	if cfg.AIEnabled {
		fmt.Println("AI advisory endpoints are enabled")
	} else {
		fmt.Println("AI advisory endpoints are disabled")
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	go func() {
		<-signalCtx.Done()
		fmt.Println("Shutdown signal received; stopping Baseline API server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Printf("API shutdown warning: %v\n", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			os.Exit(types.ExitSuccess)
		}
		fmt.Printf("API FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}
}

func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func loadAPIEnvFiles() error {
	candidates := []string{}
	if explicit := strings.TrimSpace(os.Getenv("BASELINE_API_ENV_FILE")); explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates, ".env.production", ".env", "api.env")

	for _, path := range candidates {
		if err := loadEnvFileIfPresent(path); err != nil {
			return err
		}
	}
	return nil
}

func loadEnvFileIfPresent(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		if strings.TrimSpace(os.Getenv(key)) != "" {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if len(value) >= 2 {
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}

	return scanner.Err()
}

type prodVerifyResult struct {
	Errors   []string
	Warnings []string
}

func verifyAPIProdConfig(cfg api.Config, getenv func(string) string) prodVerifyResult {
	result := prodVerifyResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	if strings.TrimSpace(cfg.DBPath) == "" || cfg.DBPath == ":memory:" {
		result.Errors = append(result.Errors, "BASELINE_API_DB_PATH must point to a persistent file path (not :memory:).")
	}

	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 {
		result.Errors = append(result.Errors, "BASELINE_API_TIMEOUT_MS and idle timeout must be positive.")
	}
	if cfg.IdleTimeout > 0 && (cfg.IdleTimeout < cfg.ReadTimeout || cfg.IdleTimeout < cfg.WriteTimeout) {
		result.Warnings = append(result.Warnings, "Idle timeout is lower than read/write timeout; increase idle timeout to reduce premature disconnects.")
	}

	if cfg.MaxBodyBytes <= 0 {
		result.Errors = append(result.Errors, "BASELINE_API_MAX_BODY_BYTES must be greater than zero.")
	}
	if cfg.MaxBodyBytes > 10*1024*1024 {
		result.Warnings = append(result.Warnings, "BASELINE_API_MAX_BODY_BYTES is very high (>10MB); reduce unless required.")
	}

	if cfg.ShutdownTimeout <= 0 {
		result.Errors = append(result.Errors, "BASELINE_API_SHUTDOWN_TIMEOUT_MS must be greater than zero.")
	}
	if cfg.ShutdownTimeout > 0 && cfg.ShutdownTimeout < 2*time.Second {
		result.Warnings = append(result.Warnings, "Shutdown timeout is very low; graceful shutdown may terminate in-flight requests.")
	}

	if len(cfg.CORSAllowedOrigins) == 0 {
		result.Errors = append(result.Errors, "BASELINE_API_CORS_ALLOWED_ORIGINS must be set for production browser clients.")
	} else {
		for _, origin := range cfg.CORSAllowedOrigins {
			trimmed := strings.TrimSpace(origin)
			if trimmed == "*" {
				result.Errors = append(result.Errors, "CORS wildcard '*' is not allowed in production.")
				continue
			}
			if strings.HasPrefix(strings.ToLower(trimmed), "http://") {
				result.Errors = append(result.Errors, "CORS origin must use HTTPS: "+trimmed)
			}
		}
	}

	host := hostFromAddr(cfg.Addr)
	if !cfg.TrustProxyHeaders && !isLoopbackHost(host) {
		result.Errors = append(result.Errors, "BASELINE_API_TRUST_PROXY_HEADERS should be true when binding to non-loopback addresses behind TLS termination.")
	}

	if !cfg.SelfServiceEnabled && len(cfg.APIKeys) == 0 && !cfg.DashboardSessionEnabled {
		result.Errors = append(result.Errors, "enable dashboard sessions or configure API keys when self-service is disabled.")
	}
	if cfg.SelfServiceEnabled {
		if len(cfg.EnrollmentTokens) == 0 {
			result.Errors = append(result.Errors, "self-service is enabled but no enrollment tokens are configured.")
		}
		if cfg.EnrollmentMaxUses > 1 {
			result.Warnings = append(result.Warnings, "Enrollment max uses is greater than 1; one-time enrollment tokens are safer.")
		}
		if cfg.EnrollmentTokenTTL > 24*time.Hour {
			result.Warnings = append(result.Warnings, "Enrollment token TTL is longer than 24 hours; reduce token lifetime.")
		}
	}
	if cfg.DashboardSessionEnabled && !isLoopbackHost(host) {
		result.Warnings = append(result.Warnings, "Dashboard session auth is enabled on a non-loopback address; place the API behind trusted auth/proxy.")
	}
	if cfg.DashboardAuthProxyEnabled {
		if !cfg.DashboardSessionEnabled {
			result.Errors = append(result.Errors, "dashboard auth proxy requires dashboard sessions to be enabled.")
		}
		if !cfg.TrustProxyHeaders {
			result.Errors = append(result.Errors, "dashboard auth proxy requires BASELINE_API_TRUST_PROXY_HEADERS=true.")
		}
		if strings.TrimSpace(cfg.DashboardAuthProxyUserHeader) == "" {
			result.Errors = append(result.Errors, "BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER must not be empty when auth proxy is enabled.")
		}
	}

	if !hasAdminKey(cfg.APIKeys) {
		result.Warnings = append(result.Warnings, "No admin API key is bootstrapped via environment; ensure an active admin key exists in the database.")
	}

	if cfg.AIEnabled {
		result.Warnings = append(result.Warnings, "AI advisory endpoints are enabled; keep AI disabled unless explicitly required.")
	}

	if secretLooksPlaceholder(getenv("BASELINE_API_KEY")) || secretLooksPlaceholder(getenv("BASELINE_API_KEYS")) {
		result.Errors = append(result.Errors, "API key environment variables still look like placeholder values.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_ENROLLMENT_TOKENS")) {
		result.Errors = append(result.Errors, "Enrollment token environment variable looks like a placeholder value.")
	}

	return result
}

func hostFromAddr(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, ":") {
		return ""
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(trimmed, "[]")
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hasAdminKey(keys map[string]api.Role) bool {
	for _, role := range keys {
		if role == api.RoleAdmin {
			return true
		}
	}
	return false
}

func secretLooksPlaceholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	return strings.Contains(v, "replace") ||
		strings.Contains(v, "changeme") ||
		strings.Contains(v, "example") ||
		strings.Contains(v, "placeholder")
}

// requireGitRepo checks that we're in a git repository.
func requireGitRepo() error {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("not a git repository. Baseline must be run from within a git repository")
	}

	if strings.TrimSpace(string(output)) != "true" {
		return fmt.Errorf("not a git repository. Baseline must be run from within a git repository")
	}

	return nil
}

// generateFixes generates files for each violation and returns count.
func generateFixes(gen *ai.Generator, violations []types.PolicyViolation) int {
	count := 0
	for _, v := range violations {
		if generated := generateFixForViolation(gen, v); generated {
			count++
		}
	}
	return count
}

// generateFixesWithList generates files and returns the list of generated files.
func generateFixesWithList(gen *ai.Generator, violations []types.PolicyViolation) []string {
	var files []string
	for _, v := range violations {
		if file := generateFixForViolationWithFile(gen, v); file != "" {
			files = append(files, file)
		}
	}
	return files
}

// generateFixForViolation generates a fix for a single violation.
func generateFixForViolation(gen *ai.Generator, v types.PolicyViolation) bool {
	file := generateFixForViolationWithFile(gen, v)
	return file != ""
}

// generateFixForViolationWithFile generates a fix and returns the filename.
func generateFixForViolationWithFile(gen *ai.Generator, v types.PolicyViolation) string {
	violations := []types.PolicyViolation{v}

	switch v.PolicyID {
	case types.PolicyCIPipeline:
		fmt.Println("Generating CI configuration...")
		content, err := gen.GenerateCIConfig(violations)
		if err != nil {
			fmt.Printf("Failed to generate CI config: %v\n", err)
			return ""
		}
		if err := gen.WriteGeneratedFile(".github/workflows/ci.yml", content); err != nil {
			fmt.Printf("Failed to write CI config: %v\n", err)
			return ""
		}
		fmt.Println("✓ Generated .github/workflows/ci.yml")
		return ".github/workflows/ci.yml"

	case types.PolicyTestSuite:
		fmt.Println("Generating test scaffold...")
		content, err := gen.GenerateTestScaffold(violations)
		if err != nil {
			fmt.Printf("Failed to generate tests: %v\n", err)
			return ""
		}
		if err := gen.WriteGeneratedFile("main_test.go", content); err != nil {
			fmt.Printf("Failed to write tests: %v\n", err)
			return ""
		}
		fmt.Println("✓ Generated main_test.go")
		return "main_test.go"

	case types.PolicyDocumentation:
		fmt.Println("Generating README.md...")
		content, err := gen.GenerateREADME(violations)
		if err != nil {
			fmt.Printf("Failed to generate README: %v\n", err)
			return ""
		}
		if err := gen.WriteGeneratedFile("README.md", content); err != nil {
			fmt.Printf("Failed to write README: %v\n", err)
			return ""
		}
		fmt.Println("✓ Generated README.md")
		return "README.md"

	case types.PolicyDeploymentConfig:
		fmt.Println("Generating Dockerfile...")
		content, err := gen.GenerateDockerfile(violations)
		if err != nil {
			fmt.Printf("Failed to generate Dockerfile: %v\n", err)
			return ""
		}
		if err := gen.WriteGeneratedFile("Dockerfile", content); err != nil {
			fmt.Printf("Failed to write Dockerfile: %v\n", err)
			return ""
		}
		fmt.Println("✓ Generated Dockerfile")
		return "Dockerfile"

	case types.PolicyEnvVariables:
		fmt.Println("Generating .env.example...")
		content, err := gen.GenerateEnvExample(violations)
		if err != nil {
			fmt.Printf("Failed to generate .env.example: %v\n", err)
			return ""
		}
		if err := gen.WriteGeneratedFile(".env.example", content); err != nil {
			fmt.Printf("Failed to write .env.example: %v\n", err)
			return ""
		}
		fmt.Println("✓ Generated .env.example")
		return ".env.example"
	}

	return ""
}

// createOrCheckoutBranch creates or checks out the specified branch.
func createOrCheckoutBranch(branchName string) error {
	// Check if branch exists
	cmd := exec.Command("git", "branch", "--list", branchName)
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		fmt.Printf("Branch %s already exists, checking it out...\n", branchName)
		cmd = exec.Command("git", "checkout", branchName)
		return cmd.Run()
	}

	// Create new branch
	fmt.Printf("Creating new branch: %s\n", branchName)
	cmd = exec.Command("git", "checkout", "-b", branchName)
	return cmd.Run()
}

// commitAndPush stages, commits, and pushes changes.
func commitAndPush(branchName string, files []string) error {
	fmt.Println("Staging generated files...")
	for _, file := range files {
		cmd := exec.Command("git", "add", file)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to stage %s: %v\n", file, err)
		}
	}

	fmt.Println("Committing changes...")
	cmd := exec.Command("git", "commit", "-m", "fix: Add missing production infrastructure")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to commit changes: %w", err)
	}

	fmt.Println("Pushing branch to remote...")
	cmd = exec.Command("git", "push", "-u", "origin", branchName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to push branch: %w", err)
	}

	return nil
}
