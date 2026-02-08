// Package cli implements command handlers for the Baseline CLI.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/baseline/baseline/internal/ai"
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
		os.Exit(types.ExitSystemError)
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

// requireGitRepo checks that we're in a git repository.
func requireGitRepo() error {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
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
