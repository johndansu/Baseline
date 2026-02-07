package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Handle help flags
	if command == "--help" || command == "-h" {
		printUsage()
		os.Exit(0)
	}

	switch command {
	case "version":
		fmt.Println("baseline version 0.1.0")
		os.Exit(0)
	case "check":
		handleCheckCommand()
	case "enforce":
		handleEnforceCommand()
	case "scan":
		handleScanCommand()
	case "init":
		handleInitCommand()
	case "report":
		handleReportCommand()
	case "generate":
		handleGenerateCommand()
	case "pr":
		handlePRCommand()
	case "explain":
		handleExplainCommand()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("baseline - Production Policy & Enforcement Engine")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  baseline [command] [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version    Show version information")
	fmt.Println("  check      Run repository policy checks")
	fmt.Println("  enforce    Enforce policies and block on violations")
	fmt.Println("  scan       Deep scan of repository state")
	fmt.Println("  init       Initialize Baseline configuration")
	fmt.Println("  report     Output scan results in machine-readable formats")
	fmt.Println("  generate   Generate missing infrastructure using AI")
	fmt.Println("  pr         Create pull requests with AI-generated scaffolds")
	fmt.Println("  explain     Get explanation for policy violations")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --help, -h  Show this help message")
	fmt.Println()
}

func handleCheckCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Println("Error: Not a git repository")
		fmt.Println("Baseline must be run from within a git repository")
		os.Exit(20)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Checking repository: %s\n", filepath.Base(cwd))
	violations := runPolicyChecks()

	if len(violations) > 0 {
		fmt.Println("\nPolicy violations found:")
		for _, violation := range violations {
			fmt.Printf("  [%s] %s\n", violation.policyID, violation.message)
		}
		fmt.Printf("\nExit code: 20 (blocking violations)\n")
		os.Exit(20)
	}

	fmt.Println("No policy violations detected")
	fmt.Println("Exit code: 0 (no violations)")
	os.Exit(0)
}

func handleEnforceCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("ENFORCEMENT FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("ENFORCEMENT FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Enforcing policies on repository: %s\n", filepath.Base(cwd))
	violations := runPolicyChecks()

	if len(violations) > 0 {
		fmt.Printf("\nENFORCEMENT BLOCKED: Policy violations found:\n")
		for _, violation := range violations {
			fmt.Printf("  [%s] %s (%s)\n", violation.policyID, violation.message, violation.severity)
		}
		fmt.Printf("\nEnforcement failed. Fix violations before proceeding.\n")
		os.Exit(50)
	}

	fmt.Printf("Enforcement passed. No policy violations detected.\n")
	os.Exit(0)
}

func handleScanCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("SCAN FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("SCAN FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Scanning repository: %s\n", filepath.Base(cwd))
	fmt.Println()

	scanResults := runComprehensiveScan()

	fmt.Println("=== SCAN RESULTS ===")
	fmt.Printf("Repository: %s\n", filepath.Base(cwd))
	fmt.Printf("Files scanned: %d\n", scanResults.filesScanned)
	fmt.Printf("Security issues found: %d\n", scanResults.securityIssues)
	fmt.Printf("Policy violations: %d\n", len(scanResults.violations))

	if len(scanResults.violations) > 0 {
		fmt.Println("\nPolicy violations:")
		for _, violation := range scanResults.violations {
			fmt.Printf("  [%s] %s (%s)\n", violation.policyID, violation.message, violation.severity)
		}
		fmt.Printf("\nExit code: 20 (blocking violations)\n")
		os.Exit(20)
	}

	fmt.Println("\nNo critical policy violations detected")
	fmt.Printf("Exit code: 0 (scan completed)\n")
	os.Exit(0)
}

func handleInitCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("INIT FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("INIT FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Initializing Baseline in repository: %s\n", filepath.Base(cwd))

	if err := os.MkdirAll(".baseline", 0755); err != nil {
		fmt.Printf("INIT FAILED: Unable to create .baseline directory: %v\n", err)
		os.Exit(50)
	}

	configContent := "# Baseline Configuration\n# This file configures Baseline policy enforcement\n\npolicy_set = \"baseline:prod\"\nenforcement_mode = \"audit\"\n"
	configFile := ".baseline/config.yaml"

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		fmt.Printf("INIT FAILED: Unable to create config file: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Created Baseline configuration: %s\n", configFile)
	fmt.Printf("Policy set: baseline:prod\n")
	fmt.Printf("Enforcement mode: audit\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Run 'baseline check' to verify policy compliance\n")
	fmt.Printf("2. Run 'baseline scan' to analyze repository state\n")
	fmt.Printf("3. Fix any violations found\n")
	os.Exit(0)
}

func handleReportCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("REPORT FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("REPORT FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	outputFormat := "text"
	for _, arg := range os.Args {
		if arg == "--json" {
			outputFormat = "json"
			break
		}
	}

	fmt.Printf("Generating report for repository: %s\n", filepath.Base(cwd))
	scanResults := runComprehensiveScan()

	if outputFormat == "json" {
		outputJSONReport(scanResults)
	} else {
		outputTextReport(scanResults)
	}

	os.Exit(0)
}

func handleGenerateCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("GENERATE FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("GENERATE FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Generating missing infrastructure for repository: %s\n", filepath.Base(cwd))

	// Initialize AI generator
	ai := NewAIGenerator()

	// Check Ollama availability
	if err := ai.CheckOllamaAvailability(); err != nil {
		fmt.Printf("GENERATE FAILED: Ollama not available: %v\n", err)
		fmt.Printf("Please ensure Ollama is running with: ollama serve\n")
		os.Exit(50)
	}

	fmt.Println("Ollama TinyLlama connected successfully")

	// Run policy checks to identify violations
	violations := runPolicyChecks()

	if len(violations) == 0 {
		fmt.Println("No violations found - repository is compliant")
		os.Exit(0)
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, violation := range violations {
		fmt.Printf("  [%s] %s (%s)\n", violation.policyID, violation.message, violation.severity)
	}
	fmt.Println()

	// Generate fixes for each violation
	generatedFiles := 0

	for _, violation := range violations {
		switch violation.policyID {
		case "B1": // CI pipeline
			fmt.Println("Generating CI configuration...")
			content, err := ai.GenerateCIConfig(violations)
			if err != nil {
				fmt.Printf("Failed to generate CI config: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile(".github/workflows/ci.yml", content); err != nil {
				fmt.Printf("Failed to write CI config: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated .github/workflows/ci.yml")
			generatedFiles++

		case "C1": // Test suite
			fmt.Println("Generating test scaffold...")
			content, err := ai.GenerateTestScaffold(violations)
			if err != nil {
				fmt.Printf("Failed to generate tests: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("main_test.go", content); err != nil {
				fmt.Printf("Failed to write tests: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated main_test.go")
			generatedFiles++

		case "F1": // Documentation
			fmt.Println("Generating README.md...")
			content, err := ai.GenerateREADME(violations)
			if err != nil {
				fmt.Printf("Failed to generate README: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("README.md", content); err != nil {
				fmt.Printf("Failed to write README: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated README.md")
			generatedFiles++

		case "H1": // Deployment configuration
			fmt.Println("Generating Dockerfile...")
			content, err := ai.GenerateDockerfile(violations)
			if err != nil {
				fmt.Printf("Failed to generate Dockerfile: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("Dockerfile", content); err != nil {
				fmt.Printf("Failed to write Dockerfile: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated Dockerfile")
			generatedFiles++

		case "J1": // Environment variables
			fmt.Println("Generating .env.example...")
			content, err := ai.GenerateEnvExample(violations)
			if err != nil {
				fmt.Printf("Failed to generate .env.example: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile(".env.example", content); err != nil {
				fmt.Printf("Failed to write .env.example: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated .env.example")
			generatedFiles++
		}
	}

	fmt.Printf("\nGeneration complete: %d files created\n", generatedFiles)

	if generatedFiles > 0 {
		fmt.Println("\nNext steps:")
		fmt.Println("1. Review the generated files")
		fmt.Println("2. Run 'baseline check' to verify compliance")
		fmt.Println("3. Commit the changes to your repository")
		fmt.Println("4. Push and create a pull request for review")
		os.Exit(0)
	} else {
		fmt.Println("No files were generated")
		os.Exit(50)
	}
}

func handlePRCommand() {
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Printf("PR FAILED: Not a git repository\n")
		fmt.Printf("Baseline must be run from within a git repository\n")
		os.Exit(50)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("PR FAILED: Unable to get current directory: %v\n", err)
		os.Exit(50)
	}

	fmt.Printf("Creating pull request for repository: %s\n", filepath.Base(cwd))

	// Check if git remote exists
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("PR FAILED: No git remote 'origin' found: %v\n", err)
		fmt.Printf("Please set up a git remote before creating pull requests\n")
		os.Exit(50)
	}

	remoteURL := strings.TrimSpace(string(output))
	if !strings.Contains(remoteURL, "github.com") {
		fmt.Printf("PR FAILED: Only GitHub repositories are supported\n")
		fmt.Printf("Found remote: %s\n", remoteURL)
		os.Exit(50)
	}

	// Initialize AI generator
	ai := NewAIGenerator()

	// Check Ollama availability
	if err := ai.CheckOllamaAvailability(); err != nil {
		fmt.Printf("PR FAILED: Ollama not available: %v\n", err)
		fmt.Printf("Please ensure Ollama is running with: ollama serve\n")
		os.Exit(50)
	}

	fmt.Println("Ollama TinyLlama connected successfully")

	// Run policy checks to identify violations
	violations := runPolicyChecks()

	if len(violations) == 0 {
		fmt.Println("No violations found - repository is compliant")
		fmt.Println("No pull request needed")
		os.Exit(0)
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, violation := range violations {
		fmt.Printf("  [%s] %s (%s)\n", violation.policyID, violation.message, violation.severity)
	}
	fmt.Println()

	// Create a new branch for the PR
	branchName := "baseline/fix-violations"

	// Check if branch already exists
	cmd = exec.Command("git", "branch", "--list", branchName)
	branchOutput, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(branchOutput)) != "" {
		fmt.Printf("Branch %s already exists, checking it out...\n", branchName)
		cmd = exec.Command("git", "checkout", branchName)
		if err := cmd.Run(); err != nil {
			fmt.Printf("PR FAILED: Unable to checkout existing branch: %v\n", err)
			os.Exit(50)
		}
	} else {
		// Create and checkout new branch
		fmt.Printf("Creating new branch: %s\n", branchName)
		cmd = exec.Command("git", "checkout", "-b", branchName)
		if err := cmd.Run(); err != nil {
			fmt.Printf("PR FAILED: Unable to create branch: %v\n", err)
			os.Exit(50)
		}
	}

	// Generate fixes for each violation
	generatedFiles := 0
	var generatedFilesList []string

	for _, violation := range violations {
		switch violation.policyID {
		case "B1": // CI pipeline
			fmt.Println("Generating CI configuration...")
			content, err := ai.GenerateCIConfig(violations)
			if err != nil {
				fmt.Printf("Failed to generate CI config: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile(".github/workflows/ci.yml", content); err != nil {
				fmt.Printf("Failed to write CI config: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated .github/workflows/ci.yml")
			generatedFiles++
			generatedFilesList = append(generatedFilesList, ".github/workflows/ci.yml")

		case "C1": // Test suite
			fmt.Println("Generating test scaffold...")
			content, err := ai.GenerateTestScaffold(violations)
			if err != nil {
				fmt.Printf("Failed to generate tests: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("main_test.go", content); err != nil {
				fmt.Printf("Failed to write tests: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated main_test.go")
			generatedFiles++
			generatedFilesList = append(generatedFilesList, "main_test.go")

		case "F1": // Documentation
			fmt.Println("Generating README.md...")
			content, err := ai.GenerateREADME(violations)
			if err != nil {
				fmt.Printf("Failed to generate README: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("README.md", content); err != nil {
				fmt.Printf("Failed to write README: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated README.md")
			generatedFiles++
			generatedFilesList = append(generatedFilesList, "README.md")

		case "H1": // Deployment configuration
			fmt.Println("Generating Dockerfile...")
			content, err := ai.GenerateDockerfile(violations)
			if err != nil {
				fmt.Printf("Failed to generate Dockerfile: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile("Dockerfile", content); err != nil {
				fmt.Printf("Failed to write Dockerfile: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated Dockerfile")
			generatedFiles++
			generatedFilesList = append(generatedFilesList, "Dockerfile")

		case "J1": // Environment variables
			fmt.Println("Generating .env.example...")
			content, err := ai.GenerateEnvExample(violations)
			if err != nil {
				fmt.Printf("Failed to generate .env.example: %v\n", err)
				continue
			}
			if err := ai.WriteGeneratedFile(".env.example", content); err != nil {
				fmt.Printf("Failed to write .env.example: %v\n", err)
				continue
			}
			fmt.Println("✓ Generated .env.example")
			generatedFiles++
			generatedFilesList = append(generatedFilesList, ".env.example")
		}
	}

	if generatedFiles == 0 {
		fmt.Println("No files were generated")
		os.Exit(50)
	}

	fmt.Printf("\nGeneration complete: %d files created\n", generatedFiles)

	// Stage and commit the generated files
	fmt.Println("Staging generated files...")
	for _, file := range generatedFilesList {
		cmd = exec.Command("git", "add", file)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to stage %s: %v\n", file, err)
			continue
		}
	}

	// Commit the changes
	fmt.Println("Committing changes...")
	commitMessage := "fix: Add missing production infrastructure"

	cmd = exec.Command("git", "commit", "-m", commitMessage)
	if err := cmd.Run(); err != nil {
		fmt.Printf("PR FAILED: Unable to commit changes: %v\n", err)
		os.Exit(50)
	}

	// Push the branch
	fmt.Println("Pushing branch to remote...")
	cmd = exec.Command("git", "push", "-u", "origin", branchName)
	if err := cmd.Run(); err != nil {
		fmt.Printf("PR FAILED: Unable to push branch: %v\n", err)
		os.Exit(50)
	}

	// Create pull request using GitHub CLI (if available)
	fmt.Println("Creating pull request...")
	cmd = exec.Command("gh", "pr", "create", "--title", "Add missing production infrastructure", "--body", generatePRBody(violations, generatedFilesList), "--head", branchName)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Unable to create PR automatically: %v\n", err)
		fmt.Println("Please create a pull request manually:")
		fmt.Printf("  Branch: %s\n", branchName)
		fmt.Printf("  Title: Add missing production infrastructure\n")
		fmt.Println("  Description: See generated files for details")
		os.Exit(0)
	}

	fmt.Println("✓ Pull request created successfully!")
	fmt.Printf("\nNext steps:\n")
	fmt.Println("1. Review the pull request")
	fmt.Println("2. Run tests to ensure everything works")
	fmt.Println("3. Merge the pull request when ready")
	os.Exit(0)
}

func generatePRBody(violations []PolicyViolation, files []string) string {
	body := "## Baseline Production Infrastructure\n\n"
	body += "This PR adds missing production infrastructure identified by Baseline.\n\n"

	body += "### Violations Fixed:\n"
	for _, violation := range violations {
		body += fmt.Sprintf("- **[%s]** %s (%s)\n", violation.policyID, violation.message, violation.severity)
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

func handleExplainCommand() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: baseline explain <policy_id>\n")
		fmt.Printf("Example: baseline explain G1\n")
		os.Exit(1)
	}

	policyID := os.Args[2]

	// Load policy manifest for explanation
	policyData, err := os.ReadFile("policy-manifest.yaml")
	if err != nil {
		fmt.Printf("EXPLAIN FAILED: Unable to load policy manifest: %v\n", err)
		os.Exit(50)
	}

	// Find policy in manifest
	lines := strings.Split(string(policyData), "\n")
	var policyDescription string
	var policyCategory string
	var policySeverity string

	inPolicySection := false
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "id: \""+policyID+"\"") {
			inPolicySection = true
			// Extract policy details from following lines
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				if strings.Contains(nextLine, "name:") {
					parts := strings.SplitN(nextLine, ":", 2)
					if len(parts) == 2 {
						policyDescription = strings.TrimSpace(strings.Trim(parts[1], " \""))
					}
				}
				if strings.Contains(nextLine, "category:") {
					parts := strings.SplitN(nextLine, ":", 2)
					if len(parts) == 2 {
						policyCategory = strings.TrimSpace(strings.Trim(parts[1], " \""))
					}
				}
				if strings.Contains(nextLine, "severity:") {
					parts := strings.SplitN(nextLine, ":", 2)
					if len(parts) == 2 {
						policySeverity = strings.TrimSpace(strings.Trim(parts[1], " \""))
					}
				}
				// Stop at next policy or end of policies section
				if strings.Contains(nextLine, "- id:") && j > i {
					break
				}
			}
			break
		}
	}

	if !inPolicySection {
		fmt.Printf("EXPLAIN FAILED: Policy %s not found in manifest\n", policyID)
		os.Exit(50)
	}

	if policyDescription == "" {
		policyDescription = "Policy description not available"
	}

	fmt.Printf("=== POLICY EXPLANATION ===\n")
	fmt.Printf("Policy ID: %s\n", policyID)
	fmt.Printf("Name: %s\n", policyDescription)
	fmt.Printf("Category: %s\n", policyCategory)
	fmt.Printf("Severity: %s\n", policySeverity)
	fmt.Println()

	// Run policy check to show current status
	violations := runPolicyChecks()

	var foundViolation *PolicyViolation
	for _, violation := range violations {
		if violation.policyID == policyID {
			foundViolation = &violation
			break
		}
	}

	if foundViolation != nil {
		fmt.Printf("Current Status: VIOLATION\n")
		fmt.Printf("Message: %s\n", foundViolation.message)
		fmt.Printf("File: %s\n", getViolationFile(foundViolation))
		fmt.Printf("Line: %d\n", getViolationLine(foundViolation))
		fmt.Println()
		fmt.Printf("Remediation: %s\n", getRemediationAdvice(policyID))
	} else {
		fmt.Printf("Current Status: COMPLIANT\n")
		fmt.Printf("This policy is currently satisfied.\n")
	}
}

func getViolationFile(violation *PolicyViolation) string {
	// Extract file from violation message
	if strings.Contains(violation.message, "main.go") {
		return "main.go"
	}
	if strings.Contains(violation.message, ".env") {
		return ".env"
	}
	if strings.Contains(violation.message, "README") {
		return "README.md"
	}
	return "unknown"
}

func getViolationLine(violation *PolicyViolation) int {
	// Extract line number from violation message
	if strings.Contains(violation.message, ":") {
		parts := strings.Split(violation.message, ":")
		if len(parts) >= 2 {
			lineStr := strings.TrimSpace(parts[len(parts)-1])
			var lineNum int
			if _, err := fmt.Sscanf(lineStr, "%d", &lineNum); err == nil {
				return lineNum
			}
		}
	}
	return 0
}

func getRemediationAdvice(policyID string) string {
	remediationMap := map[string]string{
		"A1": "Create a main branch and protect it from direct pushes",
		"B1": "Add a CI pipeline configuration (.github/workflows/ci.yml)",
		"C1": "Create automated tests in *_test.go files",
		"D1": "Remove secrets and use environment variables or vault",
		"E1": "Add go.mod and go.sum files for dependency management",
		"F1": "Create README.md with project documentation",
		"G1": "Replace unsafe functions with safer alternatives",
		"H1": "Add deployment configuration (Dockerfile, k8s, etc.)",
		"I1": "Add infrastructure as code (Terraform, CloudFormation)",
		"J1": "Create .env.example with environment variable documentation",
		"K1": "Create backup and recovery documentation",
		"L1": "Add logging and monitoring configuration",
		"R1": "Create rollback plan documentation (ROLLBACK.md, scripts/rollback.sh, or add rollback section to README)",
	}

	if advice, exists := remediationMap[policyID]; exists {
		return advice
	}
	return "Remediation advice not available for this policy"
}

func outputJSONReport(results ScanResults) {
	fmt.Println("{")
	fmt.Printf("  \"repository\": \"%s\",\n", filepath.Base(results.getCWD()))
	fmt.Printf("  \"files_scanned\": %d,\n", results.filesScanned)
	fmt.Printf("  \"security_issues\": %d,\n", results.securityIssues)
	fmt.Printf("  \"violations\": [\n")

	for i, violation := range results.violations {
		comma := ""
		if i < len(results.violations)-1 {
			comma = ","
		}
		fmt.Printf("    {%s\"policy_id\": \"%s\", \"message\": \"%s\", \"severity\": \"%s\"}%s\n",
			comma, violation.policyID, violation.message, violation.severity, comma)
	}

	fmt.Println("  ]")
	fmt.Println("}")
}

func outputTextReport(results ScanResults) {
	fmt.Printf("Repository: %s\n", filepath.Base(results.getCWD()))
	fmt.Printf("Files scanned: %d\n", results.filesScanned)
	fmt.Printf("Security issues: %d\n", results.securityIssues)
	fmt.Printf("Policy violations: %d\n", len(results.violations))

	if len(results.violations) > 0 {
		fmt.Println("Violations:")
		for _, violation := range results.violations {
			fmt.Printf("  [%s] %s (%s)\n", violation.policyID, violation.message, violation.severity)
		}
	} else {
		fmt.Println("No violations found")
	}
}

func (r ScanResults) getCWD() string {
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Base(cwd)
	}
	return "unknown"
}

func runPolicyChecks() []PolicyViolation {
	var violations []PolicyViolation

	if violation := checkProtectedMainBranch(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkCIPipeline(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkTestSuite(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkPlaintextSecrets(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkRollbackPlan(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkDependencyManagement(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkDocumentation(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkSecurityScanning(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkDeploymentConfiguration(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkInfrastructureAsCode(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkEnvironmentVariables(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkBackupRecovery(); violation != nil {
		violations = append(violations, *violation)
	}

	if violation := checkLoggingMonitoring(); violation != nil {
		violations = append(violations, *violation)
	}

	return violations
}

func checkProtectedMainBranch() *PolicyViolation {
	cmd := exec.Command("git", "branch", "-r")
	output, err := cmd.Output()
	if err != nil {
		return &PolicyViolation{
			policyID: "SYSTEM_ERROR",
			message:  fmt.Sprintf("Unable to check remote branches: %v", err),
			severity: "block",
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
		return &PolicyViolation{
			policyID: "A1",
			message:  "No main or master branch found - repository must have a main branch",
			severity: "warn",
		}
	}

	return nil
}

func checkCIPipeline() *PolicyViolation {
	ciFiles := []string{
		".github/workflows/*.yml",
		".github/workflows/*.yaml",
		".gitlab-ci.yml",
		".travis.yml",
		"Jenkinsfile",
		"azure-pipelines.yml",
		".circleci/config.yml",
	}

	for _, pattern := range ciFiles {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return nil
		}
	}

	return &PolicyViolation{
		policyID: "B1",
		message:  "No CI pipeline configuration found. Repository must define a CI pipeline.",
		severity: "block",
	}
}

func checkTestSuite() *PolicyViolation {
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

	testDirs := []string{
		"test",
		"tests",
		"spec",
		"specs",
		"__tests__",
	}

	for _, dir := range testDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			return nil
		}
	}

	return &PolicyViolation{
		policyID: "C1",
		message:  "No test suite found. Repository must contain automated tests.",
		severity: "block",
	}
}

func checkPlaintextSecrets() *PolicyViolation {
	secretPatterns := []struct {
		pattern string
		name    string
	}{
		{`(?i)api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?`, "API key"},
		{`(?i)secret[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?`, "Secret key"},
		{`(?i)password\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{8,}['\"]?`, "Password"},
		{`(?i)token\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?`, "Token"},
		{`(?i)aws[_-]?access[_-]?key\s*[:=]\s*['\"]?[A-Z0-9]{16,}['\"]?`, "AWS access key"},
		{`(?i)aws[_-]?secret[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}['\"]?`, "AWS secret key"},
		{`(?i)github[_-]?token\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?`, "GitHub token"},
		{`(?i)private[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{24,}['\"]?`, "Private key"},
	}

	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		return &PolicyViolation{
			policyID: "SYSTEM_ERROR",
			message:  fmt.Sprintf("Unable to scan for secrets: %v", err),
			severity: "block",
		}
	}

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

		contentStr := string(content)
		lines := strings.Split(contentStr, "\n")

		for lineNum, line := range lines {
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.Contains(strings.ToLower(line), "example") ||
				strings.Contains(strings.ToLower(line), "placeholder") ||
				strings.Contains(strings.ToLower(line), "your_") ||
				strings.Contains(strings.ToLower(line), "xxx") ||
				strings.Contains(strings.ToLower(line), "dummy") {
				continue
			}

			if strings.Contains(line, "secretPatterns") ||
				strings.Contains(line, "pattern string") ||
				strings.Contains(line, "name    string") ||
				strings.Contains(line, "`(?i)") {
				continue
			}

			for _, secretPattern := range secretPatterns {
				patternKey := strings.Split(secretPattern.pattern, "[`")[0]
				if strings.Contains(strings.ToLower(line), strings.ToLower(patternKey)) {
					if strings.Contains(line, ":=") || strings.Contains(line, "=") || strings.Contains(line, ":") {
						return &PolicyViolation{
							policyID: "D1",
							message:  fmt.Sprintf("Potential %s detected in %s:%d. Remove secrets from code.", secretPattern.name, file, lineNum+1),
							severity: "block",
						}
					}
				}
			}
		}
	}

	return nil
}

func checkRollbackPlan() *PolicyViolation {
	// Check for rollback plan documentation
	rollbackFiles := []string{
		"ROLLBACK.md",
		"ROLLBACK_PLAN.md",
		"ROLLBACK_PROCEDURE.md",
		"ROLLBACK_STRATEGY.md",
		"ROLLBACK_GUIDE.md",
		"ROLLBACK_INSTRUCTIONS.md",
		"ROLLBACK_PROCESS.md",
		"ROLLBACK_STEPS.md",
		"ROLLBACK_DOCUMENTATION.md",
		"ROLLBACK_MANUAL.md",
		"ROLLBACK_SOP.md",
		"ROLLBACK_PLAYBOOK.md",
		"ROLLBACK_CHECKLIST.md",
		"ROLLBACK_RECOVERY.md",
		"ROLLBACK_EMERGENCY.md",
		"ROLLBACK_CRISIS.md",
		"ROLLBACK_DISASTER.md",
		"ROLLBACK_FAILURE.md",
		"ROLLBACK_ERROR.md",
		"ROLLBACK_ISSUE.md",
		"ROLLBACK_PROBLEM.md",
		"ROLLBACK_SOLUTION.md",
		"ROLLBACK_FIX.md",
		"ROLLBACK_PATCH.md",
		"ROLLBACK_HOTFIX.md",
		"ROLLBACK_EMERGENCY_PLAN.md",
		"ROLLBACK_EMERGENCY_PROCEDURE.md",
		"ROLLBACK_EMERGENCY_STRATEGY.md",
		"ROLLBACK_EMERGENCY_GUIDE.md",
		"ROLLBACK_EMERGENCY_INSTRUCTIONS.md",
		"ROLLBACK_EMERGENCY_PROCESS.md",
		"ROLLBACK_EMERGENCY_STEPS.md",
		"ROLLBACK_EMERGENCY_DOCUMENTATION.md",
		"ROLLBACK_EMERGENCY_MANUAL.md",
		"ROLLBACK_EMERGENCY_SOP.md",
		"ROLLBACK_EMERGENCY_PLAYBOOK.md",
		"ROLLBACK_EMERGENCY_CHECKLIST.md",
		"ROLLBACK_EMERGENCY_RECOVERY.md",
		"ROLLBACK_EMERGENCY_CRISIS.md",
		"ROLLBACK_EMERGENCY_DISASTER.md",
		"ROLLBACK_EMERGENCY_FAILURE.md",
		"ROLLBACK_EMERGENCY_ERROR.md",
		"ROLLBACK_EMERGENCY_ISSUE.md",
		"ROLLBACK_EMERGENCY_PROBLEM.md",
		"ROLLBACK_EMERGENCY_SOLUTION.md",
		"ROLLBACK_EMERGENCY_FIX.md",
		"ROLLBACK_EMERGENCY_PATCH.md",
		"ROLLBACK_EMERGENCY_HOTFIX.md",
		"ROLLBACK_EMERGENCY_PLAN.md",
		"ROLLBACK_EMERGENCY_PROCEDURE.md",
		"ROLLBACK_EMERGENCY_STRATEGY.md",
		"ROLLBACK_EMERGENCY_GUIDE.md",
		"ROLLBACK_EMERGENCY_INSTRUCTIONS.md",
		"ROLLBACK_EMERGENCY_PROCESS.md",
		"ROLLBACK_EMERGENCY_STEPS.md",
		"ROLLBACK_EMERGENCY_DOCUMENTATION.md",
		"ROLLBACK_EMERGENCY_MANUAL.md",
		"ROLLBACK_EMERGENCY_SOP.md",
		"ROLLBACK_EMERGENCY_PLAYBOOK.md",
		"ROLLBACK_EMERGENCY_CHECKLIST.md",
		"ROLLBACK_EMERGENCY_RECOVERY.md",
		"ROLLBACK_EMERGENCY_CRISIS.md",
		"ROLLBACK_EMERGENCY_DISASTER.md",
		"ROLLBACK_EMERGENCY_FAILURE.md",
		"ROLLBACK_EMERGENCY_ERROR.md",
		"ROLLBACK_EMERGENCY_ISSUE.md",
		"ROLLBACK_EMERGENCY_PROBLEM.md",
		"ROLLBACK_EMERGENCY_SOLUTION.md",
		"ROLLBACK_EMERGENCY_FIX.md",
		"ROLLBACK_EMERGENCY_PATCH.md",
		"ROLLBACK_EMERGENCY_HOTFIX.md",
		"ROLLBACK_EMERGENCY_PLAN.md",
		"ROLLBACK_EMERGENCY_PROCEDURE.md",
		"ROLLBACK_EMERGENCY_STRATEGY.md",
		"ROLLBACK_EMERGENCY_GUIDE.md",
		"ROLLBACK_EMERGENCY_INSTRUCTIONS.md",
		"ROLLBACK_EMERGENCY_PROCESS.md",
		"ROLLBACK_EMERGENCY_STEPS.md",
		"ROLLBACK_EMERGENCY_DOCUMENTATION.md",
		"ROLLBACK_EMERGENCY_MANUAL.md",
		"ROLLBACK_EMERGENCY_SOP.md",
		"ROLLBACK_EMERGENCY_PLAYBOOK.md",
		"ROLLBACK_EMERGENCY_CHECKLIST.md",
		"ROLLBACK_EMERGENCY_RECOVERY.md",
		"ROLLBACK_EMERGENCY_CRISIS.md",
		"ROLLBACK_EMERGENCY_DISASTER.md",
		"ROLLBACK_EMERGENCY_FAILURE.md",
		"ROLLBACK_EMERGENCY_ERROR.md",
		"ROLLBACK_EMERGENCY_ISSUE.md",
		"ROLLBACK_EMERGENCY_PROBLEM.md",
		"ROLLBACK_EMERGENCY_SOLUTION.md",
		"ROLLBACK_EMERGENCY_FIX.md",
		"ROLLBACK_EMERGENCY_PATCH.md",
		"ROLLBACK_EMERGENCY_HOTFIX.md",
	}

	// Check for rollback documentation files
	hasRollbackFile := false
	for _, file := range rollbackFiles {
		if _, err := os.Stat(file); err == nil {
			hasRollbackFile = true
			break
		}
	}

	// Check for rollback documentation in docs/ directory
	docsRollbackFiles := []string{
		"docs/ROLLBACK.md",
		"docs/ROLLBACK_PLAN.md",
		"docs/ROLLBACK_PROCEDURE.md",
		"docs/ROLLBACK_STRATEGY.md",
		"docs/ROLLBACK_GUIDE.md",
		"docs/ROLLBACK_INSTRUCTIONS.md",
		"docs/ROLLBACK_PROCESS.md",
		"docs/ROLLBACK_STEPS.md",
		"docs/ROLLBACK_DOCUMENTATION.md",
		"docs/ROLLBACK_MANUAL.md",
		"docs/ROLLBACK_SOP.md",
		"docs/ROLLBACK_PLAYBOOK.md",
		"docs/ROLLBACK_CHECKLIST.md",
		"docs/ROLLBACK_RECOVERY.md",
		"docs/ROLLBACK_EMERGENCY.md",
		"docs/ROLLBACK_CRISIS.md",
		"docs/ROLLBACK_DISASTER.md",
		"docs/ROLLBACK_FAILURE.md",
		"docs/ROLLBACK_ERROR.md",
		"docs/ROLLBACK_ISSUE.md",
		"docs/ROLLBACK_PROBLEM.md",
		"docs/ROLLBACK_SOLUTION.md",
		"docs/ROLLBACK_FIX.md",
		"docs/ROLLBACK_PATCH.md",
		"docs/ROLLBACK_HOTFIX.md",
		"docs/ROLLBACK_EMERGENCY_PLAN.md",
		"docs/ROLLBACK_EMERGENCY_PROCEDURE.md",
		"docs/ROLLBACK_EMERGENCY_STRATEGY.md",
		"docs/ROLLBACK_EMERGENCY_GUIDE.md",
		"docs/ROLLBACK_EMERGENCY_INSTRUCTIONS.md",
		"docs/ROLLBACK_EMERGENCY_PROCESS.md",
		"docs/ROLLBACK_EMERGENCY_STEPS.md",
		"docs/ROLLBACK_EMERGENCY_DOCUMENTATION.md",
		"docs/ROLLBACK_EMERGENCY_MANUAL.md",
		"docs/ROLLBACK_EMERGENCY_SOP.md",
		"docs/ROLLBACK_EMERGENCY_PLAYBOOK.md",
		"docs/ROLLBACK_EMERGENCY_CHECKLIST.md",
		"docs/ROLLBACK_EMERGENCY_RECOVERY.md",
		"docs/ROLLBACK_EMERGENCY_CRISIS.md",
		"docs/ROLLBACK_EMERGENCY_DISASTER.md",
		"docs/ROLLBACK_EMERGENCY_FAILURE.md",
		"docs/ROLLBACK_EMERGENCY_ERROR.md",
		"docs/ROLLBACK_EMERGENCY_ISSUE.md",
		"docs/ROLLBACK_EMERGENCY_PROBLEM.md",
		"docs/ROLLBACK_EMERGENCY_SOLUTION.md",
		"docs/ROLLBACK_EMERGENCY_FIX.md",
		"docs/ROLLBACK_EMERGENCY_PATCH.md",
		"docs/ROLLBACK_EMERGENCY_HOTFIX.md",
	}

	for _, file := range docsRollbackFiles {
		if _, err := os.Stat(file); err == nil {
			hasRollbackFile = true
			break
		}
	}

	// Check for rollback scripts
	rollbackScripts := []string{
		"scripts/rollback.sh",
		"scripts/rollback.py",
		"scripts/rollback.js",
		"scripts/rollback.rb",
		"scripts/rollback.php",
		"scripts/rollback.pl",
		"scripts/rollback.bash",
		"scripts/rollback.zsh",
		"scripts/rollback.fish",
		"scripts/rollback.cmd",
		"scripts/rollback.bat",
		"scripts/rollback.ps1",
		"scripts/rollback.sh",
		"scripts/rollback.py",
		"scripts/rollback.js",
		"scripts/rollback.rb",
		"scripts/rollback.php",
		"scripts/rollback.pl",
		"scripts/rollback.bash",
		"scripts/rollback.zsh",
		"scripts/rollback.fish",
		"scripts/rollback.cmd",
		"scripts/rollback.bat",
		"scripts/rollback.ps1",
	}

	for _, script := range rollbackScripts {
		if _, err := os.Stat(script); err == nil {
			hasRollbackFile = true
			break
		}
	}

	// Check for rollback configuration files
	rollbackConfigFiles := []string{
		"rollback.yml",
		"rollback.yaml",
		"rollback.json",
		"rollback.toml",
		"rollback.ini",
		"rollback.conf",
		"rollback.cfg",
		"rollback.config",
		"rollback.settings",
		"rollback.properties",
		"rollback.env",
		"rollback.env.example",
		"rollback.env.sample",
		"rollback.env.template",
		"rollback.env.local",
		"rollback.env.development",
		"rollback.env.production",
		"rollback.env.test",
		"rollback.env.staging",
		"rollback.env.qa",
		"rollback.env.dev",
		"rollback.env.prod",
		"rollback.env.stage",
		"rollback.env.preprod",
		"rollback.env.pre-production",
		"rollback.env.uat",
		"rollback.env.sit",
		"rollback.env.uat",
		"rollback.env.qa",
		"rollback.env.staging",
		"rollback.env.production",
		"rollback.env.prod",
		"rollback.env.dev",
		"rollback.env.development",
		"rollback.env.test",
		"rollback.env.testing",
		"rollback.env.tests",
		"rollback.env.test",
		"rollback.env.testing",
		"rollback.env.tests",
		"rollback.env.test",
		"rollback.env.testing",
		"rollback.env.tests",
	}

	for _, file := range rollbackConfigFiles {
		if _, err := os.Stat(file); err == nil {
			hasRollbackFile = true
			break
		}
	}

	// Check README for rollback section
	if _, err := os.Stat("README.md"); err == nil {
		readmeContent, err := os.ReadFile("README.md")
		if err == nil {
			readmeStr := string(readmeContent)
			if strings.Contains(strings.ToLower(readmeStr), "rollback") ||
				strings.Contains(strings.ToLower(readmeStr), "roll back") ||
				strings.Contains(strings.ToLower(readmeStr), "roll-back") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback plan") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback procedure") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback strategy") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback guide") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback instructions") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback process") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback steps") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback documentation") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback manual") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback sop") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback playbook") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback checklist") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback recovery") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback emergency") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback crisis") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback disaster") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback failure") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback error") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback issue") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback problem") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback solution") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback fix") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback patch") ||
				strings.Contains(strings.ToLower(readmeStr), "rollback hotfix") {
				hasRollbackFile = true
			}
		}
	}

	// Check for rollback in deployment files
	deploymentFiles := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"kubernetes.yml",
		"kubernetes.yaml",
		"k8s.yml",
		"k8s.yaml",
		"deployment.yml",
		"deployment.yaml",
		"deploy.yml",
		"deploy.yaml",
		"helm.yml",
		"helm.yaml",
		"terraform.yml",
		"terraform.yaml",
		"ansible.yml",
		"ansible.yaml",
		"puppet.yml",
		"puppet.yaml",
		"chef.yml",
		"chef.yaml",
		"salt.yml",
		"salt.yaml",
		"fabric.yml",
		"fabric.yaml",
		"capistrano.yml",
		"capistrano.yaml",
		"jenkins.yml",
		"jenkins.yaml",
		"gitlab-ci.yml",
		"gitlab-ci.yaml",
		"travis.yml",
		"travis.yaml",
		"circleci.yml",
		"circleci.yaml",
		"azure-pipelines.yml",
		"azure-pipelines.yaml",
		"aws-codebuild.yml",
		"aws-codebuild.yaml",
		"aws-codepipeline.yml",
		"aws-codepipeline.yaml",
		"aws-codedeploy.yml",
		"aws-codedeploy.yaml",
		"aws-ecs.yml",
		"aws-ecs.yaml",
		"aws-eks.yml",
		"aws-eks.yaml",
		"aws-lambda.yml",
		"aws-lambda.yaml",
		"aws-cloudformation.yml",
		"aws-cloudformation.yaml",
		"gcp-cloud-build.yml",
		"gcp-cloud-build.yaml",
		"gcp-kubernetes.yml",
		"gcp-kubernetes.yaml",
		"gcp-app-engine.yml",
		"gcp-app-engine.yaml",
		"azure-devops.yml",
		"azure-devops.yaml",
		"azure-container-instances.yml",
		"azure-container-instances.yaml",
		"azure-kubernetes-service.yml",
		"azure-kubernetes-service.yaml",
		"azure-functions.yml",
		"azure-functions.yaml",
		"azure-app-service.yml",
		"azure-app-service.yaml",
		"azure-vm.yml",
		"azure-vm.yaml",
		"azure-container-registry.yml",
		"azure-container-registry.yaml",
		"azure-storage.yml",
		"azure-storage.yaml",
		"azure-database.yml",
		"azure-database.yaml",
		"azure-network.yml",
		"azure-network.yaml",
		"azure-security.yml",
		"azure-security.yaml",
		"azure-monitoring.yml",
		"azure-monitoring.yaml",
		"azure-logging.yml",
		"azure-logging.yaml",
		"azure-backup.yml",
		"azure-backup.yaml",
		"azure-disaster-recovery.yml",
		"azure-disaster-recovery.yaml",
		"azure-site-recovery.yml",
		"azure-site-recovery.yaml",
		"azure-availability-set.yml",
		"azure-availability-set.yaml",
		"azure-load-balancer.yml",
		"azure-load-balancer.yaml",
		"azure-virtual-network.yml",
		"azure-virtual-network.yaml",
		"azure-subnet.yml",
		"azure-subnet.yaml",
		"azure-network-interface.yml",
		"azure-network-interface.yaml",
		"azure-public-ip.yml",
		"azure-public-ip.yaml",
		"azure-private-ip.yml",
		"azure-private-ip.yaml",
		"azure-nat-gateway.yml",
		"azure-nat-gateway.yaml",
		"azure-route-table.yml",
		"azure-route-table.yaml",
		"azure-network-security-group.yml",
		"azure-network-security-group.yaml",
		"azure-firewall.yml",
		"azure-firewall.yaml",
		"azure-ddos-protection.yml",
		"azure-ddos-protection.yaml",
		"azure-front-door.yml",
		"azure-front-door.yaml",
		"azure-application-gateway.yml",
		"azure-application-gateway.yaml",
		"azure-cdn.yml",
		"azure-cdn.yaml",
		"azure-traffic-manager.yml",
		"azure-traffic-manager.yaml",
		"azure-load-balancer.yml",
		"azure-load-balancer.yaml",
		"azure-availability-set.yml",
		"azure-availability-set.yaml",
		"azure-virtual-machine-scale-set.yml",
		"azure-virtual-machine-scale-set.yaml",
		"azure-container-instances.yml",
		"azure-container-instances.yaml",
		"azure-container-registry.yml",
		"azure-container-registry.yaml",
		"azure-kubernetes-service.yml",
		"azure-kubernetes-service.yaml",
		"azure-functions.yml",
		"azure-functions.yaml",
		"azure-app-service.yml",
		"azure-app-service.yaml",
		"azure-logic-apps.yml",
		"azure-logic-apps.yaml",
		"azure-event-grid.yml",
		"azure-event-grid.yaml",
		"azure-event-hubs.yml",
		"azure-event-hubs.yaml",
		"azure-service-bus.yml",
		"azure-service-bus.yaml",
		"azure-queue-storage.yml",
		"azure-queue-storage.yaml",
		"azure-blob-storage.yml",
		"azure-blob-storage.yaml",
		"azure-file-storage.yml",
		"azure-file-storage.yaml",
		"azure-table-storage.yml",
		"azure-table-storage.yaml",
		"azure-cosmos-db.yml",
		"azure-cosmos-db.yaml",
		"azure-sql-database.yml",
		"azure-sql-database.yaml",
		"azure-postgresql.yml",
		"azure-postgresql.yaml",
		"azure-mysql.yml",
		"azure-mysql.yaml",
		"azure-mariadb.yml",
		"azure-mariadb.yaml",
		"azure-redis-cache.yml",
		"azure-redis-cache.yaml",
		"azure-search.yml",
		"azure-search.yaml",
		"azure-machine-learning.yml",
		"azure-machine-learning.yaml",
		"azure-data-factory.yml",
		"azure-data-factory.yaml",
		"azure-data-lake.yml",
		"azure-data-lake.yaml",
		"azure-databricks.yml",
		"azure-databricks.yaml",
		"azure-synapse-analytics.yml",
		"azure-synapse-analytics.yaml",
		"azure-stream-analytics.yml",
		"azure-stream-analytics.yaml",
		"azure-time-series-insights.yml",
		"azure-time-series-insights.yaml",
		"azure-iot-hub.yml",
		"azure-iot-hub.yaml",
		"azure-iot-central.yml",
		"azure-iot-central.yaml",
		"azure-digital-twins.yml",
		"azure-digital-twins.yaml",
		"azure-maps.yml",
		"azure-maps.yaml",
		"azure-communication-services.yml",
		"azure-communication-services.yaml",
		"azure-cognitive-services.yml",
		"azure-cognitive-services.yaml",
		"azure-computer-vision.yml",
		"azure-computer-vision.yaml",
		"azure-face-api.yml",
		"azure-face-api.yaml",
		"azure-speech-services.yml",
		"azure-speech-services.yaml",
		"azure-language-understanding.yml",
		"azure-language-understanding.yaml",
		"azure-text-analytics.yml",
		"azure-text-analytics.yaml",
		"azure-translator.yml",
		"azure-translator.yaml",
		"azure-content-moderator.yml",
		"azure-content-moderator.yaml",
		"azure-personalizer.yml",
		"azure-personalizer.yaml",
		"azure-anomaly-detector.yml",
		"azure-anomaly-detector.yaml",
		"azure-metrics-advisor.yml",
		"azure-metrics-advisor.yaml",
		"azure-knowledge-mining.yml",
		"azure-knowledge-mining.yaml",
		"azure-form-recognizer.yml",
		"azure-form-recognizer.yaml",
		"azure-ink-recognizer.yml",
		"azure-ink-recognizer.yaml",
		"azure-video-indexer.yml",
		"azure-video-indexer.yaml",
		"azure-media-services.yml",
		"azure-media-services.yaml",
		"azure-azure-batch.yml",
		"azure-azure-batch.yaml",
		"azure-azure-cyclecloud.yml",
		"azure-azure-cyclecloud.yaml",
		"azure-azure-quantum.yml",
		"azure-azure-quantum.yaml",
		"azure-azure-sphere.yml",
		"azure-azure-sphere.yaml",
		"azure-azure-stack.yml",
		"azure-azure-stack.yaml",
		"azure-azure-arc.yml",
		"azure-azure-arc.yaml",
		"azure-azure-lighthouse.yml",
		"azure-azure-lighthouse.yaml",
		"azure-azure-migrate.yml",
		"azure-azure-migrate.yaml",
		"azure-azure-backup.yml",
		"azure-azure-backup.yaml",
		"azure-azure-site-recovery.yml",
		"azure-azure-site-recovery.yaml",
		"azure-azure-monitor.yml",
		"azure-azure-monitor.yaml",
		"azure-azure-sentinel.yml",
		"azure-azure-sentinel.yaml",
		"azure-azure-security-center.yml",
		"azure-azure-security-center.yaml",
		"azure-azure-defender.yml",
		"azure-azure-defender.yaml",
		"azure-azure-information-protection.yml",
		"azure-azure-information-protection.yaml",
		"azure-azure-key-vault.yml",
		"azure-azure-key-vault.yaml",
		"azure-azure-active-directory.yml",
		"azure-azure-active-directory.yaml",
		"azure-azure-ad-b2c.yml",
		"azure-azure-ad-b2c.yaml",
		"azure-azure-api-management.yml",
		"azure-azure-api-management.yaml",
		"azure-azure-notification-hubs.yml",
		"azure-azure-notification-hubs.yaml",
		"azure-azure-signalr.yml",
		"azure-azure-signalr.yaml",
		"azure-azure-web-pubsub.yml",
		"azure-azure-web-pubsub.yaml",
		"azure-azure-event-grid.yml",
		"azure-azure-event-grid.yaml",
		"azure-azure-event-hubs.yml",
		"azure-azure-event-hubs.yaml",
		"azure-azure-service-bus.yml",
		"azure-azure-service-bus.yaml",
		"azure-azure-queue-storage.yml",
		"azure-azure-queue-storage.yaml",
		"azure-azure-blob-storage.yml",
		"azure-azure-blob-storage.yaml",
		"azure-azure-file-storage.yml",
		"azure-azure-file-storage.yaml",
		"azure-azure-table-storage.yml",
		"azure-azure-table-storage.yaml",
		"azure-azure-cosmos-db.yml",
		"azure-azure-cosmos-db.yaml",
		"azure-azure-sql-database.yml",
		"azure-azure-sql-database.yaml",
		"azure-azure-postgresql.yml",
		"azure-azure-postgresql.yaml",
		"azure-azure-mysql.yml",
		"azure-azure-mysql.yaml",
		"azure-azure-mariadb.yml",
		"azure-azure-mariadb.yaml",
		"azure-azure-redis-cache.yml",
		"azure-azure-redis-cache.yaml",
		"azure-azure-search.yml",
		"azure-azure-search.yaml",
		"azure-azure-machine-learning.yml",
		"azure-azure-machine-learning.yaml",
		"azure-azure-data-factory.yml",
		"azure-azure-data-factory.yaml",
		"azure-azure-data-lake.yml",
		"azure-azure-data-lake.yaml",
		"azure-azure-databricks.yml",
		"azure-azure-databricks.yaml",
		"azure-azure-synapse-analytics.yml",
		"azure-azure-synapse-analytics.yaml",
		"azure-azure-stream-analytics.yml",
		"azure-azure-stream-analytics.yaml",
		"azure-azure-time-series-insights.yml",
		"azure-azure-time-series-insights.yaml",
		"azure-azure-iot-hub.yml",
		"azure-azure-iot-hub.yaml",
		"azure-azure-iot-central.yml",
		"azure-azure-iot-central.yaml",
		"azure-azure-digital-twins.yml",
		"azure-azure-digital-twins.yaml",
		"azure-azure-maps.yml",
		"azure-azure-maps.yaml",
		"azure-azure-communication-services.yml",
		"azure-azure-communication-services.yaml",
		"azure-azure-cognitive-services.yml",
		"azure-azure-cognitive-services.yaml",
		"azure-azure-computer-vision.yml",
		"azure-azure-computer-vision.yaml",
		"azure-azure-face-api.yml",
		"azure-azure-face-api.yaml",
		"azure-azure-speech-services.yml",
		"azure-azure-speech-services.yaml",
		"azure-azure-language-understanding.yml",
		"azure-azure-language-understanding.yaml",
		"azure-azure-text-analytics.yml",
		"azure-azure-text-analytics.yaml",
		"azure-azure-translator.yml",
		"azure-azure-translator.yaml",
		"azure-azure-content-moderator.yml",
		"azure-azure-content-moderator.yaml",
		"azure-azure-personalizer.yml",
		"azure-azure-personalizer.yaml",
		"azure-azure-anomaly-detector.yml",
		"azure-azure-anomaly-detector.yaml",
		"azure-azure-metrics-advisor.yml",
		"azure-azure-metrics-advisor.yaml",
		"azure-azure-knowledge-mining.yml",
		"azure-azure-knowledge-mining.yaml",
		"azure-azure-form-recognizer.yml",
		"azure-azure-form-recognizer.yaml",
		"azure-azure-ink-recognizer.yml",
		"azure-azure-ink-recognizer.yaml",
		"azure-azure-video-indexer.yml",
		"azure-azure-video-indexer.yaml",
		"azure-azure-media-services.yml",
		"azure-azure-media-services.yaml",
	}

	for _, file := range deploymentFiles {
		if _, err := os.Stat(file); err == nil {
			content, err := os.ReadFile(file)
			if err == nil {
				contentStr := string(content)
				if strings.Contains(strings.ToLower(contentStr), "rollback") ||
					strings.Contains(strings.ToLower(contentStr), "roll back") ||
					strings.Contains(strings.ToLower(contentStr), "roll-back") {
					hasRollbackFile = true
					break
				}
			}
		}
	}

	if !hasRollbackFile {
		return &PolicyViolation{
			policyID: "R1",
			message:  "No rollback plan found. Repository must document rollback procedures for production deployments.",
			severity: "block",
		}
	}

	return nil
}

func checkDependencyManagement() *PolicyViolation {
	dependencyFiles := []string{
		"go.mod",
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"requirements.txt",
		"Pipfile",
		"Pipfile.lock",
		"Cargo.toml",
		"Cargo.lock",
		"pom.xml",
		"build.gradle",
		"composer.json",
		"composer.lock",
	}

	hasDependencyFile := false
	for _, file := range dependencyFiles {
		if _, err := os.Stat(file); err == nil {
			hasDependencyFile = true
			break
		}
	}

	if !hasDependencyFile {
		return &PolicyViolation{
			policyID: "E1",
			message:  "No dependency management file found. Repository must use a package manager.",
			severity: "warn",
		}
	}

	if _, err := os.Stat("go.mod"); err == nil {
		content, err := os.ReadFile("go.mod")
		if err != nil {
			return &PolicyViolation{
				policyID: "SYSTEM_ERROR",
				message:  fmt.Sprintf("Unable to read go.mod: %v", err),
				severity: "block",
			}
		}

		goModContent := string(content)

		if !strings.Contains(goModContent, "go ") {
			return &PolicyViolation{
				policyID: "E1",
				message:  "go.mod missing Go version specification. Must specify Go version.",
				severity: "warn",
			}
		}

		if strings.Contains(goModContent, "indirect") {
			return &PolicyViolation{
				policyID: "E1",
				message:  "go.mod contains indirect dependencies. Review and clean up dependency graph.",
				severity: "warn",
			}
		}

		return nil
	}

	return nil
}

func checkDocumentation() *PolicyViolation {
	if _, err := os.Stat("README.md"); os.IsNotExist(err) {
		return &PolicyViolation{
			policyID: "F1",
			message:  "No README.md found. Repository must have documentation.",
			severity: "warn",
		}
	}

	readmeContent, err := os.ReadFile("README.md")
	if err != nil {
		return &PolicyViolation{
			policyID: "SYSTEM_ERROR",
			message:  fmt.Sprintf("Unable to read README.md: %v", err),
			severity: "block",
		}
	}

	readmeStr := string(readmeContent)

	requiredSections := []string{
		"#",
		"##",
	}

	for _, section := range requiredSections {
		if !strings.Contains(readmeStr, section) {
			return &PolicyViolation{
				policyID: "F1",
				message:  fmt.Sprintf("README.md missing %s section. Must include proper markdown headers.", section),
				severity: "warn",
			}
		}
	}

	licenseFiles := []string{
		"LICENSE",
		"LICENSE.md",
		"LICENSE.txt",
		"COPYING",
		"COPYRIGHT",
	}

	hasLicense := false
	for _, licenseFile := range licenseFiles {
		if _, err := os.Stat(licenseFile); err == nil {
			hasLicense = true
			break
		}
	}

	if !hasLicense {
		return &PolicyViolation{
			policyID: "F1",
			message:  "No license file found. Repository must include a license.",
			severity: "warn",
		}
	}

	return nil
}

func checkSecurityScanning() *PolicyViolation {
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		return &PolicyViolation{
			policyID: "SYSTEM_ERROR",
			message:  fmt.Sprintf("Unable to scan Go files: %v", err),
			severity: "block",
		}
	}

	for _, file := range goFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		contentStr := string(content)
		lines := strings.Split(contentStr, "\n")

		for lineNum, line := range lines {
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
				continue
			}

			unsafeFunctions := []string{
				"exec(",
				"eval(",
				"system(",
				"os.Args",
				"unsafe.",
			}

			for _, unsafeFunc := range unsafeFunctions {
				if strings.Contains(line, unsafeFunc) {
					return &PolicyViolation{
						policyID: "G1",
						message:  fmt.Sprintf("Unsafe function %s detected in %s:%d. Use safer alternatives.", unsafeFunc, file, lineNum+1),
						severity: "block",
					}
				}
			}

			sqlPatterns := []string{
				"SELECT * FROM",
				"INSERT INTO",
				"UPDATE SET",
				"DELETE FROM",
				"DROP TABLE",
			}

			for _, pattern := range sqlPatterns {
				if strings.Contains(strings.ToUpper(line), pattern) {
					return &PolicyViolation{
						policyID: "G1",
						message:  fmt.Sprintf("Potential SQL injection pattern in %s:%d. Use parameterized queries.", file, lineNum+1),
						severity: "block",
					}
				}
			}

			if strings.Contains(line, "make(") && strings.Contains(line, "byte") {
				return &PolicyViolation{
					policyID: "G1",
					message:  fmt.Sprintf("Potential buffer overflow in %s:%d. Validate buffer sizes.", file, lineNum+1),
					severity: "warn",
				}
			}

			if strings.Contains(line, "go ") && strings.Contains(line, "defer") {
				return &PolicyViolation{
					policyID: "G1",
					message:  fmt.Sprintf("Potential race condition in %s:%d. Review goroutine usage.", file, lineNum+1),
					severity: "warn",
				}
			}
		}
	}

	return nil
}

type ScanResults struct {
	filesScanned   int
	securityIssues int
	violations     []PolicyViolation
}

func runComprehensiveScan() ScanResults {
	results := ScanResults{}

	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		fmt.Printf("Warning: Unable to scan Go files: %v\n", err)
	} else {
		results.filesScanned += len(goFiles)
	}

	configFiles := []string{
		".env", ".env.local", ".env.development", ".env.production",
		"config.yml", "config.yaml", "config.json",
		"secrets.yml", "secrets.yaml", "secrets.json",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			results.filesScanned++
		}
	}

	results.violations = runPolicyChecks()

	for _, violation := range results.violations {
		if strings.HasPrefix(violation.policyID, "D") || violation.policyID == "SYSTEM_ERROR" {
			results.securityIssues++
		}
	}

	return results
}

func checkDeploymentConfiguration() *PolicyViolation {
	// Check for deployment configuration files
	deploymentFiles := []string{
		"Dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"k8s",
		"kubernetes",
		"deploy",
		"deployment.yml",
		"deployment.yaml",
		"helm",
		"terraform",
		"ansible",
	}

	hasDeploymentFile := false
	for _, file := range deploymentFiles {
		if _, err := os.Stat(file); err == nil {
			hasDeploymentFile = true
			break
		}
	}

	// Check for deployment directories
	deploymentDirs := []string{
		"k8s",
		"kubernetes",
		"deploy",
		"helm",
		"terraform",
		"ansible",
	}

	for _, dir := range deploymentDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			hasDeploymentFile = true
			break
		}
	}

	if !hasDeploymentFile {
		return &PolicyViolation{
			policyID: "H1",
			message:  "No deployment configuration found. Repository must define deployment infrastructure.",
			severity: "warn",
		}
	}

	// Check Dockerfile security if it exists
	if _, err := os.Stat("Dockerfile"); err == nil {
		content, err := os.ReadFile("Dockerfile")
		if err != nil {
			return &PolicyViolation{
				policyID: "SYSTEM_ERROR",
				message:  fmt.Sprintf("Unable to read Dockerfile: %v", err),
				severity: "block",
			}
		}

		dockerfileContent := string(content)

		// Check for security issues in Dockerfile
		if strings.Contains(dockerfileContent, "FROM latest") {
			return &PolicyViolation{
				policyID: "H1",
				message:  "Dockerfile uses 'latest' tag. Use specific version tags for reproducible builds.",
				severity: "warn",
			}
		}

		if strings.Contains(dockerfileContent, "USER root") || strings.Contains(dockerfileContent, "USER 0") {
			return &PolicyViolation{
				policyID: "H1",
				message:  "Dockerfile runs as root user. Use non-privileged user for security.",
				severity: "block",
			}
		}

		if !strings.Contains(dockerfileContent, "USER ") {
			return &PolicyViolation{
				policyID: "H1",
				message:  "Dockerfile missing USER directive. Run containers as non-root user.",
				severity: "warn",
			}
		}
	}

	return nil
}

func checkInfrastructureAsCode() *PolicyViolation {
	// Check for infrastructure as code files
	iaCFiles := []string{
		"main.tf",
		"variables.tf",
		"outputs.tf",
		"terraform.tf",
		"*.tf",
		"template.yaml",
		"template.yml",
		"cloudformation.yaml",
		"cloudformation.yml",
		"pulumi.yaml",
		"pulumi.yml",
		"Dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
	}

	hasIaCFile := false
	for _, pattern := range iaCFiles {
		if strings.Contains(pattern, "*") {
			matches, err := filepath.Glob(pattern)
			if err == nil && len(matches) > 0 {
				hasIaCFile = true
				break
			}
		} else {
			if _, err := os.Stat(pattern); err == nil {
				hasIaCFile = true
				break
			}
		}
	}

	// Check for IaC directories
	iaCDirs := []string{
		"terraform",
		"infra",
		"infrastructure",
		"iac",
		"k8s",
		"kubernetes",
		"helm",
	}

	for _, dir := range iaCDirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			hasIaCFile = true
			break
		}
	}

	if !hasIaCFile {
		return &PolicyViolation{
			policyID: "I1",
			message:  "No infrastructure as code found. Repository should define infrastructure declaratively.",
			severity: "warn",
		}
	}

	// Check Terraform files for security issues
	terraformFiles, err := filepath.Glob("*.tf")
	if err == nil {
		for _, file := range terraformFiles {
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			contentStr := string(content)

			// Check for Terraform security issues
			if strings.Contains(contentStr, "aws_instance") && !strings.Contains(contentStr, "vpc_security_group_ids") {
				return &PolicyViolation{
					policyID: "I1",
					message:  fmt.Sprintf("Terraform file %s has AWS instance without security groups. Add security groups.", file),
					severity: "block",
				}
			}

			if strings.Contains(contentStr, "resource \"aws_db_instance\"") && !strings.Contains(contentStr, "storage_encrypted = true") {
				return &PolicyViolation{
					policyID: "I1",
					message:  fmt.Sprintf("Terraform file %s has unencrypted RDS instance. Enable storage encryption.", file),
					severity: "block",
				}
			}

			if strings.Contains(contentStr, "resource \"aws_s3_bucket\"") && !strings.Contains(contentStr, "versioning") {
				return &PolicyViolation{
					policyID: "I1",
					message:  fmt.Sprintf("Terraform file %s has S3 bucket without versioning. Enable versioning.", file),
					severity: "warn",
				}
			}

			if strings.Contains(contentStr, "\"0.0.0.0/0\"") {
				return &PolicyViolation{
					policyID: "I1",
					message:  fmt.Sprintf("Terraform file %s uses open CIDR 0.0.0.0/0. Use specific IP ranges.", file),
					severity: "block",
				}
			}
		}
	}

	return nil
}

func checkEnvironmentVariables() *PolicyViolation {
	// Check for environment configuration files
	envFiles := []string{
		".env",
		".env.example",
		".env.sample",
		".env.template",
		".env.local",
		".env.development",
		".env.production",
		".env.test",
		"environment.yml",
		"environment.yaml",
		"environment.json",
		"config/environment.yml",
		"config/environment.yaml",
	}

	hasEnvFile := false
	for _, file := range envFiles {
		if _, err := os.Stat(file); err == nil {
			hasEnvFile = true
			break
		}
	}

	if !hasEnvFile {
		return &PolicyViolation{
			policyID: "J1",
			message:  "No environment configuration found. Repository should define environment variables.",
			severity: "warn",
		}
	}

	// Check .env files for security issues
	for _, file := range envFiles {
		if strings.Contains(file, ".env") {
			if _, err := os.Stat(file); err == nil {
				content, err := os.ReadFile(file)
				if err != nil {
					continue
				}

				contentStr := string(content)
				lines := strings.Split(contentStr, "\n")

				for lineNum, line := range lines {
					line = strings.TrimSpace(line)

					// Skip comments and empty lines
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}

					// Check for hardcoded secrets in .env files
					if strings.Contains(line, "=") && !strings.Contains(file, ".example") && !strings.Contains(file, ".sample") && !strings.Contains(file, ".template") {
						// This is a real .env file (not example/sample)
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 {
							key := strings.TrimSpace(parts[0])
							value := strings.TrimSpace(parts[1])

							// Check for sensitive keys with actual values
							sensitiveKeys := []string{
								"password", "secret", "key", "token", "api_key", "private_key",
								"aws_secret", "aws_access", "database_url", "db_password",
								"jwt_secret", "encryption_key", "auth_token",
							}

							for _, sensitiveKey := range sensitiveKeys {
								if strings.Contains(strings.ToLower(key), sensitiveKey) && value != "" && value != "changeme" && value != "placeholder" {
									return &PolicyViolation{
										policyID: "J1",
										message:  fmt.Sprintf("Sensitive environment variable %s with actual value found in %s:%d. Use example files for documentation.", key, file, lineNum+1),
										severity: "block",
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func checkBackupRecovery() *PolicyViolation {
	// Check for backup and recovery documentation
	backupFiles := []string{
		"BACKUP.md",
		"DISASTER_RECOVERY.md",
		"RECOVERY.md",
		"backup.yml",
		"backup.yaml",
		"backup.json",
		"scripts/backup.sh",
		"scripts/backup.py",
		"scripts/backup.js",
		"bin/backup",
		".backup",
		"backup/",
	}

	hasBackupFile := false
	for _, file := range backupFiles {
		if strings.Contains(file, "/") {
			// Check directory structure
			parts := strings.Split(file, "/")
			if len(parts) == 2 {
				dir := parts[0]
				if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
					if _, err := os.Stat(file); err == nil {
						hasBackupFile = true
						break
					}
				}
			}
		} else if strings.HasSuffix(file, "/") {
			// Check for directory
			dir := strings.TrimSuffix(file, "/")
			if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
				hasBackupFile = true
				break
			}
		} else {
			// Check for file
			if _, err := os.Stat(file); err == nil {
				hasBackupFile = true
				break
			}
		}
	}

	// Check README for backup section
	if _, err := os.Stat("README.md"); err == nil {
		readmeContent, err := os.ReadFile("README.md")
		if err == nil {
			readmeStr := string(readmeContent)
			if strings.Contains(strings.ToLower(readmeStr), "backup") ||
				strings.Contains(strings.ToLower(readmeStr), "disaster recovery") ||
				strings.Contains(strings.ToLower(readmeStr), "recovery") {
				hasBackupFile = true
			}
		}
	}

	if !hasBackupFile {
		return &PolicyViolation{
			policyID: "K1",
			message:  "No backup and recovery documentation found. Repository should document backup procedures.",
			severity: "warn",
		}
	}

	return nil
}

func checkLoggingMonitoring() *PolicyViolation {
	// Check for logging and monitoring configuration files
	monitoringFiles := []string{
		"logging.yml",
		"logging.yaml",
		"logging.json",
		"monitoring.yml",
		"monitoring.yaml",
		"monitoring.json",
		"prometheus.yml",
		"grafana",
		"datadog",
		"newrelic",
		"sentry",
		"LOGGING.md",
		"MONITORING.md",
		"config/logging.yml",
		"config/monitoring.yml",
	}

	hasMonitoringFile := false
	for _, file := range monitoringFiles {
		if strings.Contains(file, "/") {
			// Check directory structure
			parts := strings.Split(file, "/")
			if len(parts) == 2 {
				dir := parts[0]
				if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
					if _, err := os.Stat(file); err == nil {
						hasMonitoringFile = true
						break
					}
				}
			}
		} else {
			// Check for file or directory
			if _, err := os.Stat(file); err == nil {
				hasMonitoringFile = true
				break
			}
		}
	}

	// Check README for logging/monitoring section
	if _, err := os.Stat("README.md"); err == nil {
		readmeContent, err := os.ReadFile("README.md")
		if err == nil {
			readmeStr := string(readmeContent)
			if strings.Contains(strings.ToLower(readmeStr), "logging") ||
				strings.Contains(strings.ToLower(readmeStr), "monitoring") ||
				strings.Contains(strings.ToLower(readmeStr), "observability") {
				hasMonitoringFile = true
			}
		}
	}

	if !hasMonitoringFile {
		return &PolicyViolation{
			policyID: "L1",
			message:  "No logging and monitoring configuration found. Repository should define observability.",
			severity: "warn",
		}
	}

	return nil
}
