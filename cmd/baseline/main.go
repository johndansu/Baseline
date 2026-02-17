// Baseline - Production Policy & Enforcement Engine
//
// Baseline enforces software fundamentals before code reaches production.
// It is a policy-driven enforcement layer that blocks unsafe behavior
// and generates compliant infrastructure via PRs.
//
// AI is used ONLY for scaffolding, never for enforcement decisions.
// All AI-generated content requires human review before use.
package main

import (
	"fmt"
	"os"

	"github.com/baseline/baseline/internal/cli"
	"github.com/baseline/baseline/internal/types"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(types.ExitSystemError)
	}

	command := os.Args[1]

	// Handle help flags
	if command == "--help" || command == "-h" {
		printUsage()
		os.Exit(0)
	}

	// Route to command handlers
	switch command {
	case "version":
		cli.HandleVersion()
	case "check":
		cli.HandleCheck()
	case "enforce":
		cli.HandleEnforce()
	case "scan":
		cli.HandleScan()
	case "init":
		cli.HandleInit()
	case "report":
		cli.HandleReport(os.Args[2:])
	case "generate":
		cli.HandleGenerate()
	case "pr":
		cli.HandlePR()
	case "explain":
		cli.HandleExplain(os.Args[2:])
	case "api":
		cli.HandleAPI(os.Args[2:])
	case "dashboard":
		cli.HandleDashboard(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(types.ExitSystemError)
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
	fmt.Println("  explain    Get explanation for policy violations")
	fmt.Println("  api        Serve Baseline API endpoints")
	fmt.Println("  dashboard  Launch local web dashboard for Baseline API")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --help, -h  Show this help message")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0   Success (no violations)")
	fmt.Println("  20  Blocking violations found")
	fmt.Println("  50  System error")
	fmt.Println()
}
