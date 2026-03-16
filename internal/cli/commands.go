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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/baseline/baseline/internal/ai"
	"github.com/baseline/baseline/internal/api"
	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/log"
	"github.com/baseline/baseline/internal/policy"
	"github.com/baseline/baseline/internal/report"
	"github.com/baseline/baseline/internal/scan"
	"github.com/baseline/baseline/internal/types"
	"github.com/baseline/baseline/internal/version"
)

const securityAdviceDisclaimer = "> AI-generated suggestions may be incorrect. Validate recommendations before implementation."

// HandleVersion prints version information.
func HandleVersion() {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("version", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runVersionCommand(traceCtx)
	}))
}

// HandleCheck runs policy checks on the repository.
func HandleCheck() {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("check", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runCheckCommand(traceCtx, connection)
	}))
}

// HandleEnforce enforces policies and blocks on violations.
func HandleEnforce() {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("enforce", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runEnforceCommand(traceCtx, connection)
	}))
}

// HandleScan performs a comprehensive repository scan.
func HandleScan(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("scan", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runScanCommand(traceCtx, connection, args)
	}))
}

func runCheckCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig) tracedCommandResult {
	startedAt := time.Now()
	gitCheckSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitCheckSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		log.Error("Git repository check failed", "error", err)
		emitCLIEvent(telemetryConnection, cliEventFromCheck("cli_error", err.Error(), "system_error", 0, time.Since(startedAt)))
		fmt.Printf("Error: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitCheckSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "failed to resolve current directory", nil)
		log.Error("Failed to get current directory", "error", err)
		emitCLIEvent(telemetryConnection, cliEventFromCheck("cli_error", "unable to get current directory: "+err.Error(), "system_error", 0, time.Since(startedAt)))
		fmt.Printf("Error: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{
		"repository": filepath.Base(cwd),
	})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	log.Info("Starting repository check", "repository", filepath.Base(cwd))
	fmt.Printf("Checking repository: %s\n", filepath.Base(cwd))
	checkSpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(checkSpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{
		"violation_count": strconv.Itoa(len(violations)),
	})

	if len(violations) > 0 {
		traceCtx.Branch("cli", "HandleCheck", "violations_found", map[string]string{
			"violation_count": strconv.Itoa(len(violations)),
		})
		log.Warn("Policy violations found", "count", len(violations))
		emitCLIEvent(telemetryConnection, cliEventFromCheck("cli_warning", "policy violations detected", "violations_found", len(violations), time.Since(startedAt)))
		fmt.Println("\nPolicy violations found:")
		for _, v := range violations {
			fmt.Printf("  [%s] %s\n", v.PolicyID, v.Message)
		}
		fmt.Printf("\nExit code: %d (blocking violations)\n", types.ExitBlockingViolation)
		return tracedCommandResult{
			ExitCode:     types.ExitBlockingViolation,
			TraceStatus:  "violations_found",
			TraceMessage: "repository check completed with policy violations",
			Attributes: map[string]string{
				"repository":      filepath.Base(cwd),
				"violation_count": strconv.Itoa(len(violations)),
			},
		}
	}

	traceCtx.Branch("cli", "HandleCheck", "clean_exit", nil)
	log.Info("No policy violations detected")
	emitCLIEvent(telemetryConnection, cliEventFromCheck("cli_health", "repository check completed cleanly", "ok", 0, time.Since(startedAt)))
	fmt.Printf("Exit code: %d (no violations)\n", types.ExitSuccess)
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "repository check completed cleanly",
		Attributes: map[string]string{
			"repository": filepath.Base(cwd),
		},
	}
}

func runScanCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	startedAt := time.Now()
	parseSpan := traceCtx.HelperEnter("cli", "parseScanArgs", "parsing scan arguments", nil)
	opts, err := parseScanArgs(args)
	if err != nil {
		traceCtx.Error("cli", "parseScanArgs", err, nil)
		traceCtx.HelperExit(parseSpan, "cli", "parseScanArgs", "error", "scan arguments invalid", nil)
		emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", err.Error(), "system_error", "", "", types.ScanResults{}, time.Since(startedAt)))
		fmt.Printf("SCAN FAILED: %v\n", err)
		printScanUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "scan arguments invalid"}
	}
	traceCtx.HelperExit(parseSpan, "cli", "parseScanArgs", "ok", "scan arguments parsed", nil)
	if opts.Help {
		traceCtx.Branch("cli", "HandleScan", "help_requested", nil)
		printScanUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "scan usage printed"}
	}
	envSpan := traceCtx.HelperEnter("cli", "loadAPIEnvFiles", "loading API environment files", nil)
	if err := loadAPIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAPIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "error", "API env loading failed", nil)
		emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", "unable to load API env file: "+err.Error(), "system_error", "", "", types.ScanResults{}, time.Since(startedAt)))
		fmt.Printf("SCAN FAILED: unable to load API env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "ok", "API env files loaded", nil)

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", err.Error(), "system_error", "", "", types.ScanResults{}, time.Since(startedAt)))
		fmt.Printf("SCAN FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	if strings.TrimSpace(opts.UploadRunKey) == "" {
		traceCtx.Branch("cli", "HandleScan", "generate_upload_run_key", nil)
		keySpan := traceCtx.HelperEnter("cli", "generateAPIKey", "generating upload run key", nil)
		runKey, err := generateAPIKey()
		if err != nil {
			traceCtx.Error("cli", "generateAPIKey", err, nil)
			traceCtx.HelperExit(keySpan, "cli", "generateAPIKey", "error", "upload run key generation failed", nil)
			emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", "unable to create upload run key: "+err.Error(), "system_error", "", "", types.ScanResults{}, time.Since(startedAt)))
			fmt.Printf("SCAN FAILED: unable to create upload run key: %v\n", err)
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "upload run key generation failed"}
		}
		traceCtx.HelperExit(keySpan, "cli", "generateAPIKey", "ok", "upload run key generated", nil)
		opts.UploadRunKey = runKey
	}
	resolveUploadSpan := traceCtx.HelperEnter("cli", "resolveDashboardUploadConfigForScan", "resolving dashboard upload config", nil)
	connection, err := resolveDashboardUploadConfigForScan(opts)
	if err != nil {
		traceCtx.Error("cli", "resolveDashboardUploadConfigForScan", err, nil)
		traceCtx.HelperExit(resolveUploadSpan, "cli", "resolveDashboardUploadConfigForScan", "error", "dashboard upload config resolution failed", nil)
		emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", "unable to load dashboard upload config: "+err.Error(), "system_error", "", "", types.ScanResults{}, time.Since(startedAt)))
		fmt.Printf("SCAN FAILED: unable to load dashboard upload config: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard upload config resolution failed"}
	}
	traceCtx.HelperExit(resolveUploadSpan, "cli", "resolveDashboardUploadConfigForScan", "ok", "dashboard upload config resolved", nil)
	if !connection.Prompted && !connection.Enabled && !scanUploadConfiguredFromEnv() {
		traceCtx.Branch("cli", "HandleScan", "dashboard_upload_prompt", nil)
		promptSpan := traceCtx.HelperEnter("cli", "maybePromptForDashboardUpload", "prompting for dashboard upload", nil)
		connection, err = maybePromptForDashboardUpload(os.Stdin, os.Stdout)
		if err != nil && !errors.Is(err, errDashboardUploadPromptSkipped) {
			fmt.Printf("SCAN FAILED: unable to configure dashboard upload: %v\n", err)
			traceCtx.Error("cli", "maybePromptForDashboardUpload", err, nil)
			traceCtx.HelperExit(promptSpan, "cli", "maybePromptForDashboardUpload", "error", "dashboard upload prompt failed", nil)
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard upload prompt failed"}
		}
		promptStatus := "ok"
		promptMessage := "dashboard upload prompt completed"
		if errors.Is(err, errDashboardUploadPromptSkipped) {
			promptStatus = "skipped"
			promptMessage = "dashboard upload prompt skipped"
		}
		traceCtx.HelperExit(promptSpan, "cli", "maybePromptForDashboardUpload", promptStatus, promptMessage, nil)
	}
	if connection.Prompted && !connection.Enabled {
		traceCtx.Branch("cli", "HandleScan", "dashboard_upload_disabled", nil)
		opts.APIBaseURL = ""
		opts.ProjectID = ""
		opts.APIKey = ""
	} else if strings.TrimSpace(connection.APIBaseURL) != "" {
		traceCtx.Branch("cli", "HandleScan", "dashboard_upload_enabled", map[string]string{
			"project_id": strings.TrimSpace(connection.ProjectID),
		})
		opts.APIBaseURL = strings.TrimSpace(connection.APIBaseURL)
		if strings.TrimSpace(opts.ProjectID) == "" {
			opts.ProjectID = strings.TrimSpace(connection.ProjectID)
		}
		if strings.TrimSpace(opts.APIKey) == "" {
			opts.APIKey = strings.TrimSpace(connection.APIKey)
		}
	} else if opts.APIBaseURL == "" {
		opts.APIBaseURL = defaultScanUploadBaseURL()
	}

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		emitCLIEvent(connection, cliEventFromScan("cli_error", "unable to get current directory: "+err.Error(), "system_error", strings.TrimSpace(connection.ProjectID), "", types.ScanResults{}, time.Since(startedAt)))
		fmt.Printf("SCAN FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{
		"repository": filepath.Base(cwd),
	})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	fmt.Printf("Scanning repository: %s\n", filepath.Base(cwd))
	fmt.Println()

	scanSpan := traceCtx.HelperEnter("scan", "RunComprehensiveScan", "running comprehensive scan", nil)
	results := scan.RunComprehensiveScan()
	traceCtx.HelperExit(scanSpan, "scan", "RunComprehensiveScan", "ok", "comprehensive scan completed", map[string]string{
		"files_scanned":   strconv.Itoa(results.FilesScanned),
		"security_issues": strconv.Itoa(results.SecurityIssues),
		"violation_count": strconv.Itoa(len(results.Violations)),
	})

	fmt.Println("=== SCAN RESULTS ===")
	fmt.Printf("Repository: %s\n", filepath.Base(cwd))
	fmt.Printf("Files scanned: %d\n", results.FilesScanned)
	fmt.Printf("Security issues found: %d\n", results.SecurityIssues)
	fmt.Printf("Policy violations: %d\n", len(results.Violations))
	telemetryProjectID := strings.TrimSpace(opts.ProjectID)
	telemetryScanID := strings.TrimSpace(opts.ScanID)
	traceCtx.SetMetadata("project_id", telemetryProjectID)
	traceCtx.SetMetadata("scan_id", telemetryScanID)

	if opts.APIBaseURL != "" {
		traceCtx.Branch("cli", "HandleScan", "upload_results", map[string]string{
			"project_id": telemetryProjectID,
		})
		uploadSpan := traceCtx.HelperEnter("cli", "uploadScanResults", "uploading scan results", map[string]string{
			"project_id": telemetryProjectID,
		})
		uploaded, uploadErr := uploadScanResults(opts, results)
		if uploadErr != nil {
			traceCtx.Error("cli", "uploadScanResults", uploadErr, map[string]string{
				"project_id": telemetryProjectID,
			})
			traceCtx.HelperExit(uploadSpan, "cli", "uploadScanResults", "error", "scan upload failed", map[string]string{
				"project_id": telemetryProjectID,
			})
			emitCLIEvent(connection, cliEventFromScan("cli_error", "dashboard upload failed: "+uploadErr.Error(), "upload_failed", telemetryProjectID, telemetryScanID, results, time.Since(startedAt)))
			if shouldResetDashboardSavedConnection(connection, uploadErr) {
				traceCtx.Branch("cli", "HandleScan", "reset_saved_dashboard_connection", nil)
				resetSpan := traceCtx.HelperEnter("cli", "resetSavedDashboardConnection", "clearing saved dashboard connection", nil)
				if resetErr := resetSavedDashboardConnection(); resetErr != nil {
					traceCtx.Error("cli", "resetSavedDashboardConnection", resetErr, nil)
					traceCtx.HelperExit(resetSpan, "cli", "resetSavedDashboardConnection", "error", "saved dashboard connection reset failed", nil)
					fmt.Printf("\n%s\n", formatDashboardUploadFailure(connection, uploadErr))
					fmt.Printf("SCAN FAILED: unable to clear revoked dashboard connection: %v\n", resetErr)
					return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard connection reset failed"}
				}
				traceCtx.HelperExit(resetSpan, "cli", "resetSavedDashboardConnection", "ok", "saved dashboard connection cleared", nil)
				fmt.Printf("\nDashboard upload failed: %v\n", uploadErr)
				fmt.Println("Saved dashboard credentials were cleared.")
				fmt.Println("Run `baseline scan` again and the dashboard upload prompt will be shown again.")
				return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "upload_failed", TraceMessage: "dashboard upload failed and saved credentials were cleared"}
			}
			fmt.Printf("\n%s\n", formatDashboardUploadFailure(connection, uploadErr))
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "upload_failed", TraceMessage: "dashboard upload failed"}
		}
		traceCtx.HelperExit(uploadSpan, "cli", "uploadScanResults", "ok", "scan upload completed", map[string]string{
			"project_id": uploaded.ProjectID,
			"scan_id":    uploaded.ScanID,
		})
		telemetryProjectID = uploaded.ProjectID
		telemetryScanID = uploaded.ScanID
		traceCtx.SetMetadata("project_id", telemetryProjectID)
		traceCtx.SetMetadata("scan_id", telemetryScanID)
		fmt.Printf("Dashboard upload: %s (scan=%s, project=%s)\n", uploaded.BaseURL, uploaded.ScanID, uploaded.ProjectID)
	}

	if len(results.Violations) > 0 {
		traceCtx.Branch("cli", "HandleScan", "violations_found", map[string]string{
			"violation_count": strconv.Itoa(len(results.Violations)),
		})
		emitCLIEvent(connection, cliEventFromScan("cli_warning", "scan completed with blocking policy violations", "violations_found", telemetryProjectID, telemetryScanID, results, time.Since(startedAt)))
		fmt.Println("\nPolicy violations:")
		for _, v := range results.Violations {
			fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
		}
		fmt.Printf("\nExit code: %d (blocking violations)\n", types.ExitBlockingViolation)
		return tracedCommandResult{
			ExitCode:     types.ExitBlockingViolation,
			TraceStatus:  "violations_found",
			TraceMessage: "scan completed with blocking policy violations",
			Attributes: map[string]string{
				"repository":      filepath.Base(cwd),
				"project_id":      telemetryProjectID,
				"scan_id":         telemetryScanID,
				"files_scanned":   strconv.Itoa(results.FilesScanned),
				"security_issues": strconv.Itoa(results.SecurityIssues),
				"violation_count": strconv.Itoa(len(results.Violations)),
			},
		}
	}

	if results.SecurityIssues > 0 {
		traceCtx.Branch("cli", "HandleScan", "security_findings", map[string]string{
			"security_issues": strconv.Itoa(results.SecurityIssues),
		})
		emitCLIEvent(connection, cliEventFromScan("cli_warning", "scan completed with security findings", "security_findings", telemetryProjectID, telemetryScanID, results, time.Since(startedAt)))
	} else {
		traceCtx.Branch("cli", "HandleScan", "clean_exit", nil)
		emitCLIEvent(connection, cliEventFromScan("cli_health", "scan completed cleanly", "ok", telemetryProjectID, telemetryScanID, results, time.Since(startedAt)))
	}

	fmt.Println("\nNo critical policy violations detected")
	fmt.Printf("Exit code: %d (scan completed)\n", types.ExitSuccess)
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "scan completed",
		Attributes: map[string]string{
			"repository":      filepath.Base(cwd),
			"project_id":      telemetryProjectID,
			"scan_id":         telemetryScanID,
			"files_scanned":   strconv.Itoa(results.FilesScanned),
			"security_issues": strconv.Itoa(results.SecurityIssues),
			"violation_count": strconv.Itoa(len(results.Violations)),
		},
	}
}

func printScanUsage() {
	fmt.Println("Usage: baseline scan [--api <url>] [--project-id <id>] [--api-key <key>] [--scan-id <id>] [--commit-sha <sha>]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --api         Upload scan results to a Baseline API after the local scan completes")
	fmt.Println("  --project-id  Explicit target project ID for dashboard upload")
	fmt.Println("  --api-key     API key used for project lookup and scan upload (defaults to BASELINE_API_KEY)")
	fmt.Println("  --scan-id     Optional explicit scan ID for the uploaded scan record")
	fmt.Println("  --commit-sha  Optional commit SHA override for the uploaded scan record")
	fmt.Println()
	fmt.Println("If --project-id is omitted, Baseline tries to resolve the project from the current git remote or repository name.")
	fmt.Println("If --api is omitted, Baseline auto-uploads when BASELINE_API_ADDR and BASELINE_API_KEY are configured.")
}

// HandleInit initializes Baseline configuration.
func HandleInit() {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("init", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runInitCommand(traceCtx)
	}))
}

func runVersionCommand(traceCtx *clitrace.Context) tracedCommandResult {
	traceCtx.Branch("cli", "version", "print_version", nil)
	fmt.Println(version.String())
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "ok", TraceMessage: "version printed"}
}

func runEnforceCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig) tracedCommandResult {
	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		log.Error("Git repository check failed", "error", err)
		fmt.Printf("ENFORCEMENT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		log.Error("Failed to get current directory", "error", err)
		fmt.Printf("ENFORCEMENT FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{"repository": filepath.Base(cwd)})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	log.Info("Starting policy enforcement", "repository", filepath.Base(cwd))
	fmt.Printf("Enforcing policies on repository: %s\n", filepath.Base(cwd))
	policySpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks for enforcement", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(policySpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{"violation_count": strconv.Itoa(len(violations))})

	if len(violations) > 0 {
		traceCtx.Branch("enforce", "policy", "violations_found", map[string]string{"violation_count": strconv.Itoa(len(violations))})
		fmt.Printf("\nENFORCEMENT BLOCKED: Policy violations found:\n")
		for _, v := range violations {
			fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
		}
		fmt.Printf("\nEnforcement failed. Fix violations before proceeding.\n")
		_ = telemetryConnection
		return tracedCommandResult{
			ExitCode:     types.ExitBlockingViolation,
			TraceStatus:  "violations_found",
			TraceMessage: "policy enforcement blocked by violations",
			Attributes: map[string]string{
				"repository":      filepath.Base(cwd),
				"violation_count": strconv.Itoa(len(violations)),
			},
		}
	}

	fmt.Printf("Enforcement passed. No policy violations detected.\n")
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "policy enforcement passed",
		Attributes: map[string]string{
			"repository": filepath.Base(cwd),
		},
	}
}

func runInitCommand(traceCtx *clitrace.Context) tracedCommandResult {
	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("INIT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		fmt.Printf("INIT FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{"repository": filepath.Base(cwd)})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	fmt.Printf("Initializing Baseline in repository: %s\n", filepath.Base(cwd))
	mkdirSpan := traceCtx.HelperEnter("fs", "os.MkdirAll", "creating .baseline directory", nil)
	if err := os.MkdirAll(".baseline", 0755); err != nil {
		traceCtx.Error("fs", "os.MkdirAll", err, nil)
		traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "error", "unable to create .baseline directory", nil)
		fmt.Printf("INIT FAILED: Unable to create .baseline directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "unable to create .baseline directory"}
	}
	traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "ok", ".baseline directory created", nil)

	configContent := `# Baseline Configuration
# This file configures Baseline policy enforcement

policy_set = "baseline:prod"
enforcement_mode = "audit"
`
	configFile := ".baseline/config.yaml"
	writeSpan := traceCtx.HelperEnter("fs", "os.WriteFile", "writing baseline config file", nil)
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		traceCtx.Error("fs", "os.WriteFile", err, nil)
		traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "error", "unable to create config file", nil)
		fmt.Printf("INIT FAILED: Unable to create config file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "unable to create config file"}
	}
	traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "ok", "baseline config file written", nil)

	fmt.Printf("Created Baseline configuration: %s\n", configFile)
	fmt.Printf("Policy set: baseline:prod\n")
	fmt.Printf("Enforcement mode: audit\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Run 'baseline check' to verify policy compliance\n")
	fmt.Printf("2. Run 'baseline scan' to analyze repository state\n")
	fmt.Printf("3. Fix any violations found\n")
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "initialized",
		TraceMessage: "baseline project configuration initialized",
		Attributes: map[string]string{
			"repository": filepath.Base(cwd),
		},
	}
}

// HandleReport generates scan results in specified format.
func HandleReport(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("report", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runReportCommand(traceCtx, connection, args)
	}))
}

func parseReportFormat(args []string) (string, error) {
	selected := "text"
	explicit := false
	for _, arg := range args {
		var candidate string
		switch arg {
		case "--text":
			candidate = "text"
		case "--json":
			candidate = "json"
		case "--sarif":
			candidate = "sarif"
		default:
			return "", fmt.Errorf("unknown flag %s", arg)
		}

		if explicit && candidate != selected {
			return "", fmt.Errorf("multiple report formats specified (%s and %s)", selected, candidate)
		}
		selected = candidate
		explicit = true
	}

	return selected, nil
}

// HandleGenerate generates missing infrastructure using AI.
func HandleGenerate(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("generate", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runGenerateCommand(traceCtx, connection, args)
	}))
}

func runReportCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "report",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("REPORT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	formatSpan := traceCtx.HelperEnter("cli", "parseReportFormat", "parsing report format", nil)
	outputFormat, err := parseReportFormat(args)
	if err != nil {
		traceCtx.Error("cli", "parseReportFormat", err, nil)
		traceCtx.HelperExit(formatSpan, "cli", "parseReportFormat", "error", "report format parsing failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "report",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("REPORT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "report format parsing failed"}
	}
	traceCtx.HelperExit(formatSpan, "cli", "parseReportFormat", "ok", "report format parsed", map[string]string{"status": outputFormat})

	scanSpan := traceCtx.HelperEnter("scan", "RunComprehensiveScan", "running scan for report output", nil)
	results := scan.RunComprehensiveScan()
	traceCtx.HelperExit(scanSpan, "scan", "RunComprehensiveScan", "ok", "scan completed for report output", map[string]string{
		"files_scanned":   strconv.Itoa(results.FilesScanned),
		"security_issues": strconv.Itoa(results.SecurityIssues),
		"violation_count": strconv.Itoa(len(results.Violations)),
	})

	outputSpan := traceCtx.HelperEnter("report", "render", "writing report output", map[string]string{"status": outputFormat})
	switch outputFormat {
	case "json":
		renderJSONSpan := traceCtx.HelperEnter("report", "OutputJSON", "rendering json report", nil)
		if err := report.OutputJSON(results); err != nil {
			traceCtx.Error("report", "OutputJSON", err, nil)
			traceCtx.HelperExit(renderJSONSpan, "report", "OutputJSON", "error", "json report generation failed", nil)
			traceCtx.HelperExit(outputSpan, "report", "OutputJSON", "error", "json report generation failed", nil)
			emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", err.Error(), "system_error", "", "", results, 0))
			fmt.Printf("REPORT FAILED: %v\n", err)
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "json report generation failed"}
		}
		traceCtx.HelperExit(renderJSONSpan, "report", "OutputJSON", "ok", "json report rendered", nil)
	case "sarif":
		renderSARIFSpan := traceCtx.HelperEnter("report", "OutputSARIF", "rendering sarif report", nil)
		if err := report.OutputSARIF(results); err != nil {
			traceCtx.Error("report", "OutputSARIF", err, nil)
			traceCtx.HelperExit(renderSARIFSpan, "report", "OutputSARIF", "error", "sarif report generation failed", nil)
			traceCtx.HelperExit(outputSpan, "report", "OutputSARIF", "error", "sarif report generation failed", nil)
			emitCLIEvent(telemetryConnection, cliEventFromScan("cli_error", err.Error(), "system_error", "", "", results, 0))
			fmt.Printf("REPORT FAILED: %v\n", err)
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "sarif report generation failed"}
		}
		traceCtx.HelperExit(renderSARIFSpan, "report", "OutputSARIF", "ok", "sarif report rendered", nil)
	default:
		traceCtx.Branch("report", "render", "text", nil)
		renderTextSpan := traceCtx.HelperEnter("report", "OutputText", "rendering text report", nil)
		report.OutputText(results)
		traceCtx.HelperExit(renderTextSpan, "report", "OutputText", "ok", "text report rendered", nil)
	}
	traceCtx.HelperExit(outputSpan, "report", "render", "ok", "report output written", nil)

	emitCLIEvent(telemetryConnection, cliEventFromScan("cli_report_generated", "scan report generated", outputFormat, "", "", results, 0))
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  outputFormat,
		TraceMessage: "scan report generated",
		Attributes: map[string]string{
			"files_scanned":   strconv.Itoa(results.FilesScanned),
			"security_issues": strconv.Itoa(results.SecurityIssues),
			"violation_count": strconv.Itoa(len(results.Violations)),
		},
	}
}

func runGenerateCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if hasHelpFlag(args) {
		traceCtx.Branch("cli", "generate", "help_requested", nil)
		printGenerateUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "generate help shown"}
	}
	if len(args) > 0 {
		err := fmt.Errorf("unknown flag %s", args[0])
		traceCtx.Error("cli", "generate", err, nil)
		fmt.Printf("GENERATE FAILED: unknown flag %s\n", args[0])
		printGenerateUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "generate arguments invalid"}
	}

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("GENERATE FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	envSpan := traceCtx.HelperEnter("cli", "loadAIEnvFiles", "loading AI env files", nil)
	if err := loadAIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "error", "AI env loading failed", nil)
		fmt.Printf("GENERATE FAILED: unable to load AI env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "ok", "AI env files loaded", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		fmt.Printf("GENERATE FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{"repository": filepath.Base(cwd)})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	fmt.Printf("Generating missing infrastructure for repository: %s\n", filepath.Base(cwd))
	genSpan := traceCtx.HelperEnter("ai", "NewDefaultGenerator", "creating default AI generator", nil)
	gen := ai.NewDefaultGenerator()
	traceCtx.HelperExit(genSpan, "ai", "NewDefaultGenerator", "ok", "default AI generator created", nil)

	availabilitySpan := traceCtx.HelperEnter("ai", "CheckAvailability", "checking AI provider availability", nil)
	if err := gen.CheckAvailability(); err != nil {
		traceCtx.Error("ai", "CheckAvailability", err, map[string]string{"repository": filepath.Base(cwd)})
		traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "error", "AI provider unavailable", nil)
		fmt.Printf("GENERATE FAILED: %v\n", err)
		fmt.Printf("Configure AI provider environment (OLLAMA_* or OPENROUTER_*) and retry\n")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI provider unavailable"}
	}
	traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "ok", "AI provider available", map[string]string{"status": gen.Provider()})
	fmt.Printf("AI provider connected: %s\n", gen.Provider())

	policySpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks for generation", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(policySpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{"violation_count": strconv.Itoa(len(violations))})

	if len(violations) == 0 {
		traceCtx.Branch("generate", "policy", "no_op", nil)
		fmt.Println("No violations found - repository is compliant")
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "no_op",
			TraceMessage: "generate found no missing infrastructure",
			Attributes: map[string]string{
				"repository": filepath.Base(cwd),
			},
		}
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
	}
	fmt.Println()

	outcomeSpan := traceCtx.HelperEnter("generate", "buildGenerationOutcome", "generating auto-fixable files", map[string]string{"violation_count": strconv.Itoa(len(violations))})
	outcome := buildGenerationOutcome(violations, func(v types.PolicyViolation) string {
		return generateFixForViolationWithFile(gen, v)
	})
	traceCtx.HelperExit(outcomeSpan, "generate", "buildGenerationOutcome", "ok", "generation outcome computed", map[string]string{
		"generated_files": strconv.Itoa(len(outcome.GeneratedFiles)),
		"failed_count":    strconv.Itoa(len(outcome.Failed)),
		"skipped_count":   strconv.Itoa(len(outcome.Skipped)),
	})

	fmt.Printf("\nGeneration complete: %d files created\n", len(outcome.GeneratedFiles))
	if len(outcome.Skipped) > 0 {
		fmt.Printf("Skipped %d violation(s) that require manual remediation\n", len(outcome.Skipped))
	}

	if len(outcome.Failed) > 0 {
		traceCtx.Branch("generate", "outcome", "generation_failed", map[string]string{"failed_count": strconv.Itoa(len(outcome.Failed))})
		fmt.Println("\nGeneration failed for auto-fixable violation(s):")
		for _, v := range outcome.Failed {
			fmt.Printf("  [%s] %s\n", v.PolicyID, v.Message)
		}
		fmt.Println("\nFix AI/provider issues and retry. Generated files (if any) were left in place for review.")
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "generation_failed",
			TraceMessage: "generation failed for auto-fixable violations",
			Attributes: map[string]string{
				"repository":      filepath.Base(cwd),
				"violation_count": strconv.Itoa(len(outcome.Failed)),
			},
		}
	}

	if len(outcome.GeneratedFiles) == 0 {
		traceCtx.Branch("generate", "outcome", "manual_remediation", map[string]string{"violation_count": strconv.Itoa(len(violations))})
		fmt.Println("No auto-fixable violations were generated. Manual remediation is required.")
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "manual_remediation",
			TraceMessage: "no auto-fixable violations were generated",
			Attributes: map[string]string{
				"repository":      filepath.Base(cwd),
				"violation_count": strconv.Itoa(len(violations)),
			},
		}
	}

	traceCtx.Branch("generate", "outcome", "generated", map[string]string{"generated_files": strconv.Itoa(len(outcome.GeneratedFiles))})
	fmt.Println("\nNext steps:")
	fmt.Println("1. Review the generated files")
	fmt.Println("2. Run 'baseline check' to verify compliance")
	fmt.Println("3. Commit the changes to your repository")
	fmt.Println("4. Push and create a pull request for review")
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "generated",
		TraceMessage: fmt.Sprintf("generated %d file(s)", len(outcome.GeneratedFiles)),
		Attributes: map[string]string{
			"repository":      filepath.Base(cwd),
			"violation_count": strconv.Itoa(len(violations)),
		},
	}
}

// HandlePR creates a pull request with generated scaffolds.
func HandlePR(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("pr", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runPRCommand(traceCtx, connection, args)
	}))
}

// HandleExplain provides explanation for a policy violation.
func HandleExplain(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("explain", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runExplainCommand(traceCtx, connection, args)
	}))
}

// HandleSecurityAdvice generates AI-based security recommendations and saves
// them to a markdown file. This is advisory only and does not affect enforcement.
func HandleSecurityAdvice(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("security-advice", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runSecurityAdviceCommand(traceCtx, connection, args)
	}))
}

func runPRCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if hasHelpFlag(args) {
		traceCtx.Branch("cli", "pr", "help_requested", nil)
		printPRUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "pull request help shown"}
	}
	if len(args) > 0 {
		traceCtx.Error("cli", "pr", fmt.Errorf("unknown flag %s", args[0]), nil)
		fmt.Printf("PR FAILED: unknown flag %s\n", args[0])
		printPRUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "pull request arguments invalid"}
	}

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("PR FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	envSpan := traceCtx.HelperEnter("cli", "loadAIEnvFiles", "loading AI env files", nil)
	if err := loadAIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "error", "AI env loading failed", nil)
		fmt.Printf("PR FAILED: unable to load AI env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "ok", "AI env files loaded", nil)

	remoteSpan := traceCtx.HelperEnter("git", "remote get-url origin", "resolving git remote origin", nil)
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		traceCtx.Error("git", "remote get-url origin", err, nil)
		traceCtx.HelperExit(remoteSpan, "git", "remote get-url origin", "error", "git remote origin lookup failed", nil)
		fmt.Printf("PR FAILED: No git remote 'origin' found: %v\n", err)
		fmt.Printf("Please set up a git remote before creating pull requests\n")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git remote origin lookup failed"}
	}
	remoteURL := strings.TrimSpace(string(output))
	traceCtx.HelperExit(remoteSpan, "git", "remote get-url origin", "ok", "git remote origin resolved", map[string]string{"status": remoteURL})
	if !strings.Contains(remoteURL, "github.com") {
		traceCtx.Branch("pr", "remote", "unsupported_remote", nil)
		fmt.Printf("PR FAILED: Only GitHub repositories are supported\n")
		fmt.Printf("Found remote: %s\n", remoteURL)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "unsupported_remote", TraceMessage: "only GitHub repositories are supported"}
	}

	genSpan := traceCtx.HelperEnter("ai", "NewDefaultGenerator", "creating default AI generator", nil)
	gen := ai.NewDefaultGenerator()
	traceCtx.HelperExit(genSpan, "ai", "NewDefaultGenerator", "ok", "default AI generator created", nil)
	availabilitySpan := traceCtx.HelperEnter("ai", "CheckAvailability", "checking AI provider availability", nil)
	if err := gen.CheckAvailability(); err != nil {
		traceCtx.Error("ai", "CheckAvailability", err, nil)
		traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "error", "AI provider unavailable", nil)
		fmt.Printf("PR FAILED: %v\n", err)
		fmt.Printf("Configure AI provider environment (OLLAMA_* or OPENROUTER_*) and retry\n")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI provider unavailable"}
	}
	traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "ok", "AI provider available", map[string]string{"status": gen.Provider()})
	fmt.Printf("AI provider connected: %s\n", gen.Provider())

	policySpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks for pull request generation", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(policySpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{"violation_count": strconv.Itoa(len(violations))})
	if len(violations) == 0 {
		traceCtx.Branch("pr", "policy", "no_op", nil)
		fmt.Println("No violations found - repository is compliant")
		fmt.Println("No pull request needed")
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "no_op", TraceMessage: "pull request generation skipped because repository is compliant"}
	}

	fmt.Printf("Found %d violations to fix:\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  [%s] %s (%s)\n", v.PolicyID, v.Message, v.Severity)
	}
	fmt.Println()

	branchName := "baseline/fix-violations"
	branchSpan := traceCtx.HelperEnter("git", "createOrCheckoutBranch", "creating or checking out remediation branch", nil)
	if err := createOrCheckoutBranch(branchName); err != nil {
		traceCtx.Error("git", "createOrCheckoutBranch", err, nil)
		traceCtx.HelperExit(branchSpan, "git", "createOrCheckoutBranch", "error", "branch preparation failed", nil)
		fmt.Printf("PR FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "git_failed", TraceMessage: "branch preparation failed"}
	}
	traceCtx.HelperExit(branchSpan, "git", "createOrCheckoutBranch", "ok", "remediation branch ready", nil)

	outcomeSpan := traceCtx.HelperEnter("generate", "buildGenerationOutcome", "generating files for pull request", nil)
	outcome := buildGenerationOutcome(violations, func(v types.PolicyViolation) string {
		return generateFixForViolationWithFile(gen, v)
	})
	traceCtx.HelperExit(outcomeSpan, "generate", "buildGenerationOutcome", "ok", "generation outcome computed", map[string]string{
		"generated_files": strconv.Itoa(len(outcome.GeneratedFiles)),
		"failed_count":    strconv.Itoa(len(outcome.Failed)),
	})

	if len(outcome.Failed) > 0 {
		traceCtx.Branch("pr", "outcome", "generation_failed", map[string]string{"failed_count": strconv.Itoa(len(outcome.Failed))})
		fmt.Println("PR FAILED: generation failed for auto-fixable violation(s):")
		for _, v := range outcome.Failed {
			fmt.Printf("  [%s] %s\n", v.PolicyID, v.Message)
		}
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "generation_failed", TraceMessage: "generation failed for auto-fixable violations"}
	}
	if len(outcome.GeneratedFiles) == 0 {
		traceCtx.Branch("pr", "outcome", "manual_remediation", nil)
		fmt.Println("PR FAILED: no auto-fixable files were generated")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "manual_remediation", TraceMessage: "no auto-fixable files were generated"}
	}

	fmt.Printf("\nGeneration complete: %d files created\n", len(outcome.GeneratedFiles))
	pushSpan := traceCtx.HelperEnter("git", "commitAndPush", "committing and pushing generated files", nil)
	if err := commitAndPush(branchName, outcome.GeneratedFiles); err != nil {
		traceCtx.Error("git", "commitAndPush", err, nil)
		traceCtx.HelperExit(pushSpan, "git", "commitAndPush", "error", "commit and push failed", nil)
		fmt.Printf("PR FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "git_failed", TraceMessage: "commit and push failed"}
	}
	traceCtx.HelperExit(pushSpan, "git", "commitAndPush", "ok", "generated files committed and pushed", nil)

	createPRSpan := traceCtx.HelperEnter("github", "gh pr create", "creating GitHub pull request", nil)
	prBody := report.GeneratePRBody(violations, outcome.GeneratedFiles)
	cmd = exec.Command("gh", "pr", "create",
		"--title", "Add missing production infrastructure",
		"--body", prBody,
		"--head", branchName)
	if err := cmd.Run(); err != nil {
		traceCtx.Error("github", "gh pr create", err, nil)
		traceCtx.HelperExit(createPRSpan, "github", "gh pr create", "error", "GitHub pull request creation failed", nil)
		fmt.Printf("PR FAILED: unable to create PR automatically: %v\n", err)
		fmt.Println("Please create a pull request manually:")
		fmt.Printf("  Branch: %s\n", branchName)
		fmt.Printf("  Title: Add missing production infrastructure\n")
		fmt.Println("  Description: See generated files for details")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "manual_followup", TraceMessage: "unable to create pull request automatically"}
	}
	traceCtx.HelperExit(createPRSpan, "github", "gh pr create", "ok", "GitHub pull request created", nil)

	fmt.Println("[OK] Pull request created successfully!")
	fmt.Printf("\nNext steps:\n")
	fmt.Println("1. Review the pull request")
	fmt.Println("2. Run tests to ensure everything works")
	fmt.Println("3. Merge the pull request when ready")
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "pr_created", TraceMessage: "pull request created successfully"}
}

func runExplainCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if hasHelpFlag(args) {
		traceCtx.Branch("cli", "explain", "help_requested", nil)
		printExplainUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "explain help shown"}
	}
	if len(args) < 1 {
		traceCtx.Error("cli", "explain", fmt.Errorf("policy id is required"), nil)
		printExplainUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "policy id is required"}
	}

	policyID := strings.ToUpper(strings.TrimSpace(args[0]))
	if !isSupportedPolicyID(policyID) {
		traceCtx.Error("cli", "explain", fmt.Errorf("unknown policy id %s", args[0]), nil)
		fmt.Printf("EXPLAIN FAILED: unknown policy id %q\n", args[0])
		fmt.Printf("Supported policy IDs: A1, B1, C1, D1, E1, F1, G1, H1, I1, J1, K1, L1, R1\n")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "unknown policy id"}
	}

	fmt.Printf("=== POLICY EXPLANATION ===\n")
	fmt.Printf("Policy ID: %s\n", policyID)
	fmt.Println()

	policySpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks for explanation", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(policySpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{"violation_count": strconv.Itoa(len(violations))})

	var foundViolation *types.PolicyViolation
	for _, v := range violations {
		if v.PolicyID == policyID {
			foundViolation = &v
			break
		}
	}

	if foundViolation != nil {
		traceCtx.Branch("explain", "policy", "violation", nil)
		fmt.Printf("Current Status: VIOLATION\n")
		fmt.Printf("Message: %s\n", foundViolation.Message)
		fmt.Printf("Severity: %s\n", foundViolation.Severity)
		fmt.Println()
		remediationSpan := traceCtx.HelperEnter("report", "GetRemediationAdvice", "resolving remediation advice", map[string]string{"policy_id": policyID})
		remediation := report.GetRemediationAdvice(policyID)
		traceCtx.HelperExit(remediationSpan, "report", "GetRemediationAdvice", "ok", "remediation advice resolved", map[string]string{"policy_id": policyID})
		fmt.Printf("Remediation: %s\n", remediation)
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "violation", TraceMessage: "policy explanation generated for active violation"}
	}

	traceCtx.Branch("explain", "policy", "compliant", nil)
	fmt.Printf("Current Status: COMPLIANT\n")
	fmt.Printf("This policy is currently satisfied.\n")
	_ = telemetryConnection
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "compliant", TraceMessage: "policy explanation generated for compliant policy"}
}

func runSecurityAdviceCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if hasHelpFlag(args) {
		traceCtx.Branch("cli", "security-advice", "help_requested", nil)
		printSecurityAdviceUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "security advice help shown"}
	}

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	envSpan := traceCtx.HelperEnter("cli", "loadAIEnvFiles", "loading AI env files", nil)
	if err := loadAIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "error", "AI env loading failed", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: unable to load AI env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAIEnvFiles", "ok", "AI env files loaded", nil)

	parseSpan := traceCtx.HelperEnter("cli", "parseSecurityAdviceArgs", "parsing security advice arguments", nil)
	outFile, err := parseSecurityAdviceArgs(args)
	if err != nil {
		traceCtx.Error("cli", "parseSecurityAdviceArgs", err, nil)
		traceCtx.HelperExit(parseSpan, "cli", "parseSecurityAdviceArgs", "error", "security advice arguments invalid", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: %v\n", err)
		printSecurityAdviceUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "security advice arguments invalid"}
	}
	traceCtx.HelperExit(parseSpan, "cli", "parseSecurityAdviceArgs", "ok", "security advice arguments parsed", nil)

	genSpan := traceCtx.HelperEnter("ai", "NewDefaultGenerator", "creating default AI generator", nil)
	gen := ai.NewDefaultGenerator()
	traceCtx.HelperExit(genSpan, "ai", "NewDefaultGenerator", "ok", "default AI generator created", nil)
	availabilitySpan := traceCtx.HelperEnter("ai", "CheckAvailability", "checking AI provider availability", nil)
	if err := gen.CheckAvailability(); err != nil {
		traceCtx.Error("ai", "CheckAvailability", err, nil)
		traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "error", "AI provider unavailable", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: %v\n", err)
		fmt.Printf("Configure AI provider environment (OLLAMA_* or OPENROUTER_*) and retry\n")
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "AI provider unavailable"}
	}
	traceCtx.HelperExit(availabilitySpan, "ai", "CheckAvailability", "ok", "AI provider available", map[string]string{"status": gen.Provider()})

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "current directory lookup failed"}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{"repository": filepath.Base(cwd)})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	policySpan := traceCtx.HelperEnter("policy", "RunAllChecks", "running policy checks for security advice", nil)
	violations := policy.RunAllChecks()
	traceCtx.HelperExit(policySpan, "policy", "RunAllChecks", "ok", "policy checks completed", map[string]string{"violation_count": strconv.Itoa(len(violations))})

	contextSpan := traceCtx.HelperEnter("security", "buildSecurityAdviceContext", "building security advice context", nil)
	context := buildSecurityAdviceContext(filepath.Base(cwd), violations)
	traceCtx.HelperExit(contextSpan, "security", "buildSecurityAdviceContext", "ok", "security advice context built", map[string]string{"violation_count": strconv.Itoa(len(violations))})
	generateSpan := traceCtx.HelperEnter("ai", "GenerateSecurityAdvice", "generating AI security advice", nil)
	content, err := gen.GenerateSecurityAdvice(context)
	if err != nil {
		traceCtx.Error("ai", "GenerateSecurityAdvice", err, nil)
		traceCtx.HelperExit(generateSpan, "ai", "GenerateSecurityAdvice", "error", "security advice generation failed", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "generation_failed", TraceMessage: "security advice generation failed"}
	}
	traceCtx.HelperExit(generateSpan, "ai", "GenerateSecurityAdvice", "ok", "security advice generated", nil)

	disclaimerSpan := traceCtx.HelperEnter("security", "ensureSecurityAdviceDisclaimer", "ensuring security advice disclaimer", nil)
	content = ensureSecurityAdviceDisclaimer(content)
	traceCtx.HelperExit(disclaimerSpan, "security", "ensureSecurityAdviceDisclaimer", "ok", "security advice disclaimer ensured", nil)
	writeSpan := traceCtx.HelperEnter("fs", "os.WriteFile", "writing security advice output", nil)
	if err := os.WriteFile(outFile, []byte(content), 0644); err != nil {
		traceCtx.Error("fs", "os.WriteFile", err, nil)
		traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "error", "security advice output write failed", nil)
		fmt.Printf("SECURITY-ADVICE FAILED: unable to write %s: %v\n", outFile, err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "security advice output write failed"}
	}
	traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "ok", "security advice output written", nil)

	fmt.Printf("AI provider connected: %s\n", gen.Provider())
	fmt.Printf("Wrote AI security advice to %s\n", outFile)
	fmt.Println("Note: AI-generated suggestions may be incorrect. Validate recommendations before implementation.")
	_ = telemetryConnection
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "written", TraceMessage: "AI security advice written to " + outFile}
}

func parseSecurityAdviceArgs(args []string) (string, error) {
	outFile := "SECURITY.AI.SUGGESTIONS.md"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 >= len(args) {
				return "", fmt.Errorf("--out requires a file path")
			}
			outFile = strings.TrimSpace(args[i+1])
			if outFile == "" {
				return "", fmt.Errorf("--out requires a non-empty file path")
			}
			i++
		default:
			return "", fmt.Errorf("unknown flag %s", args[i])
		}
	}
	return outFile, nil
}

func ensureSecurityAdviceDisclaimer(content string) string {
	trimmed := strings.TrimSpace(content)
	if strings.Contains(strings.ToLower(trimmed), "ai-generated suggestions may be incorrect") {
		return trimmed + "\n"
	}

	preface := "# AI Security Suggestions\n\n" + securityAdviceDisclaimer + "\n\n"
	if trimmed == "" {
		return preface + "_No suggestions were generated._\n"
	}

	if strings.HasPrefix(trimmed, "#") {
		return preface + trimmed + "\n"
	}

	return preface + "## Recommendations\n\n" + trimmed + "\n"
}

func buildSecurityAdviceContext(repoName string, violations []types.PolicyViolation) string {
	policyCoverage := []string{
		"- A1 Branch protection (PR-required, direct push restrictions)",
		"- B1 CI on pull requests with automated tests",
		"- C1 Automated tests exist",
		"- D1 Plaintext secret detection",
		"- E1 Dependency management files present",
		"- F1 README and license requirements",
		"- G1 Risky code pattern blocking (unsafe pointer, command/runtime injection, SQL string building)",
		"- H1 Deployment configuration and Docker non-root user checks",
		"- I1 Infrastructure-as-code artifacts",
		"- J1 Environment template presence",
		"- K1 Backup/recovery documentation",
		"- L1 Logging/monitoring documentation/configuration",
		"- R1 Rollback documentation",
	}

	lines := []string{
		"Repository: " + repoName,
		"",
		"Built-in policy coverage:",
		strings.Join(policyCoverage, "\n"),
		"",
		fmt.Sprintf("Current violation count: %d", len(violations)),
	}
	if len(violations) > 0 {
		lines = append(lines, "Current violations:")
		for _, v := range violations {
			lines = append(lines, fmt.Sprintf("- [%s] %s", v.PolicyID, v.Message))
		}
	}

	return strings.Join(lines, "\n")
}

// HandleAPI serves the optional Baseline API.
func HandleAPI(args []string) {
	subcommand := "api"
	if len(args) > 0 {
		subcommand = "api " + strings.TrimSpace(args[0])
	}
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand(subcommand, connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runAPICommand(traceCtx, subcommand, args)
	}))
}

func runAPICommand(traceCtx *clitrace.Context, subcommand string, args []string) tracedCommandResult {
	envSpan := traceCtx.HelperEnter("cli", "loadAPIEnvFiles", "loading API env files", nil)
	if err := loadAPIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAPIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "error", "API env loading failed", nil)
		fmt.Printf("API FAILED: unable to load API env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "ok", "API env files loaded", nil)

	if len(args) < 1 {
		traceCtx.Error("cli", "api", fmt.Errorf("api subcommand is required"), nil)
		printAPIUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "api subcommand is required"}
	}
	if hasHelpFlag(args[:1]) || strings.EqualFold(strings.TrimSpace(args[0]), "help") {
		traceCtx.Branch("api", subcommand, "help_requested", nil)
		printAPIUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "api help shown"}
	}

	if args[0] == "keygen" {
		if len(args) > 1 && hasHelpFlag(args[1:]) {
			printAPIUsage()
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "api keygen help shown"}
		}
		if len(args) > 1 {
			traceCtx.Error("api", "keygen", fmt.Errorf("unknown flag %s", args[1]), nil)
			fmt.Printf("API FAILED: unknown flag %s\n", args[1])
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "api keygen arguments invalid"}
		}
		keygenSpan := traceCtx.HelperEnter("api", "generateAPIKey", "generating API key", nil)
		key, err := generateAPIKey()
		if err != nil {
			traceCtx.Error("api", "generateAPIKey", err, nil)
			traceCtx.HelperExit(keygenSpan, "api", "generateAPIKey", "error", "API key generation failed", nil)
			fmt.Printf("API FAILED: unable to generate API key: %v\n", err)
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API key generation failed"}
		}
		traceCtx.HelperExit(keygenSpan, "api", "generateAPIKey", "ok", "API key generated", nil)
		fmt.Println(key)
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "ok", TraceMessage: "API key generated"}
	}

	if args[0] == "verify-prod" {
		strict := false
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--help", "-h":
				printAPIUsage()
				return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "api verify-prod help shown"}
			case "--strict":
				strict = true
			default:
				traceCtx.Error("api", "verify-prod", fmt.Errorf("unknown flag %s", args[i]), nil)
				fmt.Printf("API FAILED: unknown flag %s\n", args[i])
				return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "api verify-prod arguments invalid"}
			}
		}

		verifySpan := traceCtx.HelperEnter("api", "verifyAPIProdConfig", "verifying production API configuration", nil)
		cfg := api.ConfigFromEnv()
		result := verifyAPIProdConfig(cfg, os.Getenv)
		traceCtx.HelperExit(verifySpan, "api", "verifyAPIProdConfig", "ok", "production API configuration verified", map[string]string{
			"error_count":   strconv.Itoa(len(result.Errors)),
			"warning_count": strconv.Itoa(len(result.Warnings)),
		})
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
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "ok", TraceMessage: "API production verification passed"}
		}

		if strict && len(result.Warnings) > 0 {
			traceCtx.Branch("api", "verify-prod", "strict_warning", nil)
			fmt.Println("STRICT MODE: warnings are treated as blocking.")
			return tracedCommandResult{ExitCode: types.ExitBlockingViolation, TraceStatus: "strict_warning", TraceMessage: "API production verification warnings treated as blocking"}
		}

		if len(result.Errors) > 0 {
			traceCtx.Branch("api", "verify-prod", "violations_found", nil)
			fmt.Println("FAIL: resolve blocking issues before production deployment.")
			return tracedCommandResult{ExitCode: types.ExitBlockingViolation, TraceStatus: "violations_found", TraceMessage: "API production verification found blocking issues"}
		}

		traceCtx.Branch("api", "verify-prod", "warning", nil)
		fmt.Println("PASS WITH WARNINGS: review and address warnings before production deployment.")
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "warning", TraceMessage: "API production verification passed with warnings"}
	}

	if args[0] != "serve" {
		traceCtx.Error("api", "serve", fmt.Errorf("unknown subcommand %s", args[0]), nil)
		fmt.Printf("API FAILED: unknown subcommand %s\n", args[0])
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "unknown api subcommand"}
	}

	cfg := api.ConfigFromEnv()
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			printAPIUsage()
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "api serve help shown"}
		case "--addr":
			if i+1 >= len(args) {
				fmt.Println("API FAILED: --addr requires a value")
				return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "api serve address requires a value"}
			}
			cfg.Addr = args[i+1]
			i++
		case "--ai-enabled":
			cfg.AIEnabled = true
		default:
			traceCtx.Error("api", "serve", fmt.Errorf("unknown flag %s", args[i]), nil)
			fmt.Printf("API FAILED: unknown flag %s\n", args[i])
			return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "api serve arguments invalid"}
		}
	}

	validateSpan := traceCtx.HelperEnter("api", "validateAPIListenAddr", "validating API listen address", nil)
	if err := validateAPIListenAddr(cfg.Addr); err != nil {
		traceCtx.Error("api", "validateAPIListenAddr", err, nil)
		traceCtx.HelperExit(validateSpan, "api", "validateAPIListenAddr", "error", "API listen address validation failed", nil)
		fmt.Printf("API FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API listen address validation failed"}
	}
	traceCtx.HelperExit(validateSpan, "api", "validateAPIListenAddr", "ok", "API listen address validated", nil)

	storeSpan := traceCtx.HelperEnter("api", "NewStore", "opening persistent store", nil)
	store, err := api.NewStore(cfg.DBPath)
	if err != nil {
		traceCtx.Error("api", "NewStore", err, nil)
		traceCtx.HelperExit(storeSpan, "api", "NewStore", "error", "persistent store open failed", nil)
		fmt.Printf("API FAILED: unable to open persistent store: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "persistent store open failed"}
	}
	traceCtx.HelperExit(storeSpan, "api", "NewStore", "ok", "persistent store opened", nil)
	defer func() {
		_ = store.Close()
	}()

	serverSpan := traceCtx.HelperEnter("api", "NewServer", "constructing API server", nil)
	server, err := api.NewServer(cfg, store)
	if err != nil {
		traceCtx.Error("api", "NewServer", err, nil)
		traceCtx.HelperExit(serverSpan, "api", "NewServer", "error", "API server construction failed", nil)
		fmt.Printf("API FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API server construction failed"}
	}
	traceCtx.HelperExit(serverSpan, "api", "NewServer", "ok", "API server constructed", nil)

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

	listenSpan := traceCtx.HelperEnter("api", "ListenAndServe", "starting API server", nil)
	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			traceCtx.HelperExit(listenSpan, "api", "ListenAndServe", "ok", "API server stopped", nil)
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "stopped", TraceMessage: "API server stopped"}
		}
		traceCtx.Error("api", "ListenAndServe", err, nil)
		traceCtx.HelperExit(listenSpan, "api", "ListenAndServe", "error", "API server failed", nil)
		fmt.Printf("API FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API server failed"}
	}
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "stopped", TraceMessage: "API server stopped"}
}

func printGenerateUsage() {
	fmt.Println("Usage: baseline generate")
	fmt.Println("       baseline generate --help")
	fmt.Println()
	fmt.Println("Generate missing infrastructure scaffolds for supported policy violations using AI.")
}

func printPRUsage() {
	fmt.Println("Usage: baseline pr")
	fmt.Println("       baseline pr --help")
	fmt.Println()
	fmt.Println("Generate scaffolds, commit/push a branch, and attempt GitHub PR creation.")
}

func printExplainUsage() {
	fmt.Printf("Usage: baseline explain <policy_id>\n")
	fmt.Printf("Example: baseline explain G1\n")
}

func printSecurityAdviceUsage() {
	fmt.Println("Usage: baseline security-advice [--out <file>]")
}

func printAPIUsage() {
	fmt.Println("Usage: baseline api serve [--addr <host:port>] [--ai-enabled]")
	fmt.Println("       baseline api keygen")
	fmt.Println("       baseline api verify-prod [--strict]")
	fmt.Println("Environment:")
	fmt.Println("  BASELINE_API_KEY=<key> or BASELINE_API_KEYS=<key:role,key:role>")
	fmt.Println("  BASELINE_API_REQUIRE_HTTPS=false")
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
	fmt.Println("  BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE=false")
	fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_ENABLED=false")
	fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER=X-Forwarded-User")
	fmt.Println("  BASELINE_API_DASHBOARD_AUTH_PROXY_ROLE_HEADER=X-Forwarded-Role")
	fmt.Println("  BASELINE_API_GITHUB_WEBHOOK_SECRET=<secret>")
	fmt.Println("  BASELINE_API_GITLAB_WEBHOOK_TOKEN=<token>")
	fmt.Println("  BASELINE_API_GITHUB_TOKEN=<token>")
	fmt.Println("  BASELINE_API_GITHUB_API_URL=https://api.github.com")
	fmt.Println("  BASELINE_API_GITLAB_TOKEN=<token>")
	fmt.Println("  BASELINE_API_GITLAB_API_URL=https://gitlab.com/api/v4")
	fmt.Println("  BASELINE_API_AI_ENABLED=false")
	fmt.Println("Config file auto-load order: BASELINE_API_ENV_FILE, .env.production, .env, api.env")
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		switch strings.TrimSpace(strings.ToLower(arg)) {
		case "--help", "-h":
			return true
		}
	}
	return false
}

func isSupportedPolicyID(policyID string) bool {
	switch strings.ToUpper(strings.TrimSpace(policyID)) {
	case types.PolicyProtectedBranch,
		types.PolicyCIPipeline,
		types.PolicyTestSuite,
		types.PolicyNoSecrets,
		types.PolicyDependencyMgmt,
		types.PolicyDocumentation,
		types.PolicySecurityScanning,
		types.PolicyDeploymentConfig,
		types.PolicyInfraAsCode,
		types.PolicyEnvVariables,
		types.PolicyBackupRecovery,
		types.PolicyLoggingMonitoring,
		types.PolicyRollbackPlan:
		return true
	default:
		return false
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

// ShouldAutoStartAPI returns true when an API key is configured for serving the API.
// It loads API env files using the same precedence as HandleAPI.
func ShouldAutoStartAPI() bool {
	if err := loadAPIEnvFiles(); err != nil {
		return false
	}
	cfg := api.ConfigFromEnv()
	return len(cfg.APIKeys) > 0
}

func loadAIEnvFiles() error {
	candidates := []string{}
	if explicit := strings.TrimSpace(os.Getenv("BASELINE_AI_ENV_FILE")); explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates, ".env.production", ".env", "ai.env", "api.env")

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
	if !isLoopbackHost(host) && !cfg.RequireHTTPS {
		result.Errors = append(result.Errors, "BASELINE_API_REQUIRE_HTTPS must be true for non-loopback production addresses.")
	}
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
		if !cfg.DashboardSessionCookieSecure {
			result.Errors = append(result.Errors, "BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE must be true when dashboard sessions are exposed on non-loopback addresses.")
		}
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
	if raw := strings.ToLower(strings.TrimSpace(getenv("BASELINE_API_DASHBOARD_ROLLOUT_STAGE"))); raw != "" {
		if !isValidDashboardRolloutStage(raw) {
			result.Errors = append(result.Errors, "BASELINE_API_DASHBOARD_ROLLOUT_STAGE must be one of read_only|mutations|integrations|full.")
		} else if raw != string(api.DashboardRolloutStageFull) {
			result.Warnings = append(result.Warnings, "Dashboard rollout stage is set to "+raw+"; some mutation endpoints are intentionally disabled.")
		}
	}

	if !hasAdminKey(cfg.APIKeys) {
		result.Warnings = append(result.Warnings, "No admin API key is bootstrapped via environment; ensure an active admin key exists in the database.")
	}

	if cfg.AIEnabled {
		result.Warnings = append(result.Warnings, "AI advisory endpoints are enabled; keep AI disabled unless explicitly required.")
	}

	if cfg.OIDCEnabled {
		issuer := strings.TrimSpace(cfg.OIDCIssuerURL)
		if issuer == "" {
			result.Errors = append(result.Errors, "OIDC is enabled but issuer URL is empty.")
		} else if parsedIssuer, err := url.Parse(issuer); err != nil || strings.TrimSpace(parsedIssuer.Scheme) == "" || strings.TrimSpace(parsedIssuer.Host) == "" {
			result.Errors = append(result.Errors, "OIDC issuer URL must be a valid absolute URL.")
		} else if !strings.EqualFold(parsedIssuer.Scheme, "https") {
			result.Errors = append(result.Errors, "OIDC issuer URL must use HTTPS in production.")
		}

		if strings.TrimSpace(cfg.OIDCClientID) == "" {
			result.Errors = append(result.Errors, "OIDC is enabled but client ID is empty.")
		}
		if strings.TrimSpace(cfg.OIDCClientSecret) == "" {
			result.Errors = append(result.Errors, "OIDC is enabled but client secret is empty.")
		}

		redirectRaw := strings.TrimSpace(cfg.OIDCRedirectURL)
		if redirectRaw == "" {
			result.Errors = append(result.Errors, "OIDC is enabled but redirect URL is empty.")
		} else {
			redirectURL, err := url.Parse(redirectRaw)
			if err != nil || strings.TrimSpace(redirectURL.Scheme) == "" || strings.TrimSpace(redirectURL.Host) == "" {
				result.Errors = append(result.Errors, "OIDC redirect URL must be a valid absolute URL.")
			} else {
				redirectHost := strings.TrimSpace(redirectURL.Hostname())
				if redirectHost == "" {
					result.Errors = append(result.Errors, "OIDC redirect URL host is required.")
				}
				if strings.TrimSpace(redirectURL.Path) != "/v1/auth/oidc/callback" {
					result.Errors = append(result.Errors, "OIDC redirect URL path must be exactly /v1/auth/oidc/callback.")
				}
				if strings.TrimSpace(redirectURL.Fragment) != "" {
					result.Errors = append(result.Errors, "OIDC redirect URL must not include a fragment.")
				}
				if isLoopbackHost(redirectHost) {
					result.Warnings = append(result.Warnings, "OIDC redirect URL points to loopback host; replace with production host before deployment.")
				} else if !strings.EqualFold(redirectURL.Scheme, "https") {
					result.Errors = append(result.Errors, "OIDC redirect URL must use HTTPS for non-loopback hosts.")
				}
			}
		}

		if !containsStringFold(cfg.OIDCScopes, "openid") {
			result.Errors = append(result.Errors, "OIDC scopes must include 'openid'.")
		}
		if !containsStringFold(cfg.OIDCScopes, "email") {
			result.Warnings = append(result.Warnings, "OIDC scopes do not include 'email'; domain/verified-email checks may not work.")
		}
		if !cfg.OIDCRequireVerifiedEmail {
			result.Warnings = append(result.Warnings, "OIDC verified-email enforcement is disabled; this weakens account assurance.")
		}
		if len(cfg.OIDCAllowedEmailDomains) == 0 {
			result.Warnings = append(result.Warnings, "No OIDC allowed email domains configured; consider domain allowlisting for production.")
		}

		auth0Enabled := parseBoolWithDefault(strings.TrimSpace(getenv("BASELINE_API_AUTH0_ENABLED")), false)
		supabaseEnabled := parseBoolWithDefault(strings.TrimSpace(getenv("BASELINE_API_SUPABASE_ENABLED")), false)
		if auth0Enabled && supabaseEnabled {
			result.Warnings = append(result.Warnings, "Both Auth0 and Supabase aliases are enabled; keep a single provider alias active to avoid config ambiguity.")
		}
		if auth0Enabled && !strings.Contains(strings.ToLower(cfg.OIDCIssuerURL), "auth0.") {
			result.Warnings = append(result.Warnings, "Auth0 alias is enabled but issuer URL does not look like an Auth0 domain.")
		}
		if supabaseEnabled && !strings.Contains(strings.ToLower(cfg.OIDCIssuerURL), "supabase.") {
			result.Warnings = append(result.Warnings, "Supabase alias is enabled but issuer URL does not look like a Supabase domain.")
		}
	}

	if secretLooksPlaceholder(getenv("BASELINE_API_KEY")) || secretLooksPlaceholder(getenv("BASELINE_API_KEYS")) {
		result.Errors = append(result.Errors, "API key environment variables still look like placeholder values.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_ENROLLMENT_TOKENS")) {
		result.Errors = append(result.Errors, "Enrollment token environment variable looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_GITHUB_WEBHOOK_SECRET")) {
		result.Errors = append(result.Errors, "GitHub webhook secret looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_GITLAB_WEBHOOK_TOKEN")) {
		result.Errors = append(result.Errors, "GitLab webhook token looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_GITHUB_TOKEN")) {
		result.Errors = append(result.Errors, "GitHub API token looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_GITLAB_TOKEN")) {
		result.Errors = append(result.Errors, "GitLab API token looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_OIDC_CLIENT_ID")) ||
		secretLooksPlaceholder(getenv("BASELINE_API_AUTH0_CLIENT_ID")) ||
		secretLooksPlaceholder(getenv("BASELINE_API_SUPABASE_CLIENT_ID")) {
		result.Errors = append(result.Errors, "OIDC client ID looks like a placeholder value.")
	}
	if secretLooksPlaceholder(getenv("BASELINE_API_OIDC_CLIENT_SECRET")) ||
		secretLooksPlaceholder(getenv("BASELINE_API_AUTH0_CLIENT_SECRET")) ||
		secretLooksPlaceholder(getenv("BASELINE_API_SUPABASE_CLIENT_SECRET")) {
		result.Errors = append(result.Errors, "OIDC client secret looks like a placeholder value.")
	}

	return result
}

func containsStringFold(values []string, expected string) bool {
	needle := strings.TrimSpace(strings.ToLower(expected))
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(strings.ToLower(value)) == needle {
			return true
		}
	}
	return false
}

func isValidDashboardRolloutStage(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(api.DashboardRolloutStageReadOnly),
		string(api.DashboardRolloutStageMutations),
		string(api.DashboardRolloutStageIntegrations),
		string(api.DashboardRolloutStageFull):
		return true
	default:
		return false
	}
}

func parseBoolWithDefault(raw string, fallback bool) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(trimmed)
	if err != nil {
		return fallback
	}
	return parsed
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

func validateAPIListenAddr(addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return errors.New("--addr cannot be empty")
	}
	if strings.HasPrefix(trimmed, ":") {
		port := strings.TrimPrefix(trimmed, ":")
		if port == "" {
			return errors.New("--addr requires a port after ':'")
		}
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("invalid --addr port %q", port)
		}
		return nil
	}

	if _, _, err := net.SplitHostPort(trimmed); err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", trimmed, err)
	}
	return nil
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

type generationOutcome struct {
	GeneratedFiles []string
	Failed         []types.PolicyViolation
	Skipped        []types.PolicyViolation
}

func buildGenerationOutcome(
	violations []types.PolicyViolation,
	generate func(types.PolicyViolation) string,
) generationOutcome {
	outcome := generationOutcome{
		GeneratedFiles: []string{},
		Failed:         []types.PolicyViolation{},
		Skipped:        []types.PolicyViolation{},
	}

	for _, violation := range violations {
		if !isAIFixSupported(violation.PolicyID) {
			outcome.Skipped = append(outcome.Skipped, violation)
			continue
		}

		file := strings.TrimSpace(generate(violation))
		if file == "" {
			outcome.Failed = append(outcome.Failed, violation)
			continue
		}
		outcome.GeneratedFiles = append(outcome.GeneratedFiles, file)
	}

	return outcome
}

func isAIFixSupported(policyID string) bool {
	switch policyID {
	case types.PolicyCIPipeline,
		types.PolicyTestSuite,
		types.PolicyDocumentation,
		types.PolicyDeploymentConfig,
		types.PolicyEnvVariables:
		return true
	default:
		return false
	}
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
		fmt.Println("[OK] Generated .github/workflows/ci.yml")
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
		fmt.Println("[OK] Generated main_test.go")
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
		fmt.Println("[OK] Generated README.md")
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
		fmt.Println("[OK] Generated Dockerfile")
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
		fmt.Println("[OK] Generated .env.example")
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
