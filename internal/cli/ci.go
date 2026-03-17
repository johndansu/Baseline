package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

type ciSetupOptions struct {
	Help     bool
	Provider string
	Mode     string
	Force    bool
}

type ciProviderSpec struct {
	Provider     string
	DisplayName  string
	WorkflowPath string
	Content      string
}

// HandleCI manages CI workflow scaffolding commands.
func HandleCI(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("ci", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runCICommand(traceCtx, args)
	}))
}

func runCICommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	if len(args) == 0 {
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci usage shown",
		}
	}
	if len(args) == 1 && hasHelpFlag(args) {
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci usage shown",
		}
	}

	switch strings.TrimSpace(strings.ToLower(args[0])) {
	case "setup":
		return runCISetupCommand(traceCtx, args[1:])
	default:
		fmt.Printf("CI FAILED: unknown subcommand %s\n\n", args[0])
		printCIUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "ci subcommand invalid",
		}
	}
}

func runCISetupCommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	opts, err := parseCISetupArgs(args)
	if err != nil {
		fmt.Printf("CI SETUP FAILED: %v\n\n", err)
		printCISetupUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "ci setup arguments invalid",
		}
	}
	if opts.Help {
		printCISetupUsage()
		return tracedCommandResult{
			ExitCode:     types.ExitSuccess,
			TraceStatus:  "help",
			TraceMessage: "ci setup usage shown",
		}
	}

	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		fmt.Printf("CI SETUP FAILED: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "git repository check failed",
		}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	cwdSpan := traceCtx.HelperEnter("cli", "os.Getwd", "resolving current directory", nil)
	cwd, err := os.Getwd()
	if err != nil {
		traceCtx.Error("cli", "os.Getwd", err, nil)
		traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "error", "current directory resolution failed", nil)
		fmt.Printf("CI SETUP FAILED: Unable to get current directory: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "current directory lookup failed",
		}
	}
	traceCtx.HelperExit(cwdSpan, "cli", "os.Getwd", "ok", "resolved current directory", map[string]string{
		"repository": filepath.Base(cwd),
	})
	traceCtx.SetMetadata("repository", filepath.Base(cwd))

	spec, err := buildCIProviderSpec(opts)
	if err != nil {
		fmt.Printf("CI SETUP FAILED: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unsupported ci provider",
			Attributes: map[string]string{
				"provider": opts.Provider,
			},
		}
	}

	if _, err := os.Stat(spec.WorkflowPath); err == nil && !opts.Force {
		fmt.Printf("CI SETUP FAILED: %s already exists. Re-run with --force to overwrite it.\n", spec.WorkflowPath)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "workflow file already exists",
			Attributes: map[string]string{
				"provider":      opts.Provider,
				"workflow_path": spec.WorkflowPath,
			},
		}
	}

	mkdirSpan := traceCtx.HelperEnter("fs", "os.MkdirAll", "creating workflow directory", nil)
	if err := os.MkdirAll(filepath.Dir(spec.WorkflowPath), 0755); err != nil {
		traceCtx.Error("fs", "os.MkdirAll", err, nil)
		traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "error", "unable to create workflow directory", nil)
		fmt.Printf("CI SETUP FAILED: Unable to create workflow directory: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unable to create workflow directory",
		}
	}
	traceCtx.HelperExit(mkdirSpan, "fs", "os.MkdirAll", "ok", "workflow directory created", nil)

	writeSpan := traceCtx.HelperEnter("fs", "os.WriteFile", "writing CI workflow file", nil)
	if err := os.WriteFile(spec.WorkflowPath, []byte(spec.Content), 0644); err != nil {
		traceCtx.Error("fs", "os.WriteFile", err, nil)
		traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "error", "unable to write workflow file", nil)
		fmt.Printf("CI SETUP FAILED: Unable to write workflow file: %v\n", err)
		return tracedCommandResult{
			ExitCode:     types.ExitSystemError,
			TraceStatus:  "system_error",
			TraceMessage: "unable to write workflow file",
		}
	}
	traceCtx.HelperExit(writeSpan, "fs", "os.WriteFile", "ok", "workflow file written", nil)

	fmt.Printf("Created %s workflow: %s\n", spec.DisplayName, spec.WorkflowPath)
	fmt.Printf("Baseline will run `%s` in %s.\n", "baseline "+opts.Mode, spec.DisplayName)
	fmt.Printf("Review and commit the workflow file to activate CI enforcement.\n")

	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "ci workflow scaffolded",
		Attributes: map[string]string{
			"repository":    filepath.Base(cwd),
			"provider":      opts.Provider,
			"mode":          opts.Mode,
			"workflow_path": spec.WorkflowPath,
		},
	}
}

func parseCISetupArgs(args []string) (ciSetupOptions, error) {
	opts := ciSetupOptions{
		Provider: "github",
		Mode:     "enforce",
	}
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch arg {
		case "--help", "-h":
			opts.Help = true
		case "--force":
			opts.Force = true
		case "--provider":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --provider")
			}
			opts.Provider = strings.ToLower(strings.TrimSpace(args[i]))
		case "--mode":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --mode")
			}
			opts.Mode = strings.ToLower(strings.TrimSpace(args[i]))
		default:
			return opts, fmt.Errorf("unknown flag %s", arg)
		}
	}

	if opts.Provider == "" {
		return opts, fmt.Errorf("provider must not be empty")
	}
	opts.Provider = normalizeCIProvider(opts.Provider)
	if opts.Provider == "" {
		return opts, fmt.Errorf("unsupported provider (expected github, gitlab, or azure)")
	}
	switch opts.Mode {
	case "enforce", "check":
	default:
		return opts, fmt.Errorf("unsupported mode %q (expected enforce or check)", opts.Mode)
	}
	return opts, nil
}

func normalizeCIProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "github", "github-actions", "gha":
		return "github"
	case "gitlab", "gitlab-ci":
		return "gitlab"
	case "azure", "azure-devops", "ado":
		return "azure"
	default:
		return ""
	}
}

func buildCIProviderSpec(opts ciSetupOptions) (ciProviderSpec, error) {
	command := "baseline " + opts.Mode
	switch opts.Provider {
	case "github":
		return ciProviderSpec{
			Provider:     "github",
			DisplayName:  "GitHub Actions",
			WorkflowPath: filepath.Join(".github", "workflows", "baseline.yml"),
			Content:      renderGitHubActionsWorkflow(command),
		}, nil
	case "gitlab":
		return ciProviderSpec{
			Provider:     "gitlab",
			DisplayName:  "GitLab CI",
			WorkflowPath: ".gitlab-ci.yml",
			Content:      renderGitLabCIWorkflow(command),
		}, nil
	case "azure":
		return ciProviderSpec{
			Provider:     "azure",
			DisplayName:  "Azure Pipelines",
			WorkflowPath: "azure-pipelines.yml",
			Content:      renderAzurePipelineWorkflow(command),
		}, nil
	default:
		return ciProviderSpec{}, fmt.Errorf("unsupported provider %q", opts.Provider)
	}
}

func renderGitHubActionsWorkflow(command string) string {
	return fmt.Sprintf(`name: Baseline

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  baseline:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build Baseline CLI
        run: go build -o baseline ./cmd/baseline

      - name: Run Baseline
        run: ./%s
`, command)
}

func renderGitLabCIWorkflow(command string) string {
	return fmt.Sprintf(`stages:
  - baseline

baseline:
  stage: baseline
  image: golang:1.24
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - go build -o baseline ./cmd/baseline
    - ./%s
`, command)
}

func renderAzurePipelineWorkflow(command string) string {
	return fmt.Sprintf(`trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self

  - task: GoTool@0
    inputs:
      version: '1.24'

  - script: go build -o baseline ./cmd/baseline
    displayName: Build Baseline CLI

  - script: ./%s
    displayName: Run Baseline
`, command)
}

func printCIUsage() {
	fmt.Println("Usage: baseline ci <subcommand>")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  setup   Generate CI workflow scaffolding")
}

func printCISetupUsage() {
	fmt.Println("Usage: baseline ci setup [--provider github|gitlab|azure] [--mode enforce|check] [--force]")
	fmt.Println()
	fmt.Println("Creates a CI workflow file for the selected provider.")
	fmt.Println("Default mode is `enforce`, which blocks the pipeline on violations.")
}
