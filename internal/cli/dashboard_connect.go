package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/baseline/baseline/internal/api"
	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
	"gopkg.in/yaml.v3"
)

type baselineLocalConfig struct {
	PolicySet       string                  `yaml:"policy_set,omitempty"`
	EnforcementMode string                  `yaml:"enforcement_mode,omitempty"`
	Dashboard       baselineDashboardConfig `yaml:"dashboard,omitempty"`
}

type baselineDashboardConfig struct {
	Upload dashboardUploadConfig `yaml:"upload,omitempty"`
}

type dashboardUploadConfig struct {
	Prompted   bool   `yaml:"prompted,omitempty"`
	Enabled    bool   `yaml:"enabled,omitempty"`
	APIBaseURL string `yaml:"api_base_url,omitempty"`
	ProjectID  string `yaml:"project_id,omitempty"`
	APIKeyRef  string `yaml:"api_key_ref,omitempty"`
}

type baselineSecrets struct {
	Dashboard baselineDashboardSecrets `json:"dashboard,omitempty"`
}

type baselineDashboardSecrets struct {
	APIKeys    map[string]string           `json:"api_keys,omitempty"`
	CLISession baselineDashboardCLISession `json:"cli_session,omitempty"`
}

type baselineDashboardCLISession struct {
	APIBaseURL   string `json:"api_base_url,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         string `json:"user,omitempty"`
	Email        string `json:"email,omitempty"`
	Role         string `json:"role,omitempty"`
}

type dashboardConnectionConfig struct {
	APIBaseURL   string
	ProjectID    string
	APIKey       string
	AccessToken  string
	RefreshToken string
	Enabled      bool
	Prompted     bool
	Source       string
}

type dashboardConnectOptions struct {
	APIBaseURL string
	APIKey     string
	ProjectID  string
}

type dashboardConnectResult struct {
	APIBaseURL string
	ProjectID  string
}

var errDashboardUploadPromptSkipped = errors.New("dashboard upload prompt skipped")
var interactiveTerminalCheck = isInteractiveTerminal

func handleDashboardConnect(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard connect", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardConnectCommand(traceCtx, connection, args)
	}))
}

func handleDashboardStatus(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard status", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardStatusCommand(traceCtx, connection, args)
	}))
}

func handleDashboardDisconnect(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard disconnect", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardDisconnectCommand(traceCtx, connection, args)
	}))
}

func runDashboardConnectCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	gitSpan := traceCtx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	if err := requireGitRepo(); err != nil {
		traceCtx.Error("cli", "requireGitRepo", err, nil)
		traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "error", "git repository check failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard connect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "git repository check failed"}
	}
	traceCtx.HelperExit(gitSpan, "cli", "requireGitRepo", "ok", "git repository check passed", nil)

	envSpan := traceCtx.HelperEnter("cli", "loadAPIEnvFiles", "loading API env files", nil)
	if err := loadAPIEnvFiles(); err != nil {
		traceCtx.Error("cli", "loadAPIEnvFiles", err, nil)
		traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "error", "API env loading failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard connect",
			Message:   "unable to load API env file: " + err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD CONNECT FAILED: unable to load API env file: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "API env loading failed"}
	}
	traceCtx.HelperExit(envSpan, "cli", "loadAPIEnvFiles", "ok", "API env files loaded", nil)

	parseSpan := traceCtx.HelperEnter("cli", "parseDashboardConnectArgs", "parsing dashboard connect arguments", nil)
	opts, err := parseDashboardConnectArgs(args)
	if err != nil {
		if errors.Is(err, errDashboardHelp) {
			traceCtx.Branch("cli", "dashboard connect", "help_requested", nil)
			traceCtx.HelperExit(parseSpan, "cli", "parseDashboardConnectArgs", "ok", "help requested", nil)
			emitCLIEvent(telemetryConnection, cliEventPayload{
				EventType: "cli_completed",
				Command:   "dashboard connect",
				Message:   "dashboard connect help shown",
				Status:    "help",
			})
			printDashboardConnectUsage()
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard connect help shown"}
		}
		traceCtx.Error("cli", "parseDashboardConnectArgs", err, nil)
		traceCtx.HelperExit(parseSpan, "cli", "parseDashboardConnectArgs", "error", "dashboard connect arguments invalid", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard connect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n\n", err)
		printDashboardConnectUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard connect arguments invalid"}
	}
	traceCtx.HelperExit(parseSpan, "cli", "parseDashboardConnectArgs", "ok", "dashboard connect arguments parsed", nil)

	connectSpan := traceCtx.HelperEnter("cli", "connectDashboardForCurrentProject", "connecting dashboard for current project", nil)
	result, err := connectDashboardForCurrentProject(traceCtx, opts, os.Stdin, os.Stdout, true)
	if err != nil {
		traceCtx.Error("cli", "connectDashboardForCurrentProject", err, nil)
		traceCtx.HelperExit(connectSpan, "cli", "connectDashboardForCurrentProject", "error", "dashboard connection failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard connect",
			Message:   err.Error(),
			Status:    "connect_failed",
		})
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "connect_failed", TraceMessage: "dashboard connection failed"}
	}
	traceCtx.SetMetadata("project_id", result.ProjectID)
	traceCtx.HelperExit(connectSpan, "cli", "connectDashboardForCurrentProject", "ok", "dashboard connection saved", map[string]string{
		"project_id": result.ProjectID,
	})

	emitCLIEvent(telemetryConnection, cliEventPayload{
		EventType: "cli_config_changed",
		Command:   "dashboard connect",
		Message:   "dashboard connection saved",
		Status:    "connected",
		ProjectID: result.ProjectID,
	})
	fmt.Printf("Dashboard connection saved.\n")
	fmt.Printf("API: %s\n", result.APIBaseURL)
	fmt.Printf("Project: %s\n", result.ProjectID)
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "connected",
		TraceMessage: "dashboard connection saved",
		Attributes: map[string]string{
			"project_id": result.ProjectID,
		},
	}
}

func runDashboardStatusCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if len(args) > 0 && hasHelpFlag(args) {
		traceCtx.Branch("cli", "dashboard status", "help_requested", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_completed",
			Command:   "dashboard status",
			Message:   "dashboard status help shown",
			Status:    "help",
		})
		printDashboardStatusUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard status help shown"}
	}
	if len(args) > 0 {
		traceCtx.Error("cli", "dashboard status", fmt.Errorf("unknown flag %s", args[0]), nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard status",
			Message:   "unknown flag " + args[0],
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD STATUS FAILED: unknown flag %s\n\n", args[0])
		printDashboardStatusUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard status arguments invalid"}
	}

	configSpan := traceCtx.HelperEnter("cli", "loadBaselineLocalConfig", "loading local dashboard config", nil)
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		traceCtx.Error("cli", "loadBaselineLocalConfig", err, nil)
		traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "error", "local dashboard config load failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard status",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD STATUS FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard config load failed"}
	}
	traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "ok", "local dashboard config loaded", nil)

	secretsSpan := traceCtx.HelperEnter("cli", "loadBaselineSecrets", "loading dashboard secrets", nil)
	secrets, err := loadBaselineSecrets()
	if err != nil {
		traceCtx.Error("cli", "loadBaselineSecrets", err, nil)
		traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "error", "dashboard secrets load failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard status",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD STATUS FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard secrets load failed"}
	}
	traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "ok", "dashboard secrets loaded", nil)

	upload := cfg.Dashboard.Upload
	apiKey := strings.TrimSpace(secrets.Dashboard.APIKeys[upload.APIKeyRef])
	cliAccessToken := storedCLIAccessTokenForBaseURL(upload.APIBaseURL)
	traceCtx.SetMetadata("project_id", strings.TrimSpace(upload.ProjectID))

	fmt.Println("=== DASHBOARD CONNECTION STATUS ===")
	fmt.Printf("Config file: %s\n", baselineConfigPath())
	fmt.Printf("Prompted: %t\n", upload.Prompted)
	fmt.Printf("Enabled: %t\n", upload.Enabled)
	fmt.Printf("API URL: %s\n", valueOrPlaceholder(upload.APIBaseURL))
	fmt.Printf("Project ID: %s\n", valueOrPlaceholder(upload.ProjectID))
	fmt.Printf("Fallback API key stored: %t\n", apiKey != "")
	fmt.Printf("CLI session stored: %t\n", cliAccessToken != "")

	status := "not_configured"
	if !upload.Prompted {
		fmt.Println("Status: not configured for this project.")
	} else if upload.Enabled && upload.APIBaseURL != "" && upload.ProjectID != "" && (apiKey != "" || cliAccessToken != "") {
		status = "connected"
		fmt.Println("Status: connected.")
	} else if upload.Enabled {
		status = "incomplete"
		fmt.Println("Status: incomplete connection. Run `baseline dashboard login` first, or use `baseline dashboard connect` as a fallback.")
	} else {
		status = "disabled"
		fmt.Println("Status: dashboard upload disabled for this project.")
	}
	traceCtx.Branch("cli", "dashboard status", status, nil)
	emitCLIEvent(telemetryConnection, cliEventPayload{
		EventType: "cli_completed",
		Command:   "dashboard status",
		Message:   "dashboard status inspected",
		Status:    "ok",
		ProjectID: strings.TrimSpace(upload.ProjectID),
	})
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "ok",
		TraceMessage: "dashboard status inspected",
		Attributes: map[string]string{
			"project_id": strings.TrimSpace(upload.ProjectID),
		},
	}
}

func runDashboardDisconnectCommand(traceCtx *clitrace.Context, telemetryConnection dashboardConnectionConfig, args []string) tracedCommandResult {
	if len(args) > 0 && hasHelpFlag(args) {
		traceCtx.Branch("cli", "dashboard disconnect", "help_requested", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_completed",
			Command:   "dashboard disconnect",
			Message:   "dashboard disconnect help shown",
			Status:    "help",
		})
		printDashboardDisconnectUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard disconnect help shown"}
	}
	if len(args) > 0 {
		traceCtx.Error("cli", "dashboard disconnect", fmt.Errorf("unknown flag %s", args[0]), nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard disconnect",
			Message:   "unknown flag " + args[0],
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD DISCONNECT FAILED: unknown flag %s\n\n", args[0])
		printDashboardDisconnectUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard disconnect arguments invalid"}
	}

	configSpan := traceCtx.HelperEnter("cli", "loadBaselineLocalConfig", "loading local dashboard config", nil)
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		traceCtx.Error("cli", "loadBaselineLocalConfig", err, nil)
		traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "error", "local dashboard config load failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard disconnect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard config load failed"}
	}
	traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "ok", "local dashboard config loaded", nil)

	secretsSpan := traceCtx.HelperEnter("cli", "loadBaselineSecrets", "loading dashboard secrets", nil)
	secrets, err := loadBaselineSecrets()
	if err != nil {
		traceCtx.Error("cli", "loadBaselineSecrets", err, nil)
		traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "error", "dashboard secrets load failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard disconnect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard secrets load failed"}
	}
	traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "ok", "dashboard secrets loaded", nil)

	ref := strings.TrimSpace(cfg.Dashboard.Upload.APIKeyRef)
	traceCtx.SetMetadata("project_id", strings.TrimSpace(cfg.Dashboard.Upload.ProjectID))
	cfg.Dashboard.Upload = dashboardUploadConfig{}
	if ref != "" && secrets.Dashboard.APIKeys != nil {
		delete(secrets.Dashboard.APIKeys, ref)
	}

	saveConfigSpan := traceCtx.HelperEnter("cli", "saveBaselineLocalConfig", "saving cleared dashboard config", nil)
	if err := saveBaselineLocalConfig(cfg); err != nil {
		traceCtx.Error("cli", "saveBaselineLocalConfig", err, nil)
		traceCtx.HelperExit(saveConfigSpan, "cli", "saveBaselineLocalConfig", "error", "local dashboard config save failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard disconnect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard config save failed"}
	}
	traceCtx.HelperExit(saveConfigSpan, "cli", "saveBaselineLocalConfig", "ok", "cleared dashboard config saved", nil)

	saveSecretsSpan := traceCtx.HelperEnter("cli", "saveBaselineSecrets", "saving cleared dashboard secrets", nil)
	if err := saveBaselineSecrets(secrets); err != nil {
		traceCtx.Error("cli", "saveBaselineSecrets", err, nil)
		traceCtx.HelperExit(saveSecretsSpan, "cli", "saveBaselineSecrets", "error", "dashboard secrets save failed", nil)
		emitCLIEvent(telemetryConnection, cliEventPayload{
			EventType: "cli_error",
			Command:   "dashboard disconnect",
			Message:   err.Error(),
			Status:    "system_error",
		})
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard secrets save failed"}
	}
	traceCtx.HelperExit(saveSecretsSpan, "cli", "saveBaselineSecrets", "ok", "cleared dashboard secrets saved", nil)

	emitCLIEvent(telemetryConnection, cliEventPayload{
		EventType: "cli_config_changed",
		Command:   "dashboard disconnect",
		Message:   "dashboard connection removed",
		Status:    "disconnected",
	})
	fmt.Println("Dashboard connection removed for this project.")
	return tracedCommandResult{
		ExitCode:     types.ExitSuccess,
		TraceStatus:  "disconnected",
		TraceMessage: "dashboard connection removed",
	}
}

func parseDashboardConnectArgs(args []string) (dashboardConnectOptions, error) {
	opts := dashboardConnectOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			return dashboardConnectOptions{}, errDashboardHelp
		case "--api":
			if i+1 >= len(args) {
				return dashboardConnectOptions{}, errors.New("--api requires a value")
			}
			opts.APIBaseURL = strings.TrimSpace(args[i+1])
			i++
		case "--api-key":
			if i+1 >= len(args) {
				return dashboardConnectOptions{}, errors.New("--api-key requires a value")
			}
			opts.APIKey = strings.TrimSpace(args[i+1])
			i++
		case "--project-id":
			if i+1 >= len(args) {
				return dashboardConnectOptions{}, errors.New("--project-id requires a value")
			}
			opts.ProjectID = strings.TrimSpace(args[i+1])
			i++
		default:
			return dashboardConnectOptions{}, fmt.Errorf("unknown flag %s", args[i])
		}
	}
	return opts, nil
}

func connectDashboardForCurrentProject(traceCtx *clitrace.Context, opts dashboardConnectOptions, stdin *os.File, stdout *os.File, interactive bool) (dashboardConnectResult, error) {
	var reader *bufio.Reader
	if interactive {
		reader = bufio.NewReader(stdin)
	}
	return connectDashboardForCurrentProjectWithReader(traceCtx, opts, reader, stdout, interactive)
}

func connectDashboardForCurrentProjectWithReader(traceCtx *clitrace.Context, opts dashboardConnectOptions, reader *bufio.Reader, stdout *os.File, interactive bool) (dashboardConnectResult, error) {
	apiBaseURL := resolveDashboardConnectBaseURL(strings.TrimSpace(opts.APIBaseURL))
	apiKey := strings.TrimSpace(opts.APIKey)
	projectID := strings.TrimSpace(opts.ProjectID)

	if interactive {
		if reader == nil {
			return dashboardConnectResult{}, errors.New("interactive dashboard connect requires an input reader")
		}
	}

	if strings.TrimSpace(apiBaseURL) == "" {
		return dashboardConnectResult{}, errors.New("dashboard API URL is required")
	}
	validateSpan := ""
	if traceCtx != nil {
		validateSpan = traceCtx.HelperEnter("cli", "validateAPIBaseURL", "validating dashboard API base URL", nil)
	}
	normalizedURL, err := validateAPIBaseURL(apiBaseURL)
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "validateAPIBaseURL", err, nil)
			traceCtx.HelperExit(validateSpan, "cli", "validateAPIBaseURL", "error", "dashboard API base URL validation failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(validateSpan, "cli", "validateAPIBaseURL", "ok", "dashboard API base URL validated", nil)
	}
	apiBaseURL = normalizedURL

	if strings.TrimSpace(apiKey) == "" {
		if token := dashboardSessionAccessTokenForBaseURL(apiBaseURL); token != "" {
			return connectDashboardUploadWithBearerToken(apiBaseURL, token, projectID)
		}
		if interactive {
			result, err := connectDashboardForCurrentProjectViaBrowserLogin(traceCtx, apiBaseURL, projectID, stdout)
			if err == nil {
				return result, nil
			}
			fmt.Fprintf(stdout, "Dashboard browser connect unavailable (%v). Falling back to manual API key entry.\n", err)
			prompt := fmt.Sprintf("Dashboard API URL [%s]: ", apiBaseURL)
			value, promptErr := promptForInput(reader, stdout, prompt)
			if promptErr != nil {
				return dashboardConnectResult{}, promptErr
			}
			value = strings.TrimSpace(value)
			if value != "" {
				apiBaseURL, err = validateAPIBaseURL(value)
				if err != nil {
					return dashboardConnectResult{}, err
				}
			}
			value, promptErr = promptForInput(reader, stdout, "Dashboard API key: ")
			if promptErr != nil {
				return dashboardConnectResult{}, promptErr
			}
			apiKey = strings.TrimSpace(value)
		}
	}
	if strings.TrimSpace(apiKey) == "" {
		return dashboardConnectResult{}, errors.New("dashboard API key is required")
	}

	client := &http.Client{Timeout: 15 * time.Second}

	resolveProjectSpan := ""
	if traceCtx != nil {
		resolveProjectSpan = traceCtx.HelperEnter("cli", "resolveOrCreateProjectForConnection", "resolving or creating dashboard project", nil)
	}
	resolvedProjectID, err := resolveOrCreateProjectForConnection(client, apiBaseURL, apiKey, projectID)
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "resolveOrCreateProjectForConnection", err, nil)
			traceCtx.HelperExit(resolveProjectSpan, "cli", "resolveOrCreateProjectForConnection", "error", "dashboard project resolution failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.SetMetadata("project_id", resolvedProjectID)
		traceCtx.HelperExit(resolveProjectSpan, "cli", "resolveOrCreateProjectForConnection", "ok", "dashboard project resolved", map[string]string{
			"project_id": resolvedProjectID,
		})
	}

	configSpan := ""
	if traceCtx != nil {
		configSpan = traceCtx.HelperEnter("cli", "loadBaselineLocalConfig", "loading local dashboard config", nil)
	}
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "loadBaselineLocalConfig", err, nil)
			traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "error", "local dashboard config load failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(configSpan, "cli", "loadBaselineLocalConfig", "ok", "local dashboard config loaded", nil)
	}
	secretsSpan := ""
	if traceCtx != nil {
		secretsSpan = traceCtx.HelperEnter("cli", "loadBaselineSecrets", "loading dashboard secrets", nil)
	}
	secrets, err := loadBaselineSecrets()
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "loadBaselineSecrets", err, nil)
			traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "error", "dashboard secrets load failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(secretsSpan, "cli", "loadBaselineSecrets", "ok", "dashboard secrets loaded", nil)
	}
	if secrets.Dashboard.APIKeys == nil {
		secrets.Dashboard.APIKeys = map[string]string{}
	}

	cfg.Dashboard.Upload = dashboardUploadConfig{
		Prompted:   true,
		Enabled:    true,
		APIBaseURL: apiBaseURL,
		ProjectID:  resolvedProjectID,
		APIKeyRef:  "default",
	}
	secrets.Dashboard.APIKeys["default"] = apiKey

	saveConfigSpan := ""
	if traceCtx != nil {
		saveConfigSpan = traceCtx.HelperEnter("cli", "saveBaselineLocalConfig", "saving dashboard connection config", nil)
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "saveBaselineLocalConfig", err, nil)
			traceCtx.HelperExit(saveConfigSpan, "cli", "saveBaselineLocalConfig", "error", "dashboard connection config save failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(saveConfigSpan, "cli", "saveBaselineLocalConfig", "ok", "dashboard connection config saved", nil)
	}
	saveSecretsSpan := ""
	if traceCtx != nil {
		saveSecretsSpan = traceCtx.HelperEnter("cli", "saveBaselineSecrets", "saving dashboard API key", nil)
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "saveBaselineSecrets", err, nil)
			traceCtx.HelperExit(saveSecretsSpan, "cli", "saveBaselineSecrets", "error", "dashboard API key save failed", nil)
		}
		return dashboardConnectResult{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(saveSecretsSpan, "cli", "saveBaselineSecrets", "ok", "dashboard API key saved", nil)
	}

	return dashboardConnectResult{
		APIBaseURL: apiBaseURL,
		ProjectID:  resolvedProjectID,
	}, nil
}

func resolveDashboardConnectBaseURL(explicit string) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	if session := loadStoredDashboardCLISession(); strings.TrimSpace(session.APIBaseURL) != "" {
		return strings.TrimSpace(session.APIBaseURL)
	}
	if baseURL := defaultScanUploadBaseURL(); strings.TrimSpace(baseURL) != "" {
		return baseURL
	}
	return apiURLFromAPIAddr(os.Getenv("BASELINE_API_ADDR"))
}

func dashboardSessionAccessTokenForBaseURL(baseURL string) string {
	normalizedBaseURL := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if normalizedBaseURL == "" {
		return ""
	}
	if session, err := refreshedStoredDashboardCLISession(normalizedBaseURL); err == nil {
		if strings.TrimRight(strings.TrimSpace(session.APIBaseURL), "/") == normalizedBaseURL && strings.TrimSpace(session.AccessToken) != "" {
			return strings.TrimSpace(session.AccessToken)
		}
	}
	return storedCLIAccessTokenForBaseURL(normalizedBaseURL)
}

func connectDashboardForCurrentProjectViaBrowserLogin(traceCtx *clitrace.Context, apiBaseURL, explicitProjectID string, stdout *os.File) (dashboardConnectResult, error) {
	session, err := completeDashboardBrowserLogin(traceCtx, apiBaseURL, "Approve this dashboard connection in your browser.", stdout, false)
	if err != nil {
		return dashboardConnectResult{}, err
	}
	return connectDashboardUploadWithBearerToken(apiBaseURL, session.AccessToken, explicitProjectID)
}

func maybePromptForDashboardUpload(stdin *os.File, stdout *os.File) (dashboardConnectionConfig, error) {
	if !interactiveTerminalCheck(stdin, stdout) {
		return dashboardConnectionConfig{}, errDashboardUploadPromptSkipped
	}
	reader := bufio.NewReader(stdin)
	answer, err := promptForInput(reader, stdout, "Upload scan results to your dashboard for this project? [y/N]: ")
	if err != nil {
		return dashboardConnectionConfig{}, err
	}
	normalized := strings.ToLower(strings.TrimSpace(answer))
	if normalized != "y" && normalized != "yes" {
		if err := disableDashboardUploadForProject(); err != nil {
			return dashboardConnectionConfig{}, err
		}
		return dashboardConnectionConfig{}, errDashboardUploadPromptSkipped
	}

	result, err := connectDashboardForCurrentProjectWithReader(nil, dashboardConnectOptions{}, reader, stdout, true)
	if err != nil {
		return dashboardConnectionConfig{}, err
	}
	return dashboardConnectionConfig{
		APIBaseURL: result.APIBaseURL,
		ProjectID:  result.ProjectID,
		APIKey:     loadStoredDashboardAPIKey("default"),
		Enabled:    true,
		Prompted:   true,
		Source:     "prompt",
	}, nil
}

func resolveDashboardUploadConfigForScan(opts scanCommandOptions) (dashboardConnectionConfig, error) {
	if strings.TrimSpace(opts.APIBaseURL) != "" {
		apiKey := strings.TrimSpace(opts.APIKey)
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("BASELINE_API_KEY"))
		}
		accessToken := storedCLIAccessTokenForBaseURL(strings.TrimSpace(opts.APIBaseURL))
		return dashboardConnectionConfig{
			APIBaseURL:  strings.TrimSpace(opts.APIBaseURL),
			ProjectID:   strings.TrimSpace(opts.ProjectID),
			APIKey:      apiKey,
			AccessToken: accessToken,
			Enabled:     true,
			Prompted:    true,
			Source:      "flags",
		}, nil
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return dashboardConnectionConfig{}, err
	}
	upload := cfg.Dashboard.Upload
	if upload.Prompted {
		apiKey := loadStoredDashboardAPIKey(upload.APIKeyRef)
		session := loadStoredDashboardCLISession()
		accessToken := ""
		refreshToken := ""
		if strings.TrimRight(strings.TrimSpace(session.APIBaseURL), "/") == strings.TrimRight(strings.TrimSpace(upload.APIBaseURL), "/") {
			accessToken = strings.TrimSpace(session.AccessToken)
			refreshToken = strings.TrimSpace(session.RefreshToken)
		}
		return dashboardConnectionConfig{
			APIBaseURL:   strings.TrimSpace(upload.APIBaseURL),
			ProjectID:    strings.TrimSpace(upload.ProjectID),
			APIKey:       apiKey,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			Enabled:      upload.Enabled,
			Prompted:     upload.Prompted,
			Source:       "saved",
		}, nil
	}

	session := loadStoredDashboardCLISession()
	if strings.TrimSpace(session.APIBaseURL) != "" && strings.TrimSpace(session.AccessToken) != "" {
		return dashboardConnectionConfig{
			APIBaseURL:   strings.TrimSpace(session.APIBaseURL),
			AccessToken:  strings.TrimSpace(session.AccessToken),
			RefreshToken: strings.TrimSpace(session.RefreshToken),
			Enabled:      true,
			Prompted:     false,
			Source:       "cli_session",
		}, nil
	}

	if scanUploadConfiguredFromEnv() {
		return dashboardConnectionConfig{
			APIBaseURL: defaultScanUploadBaseURL(),
			ProjectID:  strings.TrimSpace(opts.ProjectID),
			APIKey:     strings.TrimSpace(os.Getenv("BASELINE_API_KEY")),
			Enabled:    true,
			Prompted:   false,
			Source:     "env",
		}, nil
	}

	return dashboardConnectionConfig{}, nil
}

func shouldSuggestDashboardRepair(connection dashboardConnectionConfig, err error) bool {
	if connection.Source != "saved" || err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(message, "status 401") ||
		strings.Contains(message, "status 403") ||
		strings.Contains(message, "status 404") ||
		strings.Contains(message, "rejected with status 401") ||
		strings.Contains(message, "rejected with status 403") ||
		strings.Contains(message, "rejected with status 404") ||
		strings.Contains(message, "not found or not accessible") ||
		strings.Contains(message, "could not resolve a dashboard project") ||
		strings.Contains(message, "multiple projects matched") ||
		strings.Contains(message, "no projects found in api")
}

func shouldResetDashboardSavedConnection(connection dashboardConnectionConfig, err error) bool {
	if connection.Source != "saved" || err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(message, "status 401") ||
		strings.Contains(message, "status 403") ||
		strings.Contains(message, "rejected with status 401") ||
		strings.Contains(message, "rejected with status 403") ||
		strings.Contains(message, "unauthorized") ||
		strings.Contains(message, "forbidden")
}

func formatDashboardUploadFailure(connection dashboardConnectionConfig, err error) string {
	if !shouldSuggestDashboardRepair(connection, err) {
		return fmt.Sprintf("API upload failed: %v", err)
	}
	return fmt.Sprintf(
		"Dashboard upload failed: %v\nRun `baseline dashboard connect` to repair this project connection.",
		err,
	)
}

func resetSavedDashboardConnection() error {
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return err
	}
	secrets, err := loadBaselineSecrets()
	if err != nil {
		return err
	}

	ref := strings.TrimSpace(cfg.Dashboard.Upload.APIKeyRef)
	cfg.Dashboard.Upload = dashboardUploadConfig{}
	if ref != "" && secrets.Dashboard.APIKeys != nil {
		delete(secrets.Dashboard.APIKeys, ref)
	}

	if err := saveBaselineLocalConfig(cfg); err != nil {
		return err
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		return err
	}
	return nil
}

func resolveOrCreateProjectForConnection(client *http.Client, baseURL, apiKey, explicitProjectID string) (string, error) {
	if client == nil {
		client = &http.Client{}
	}
	projects, err := fetchUploadProjects(client, baseURL, apiKey)
	if err != nil {
		return "", err
	}
	explicit := strings.TrimSpace(explicitProjectID)
	if explicit != "" {
		for _, project := range projects {
			if strings.TrimSpace(project.ID) == explicit {
				return explicit, nil
			}
		}
		return "", fmt.Errorf("project %q not found or not accessible with this API key", explicit)
	}

	repoName := currentRepositoryName()
	remoteURL := currentGitRemoteURL()
	matched, matchErr := matchProjectForScanUpload(projects, repoName, remoteURL)
	if matchErr == nil {
		return strings.TrimSpace(matched.ID), nil
	}
	if !strings.Contains(matchErr.Error(), "could not resolve") {
		return "", matchErr
	}

	created, err := createProjectForConnection(client, baseURL, apiKey, repoName, remoteURL)
	if err != nil {
		return "", err
	}
	return created.ID, nil
}

func createProjectForConnection(client *http.Client, baseURL, apiKey, repoName, remoteURL string) (api.Project, error) {
	name := strings.TrimSpace(repoName)
	if name == "" {
		return api.Project{}, errors.New("could not determine repository name for project creation")
	}
	branch := currentGitBranch()
	if branch == "" {
		branch = "main"
	}
	payload := map[string]any{
		"name":           name,
		"repository_url": strings.TrimSpace(remoteURL),
		"default_branch": branch,
		"policy_set":     "baseline:prod",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return api.Project{}, fmt.Errorf("encode project create payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/projects", bytes.NewReader(body))
	if err != nil {
		return api.Project{}, fmt.Errorf("build project create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return api.Project{}, fmt.Errorf("create project: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return api.Project{}, fmt.Errorf("project create rejected with status %d", resp.StatusCode)
	}
	var created api.Project
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return api.Project{}, fmt.Errorf("decode project create response: %w", err)
	}
	return created, nil
}

func currentGitBranch() string {
	out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(out))
	if strings.EqualFold(value, "HEAD") {
		return ""
	}
	return value
}

func promptForInput(reader *bufio.Reader, stdout *os.File, prompt string) (string, error) {
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func isInteractiveTerminal(stdin *os.File, stdout *os.File) bool {
	if stdin == nil || stdout == nil {
		return false
	}
	if strings.TrimSpace(os.Getenv("CI")) != "" {
		return false
	}
	stdinInfo, err := stdin.Stat()
	if err != nil {
		return false
	}
	stdoutInfo, err := stdout.Stat()
	if err != nil {
		return false
	}
	return (stdinInfo.Mode()&os.ModeCharDevice) != 0 && (stdoutInfo.Mode()&os.ModeCharDevice) != 0
}

func disableDashboardUploadForProject() error {
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return err
	}
	cfg.Dashboard.Upload = dashboardUploadConfig{
		Prompted: true,
		Enabled:  false,
	}
	return saveBaselineLocalConfig(cfg)
}

func baselineConfigPath() string {
	if explicit := strings.TrimSpace(os.Getenv("BASELINE_CONFIG_PATH")); explicit != "" {
		return explicit
	}
	return filepath.Join(".baseline", "config.yaml")
}

func baselineSecretsPath() string {
	return filepath.Join(filepath.Dir(baselineConfigPath()), "secrets.json")
}

func loadBaselineLocalConfig() (baselineLocalConfig, error) {
	path := baselineConfigPath()
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return baselineLocalConfig{}, nil
		}
		return baselineLocalConfig{}, err
	}
	cfg, err := parseBaselineLocalConfig(content)
	if err != nil {
		return baselineLocalConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

func parseBaselineLocalConfig(content []byte) (baselineLocalConfig, error) {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return baselineLocalConfig{}, nil
	}
	if looksLikeLegacyBaselineConfig(trimmed) {
		return parseLegacyBaselineLocalConfig(trimmed), nil
	}
	var cfg baselineLocalConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return baselineLocalConfig{}, err
	}
	return cfg, nil
}

func looksLikeLegacyBaselineConfig(content string) bool {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			colonIdx := strings.Index(line, ":")
			return colonIdx == -1 || idx < colonIdx
		}
		if strings.Contains(line, ":") {
			return false
		}
	}
	return false
}

func parseLegacyBaselineLocalConfig(content string) baselineLocalConfig {
	cfg := baselineLocalConfig{}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch key {
		case "policy_set":
			cfg.PolicySet = value
		case "enforcement_mode":
			cfg.EnforcementMode = value
		}
	}
	return cfg
}

func saveBaselineLocalConfig(cfg baselineLocalConfig) error {
	path := baselineConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	payload, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0644)
}

func loadBaselineSecrets() (baselineSecrets, error) {
	path := baselineSecretsPath()
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return baselineSecrets{}, nil
		}
		return baselineSecrets{}, err
	}
	var secrets baselineSecrets
	if err := json.Unmarshal(content, &secrets); err != nil {
		return baselineSecrets{}, err
	}
	return secrets, nil
}

func saveBaselineSecrets(secrets baselineSecrets) error {
	path := baselineSecretsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0600)
}

func loadStoredDashboardAPIKey(ref string) string {
	secrets, err := loadBaselineSecrets()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(secrets.Dashboard.APIKeys[strings.TrimSpace(ref)])
}

func loadStoredDashboardCLISession() baselineDashboardCLISession {
	secrets, err := loadBaselineSecrets()
	if err != nil {
		return baselineDashboardCLISession{}
	}
	return secrets.Dashboard.CLISession
}

func saveStoredDashboardCLISession(session baselineDashboardCLISession) error {
	secrets, err := loadBaselineSecrets()
	if err != nil {
		return err
	}
	secrets.Dashboard.CLISession = session
	return saveBaselineSecrets(secrets)
}

func clearStoredDashboardCLISession() error {
	return saveStoredDashboardCLISession(baselineDashboardCLISession{})
}

func storedCLIAccessTokenForBaseURL(baseURL string) string {
	session := loadStoredDashboardCLISession()
	if strings.TrimSpace(session.AccessToken) == "" {
		return ""
	}
	storedBaseURL := strings.TrimRight(strings.TrimSpace(session.APIBaseURL), "/")
	if storedBaseURL == "" {
		return ""
	}
	if strings.TrimRight(strings.TrimSpace(baseURL), "/") != storedBaseURL {
		return ""
	}
	return strings.TrimSpace(session.AccessToken)
}

func authTokenForBaseURL(baseURL, explicitAPIKey string) string {
	if token := strings.TrimSpace(explicitAPIKey); token != "" {
		return token
	}
	if session, err := refreshedStoredDashboardCLISession(baseURL); err == nil {
		if strings.TrimSpace(session.AccessToken) != "" {
			return strings.TrimSpace(session.AccessToken)
		}
	}
	if token := storedCLIAccessTokenForBaseURL(baseURL); token != "" {
		return token
	}
	return strings.TrimSpace(os.Getenv("BASELINE_API_KEY"))
}

func valueOrPlaceholder(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "(not set)"
	}
	return trimmed
}

func printDashboardConnectUsage() {
	fmt.Println("Usage: baseline dashboard connect [--api <url>] [--api-key <key>] [--project-id <id>]")
	fmt.Println()
	fmt.Println("Legacy fallback: connect the current project to a Baseline dashboard using a user-owned API key.")
	fmt.Println("Recommended for humans: use `baseline dashboard login` so the CLI reuses your dashboard session instead.")
}

func printDashboardStatusUsage() {
	fmt.Println("Usage: baseline dashboard status")
}

func printDashboardDisconnectUsage() {
	fmt.Println("Usage: baseline dashboard disconnect")
}
