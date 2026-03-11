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
	APIKeys map[string]string `json:"api_keys,omitempty"`
}

type dashboardConnectionConfig struct {
	APIBaseURL string
	ProjectID  string
	APIKey     string
	Enabled    bool
	Prompted   bool
	Source     string
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
	if err := requireGitRepo(); err != nil {
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}
	if err := loadAPIEnvFiles(); err != nil {
		fmt.Printf("DASHBOARD CONNECT FAILED: unable to load API env file: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	opts, err := parseDashboardConnectArgs(args)
	if err != nil {
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n\n", err)
		printDashboardConnectUsage()
		os.Exit(types.ExitSystemError)
	}

	result, err := connectDashboardForCurrentProject(opts, os.Stdin, os.Stdout, true)
	if err != nil {
		fmt.Printf("DASHBOARD CONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Printf("Dashboard connection saved.\n")
	fmt.Printf("API: %s\n", result.APIBaseURL)
	fmt.Printf("Project: %s\n", result.ProjectID)
	os.Exit(types.ExitSuccess)
}

func handleDashboardStatus(args []string) {
	if len(args) > 0 && hasHelpFlag(args) {
		printDashboardStatusUsage()
		os.Exit(types.ExitSuccess)
	}
	if len(args) > 0 {
		fmt.Printf("DASHBOARD STATUS FAILED: unknown flag %s\n\n", args[0])
		printDashboardStatusUsage()
		os.Exit(types.ExitSystemError)
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		fmt.Printf("DASHBOARD STATUS FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}
	secrets, err := loadBaselineSecrets()
	if err != nil {
		fmt.Printf("DASHBOARD STATUS FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	upload := cfg.Dashboard.Upload
	apiKey := strings.TrimSpace(secrets.Dashboard.APIKeys[upload.APIKeyRef])

	fmt.Println("=== DASHBOARD CONNECTION STATUS ===")
	fmt.Printf("Config file: %s\n", baselineConfigPath())
	fmt.Printf("Prompted: %t\n", upload.Prompted)
	fmt.Printf("Enabled: %t\n", upload.Enabled)
	fmt.Printf("API URL: %s\n", valueOrPlaceholder(upload.APIBaseURL))
	fmt.Printf("Project ID: %s\n", valueOrPlaceholder(upload.ProjectID))
	fmt.Printf("API key stored: %t\n", apiKey != "")

	if !upload.Prompted {
		fmt.Println("Status: not configured for this project.")
	} else if upload.Enabled && upload.APIBaseURL != "" && upload.ProjectID != "" && apiKey != "" {
		fmt.Println("Status: connected.")
	} else if upload.Enabled {
		fmt.Println("Status: incomplete connection. Run `baseline dashboard connect` to repair it.")
	} else {
		fmt.Println("Status: dashboard upload disabled for this project.")
	}
	os.Exit(types.ExitSuccess)
}

func handleDashboardDisconnect(args []string) {
	if len(args) > 0 && hasHelpFlag(args) {
		printDashboardDisconnectUsage()
		os.Exit(types.ExitSuccess)
	}
	if len(args) > 0 {
		fmt.Printf("DASHBOARD DISCONNECT FAILED: unknown flag %s\n\n", args[0])
		printDashboardDisconnectUsage()
		os.Exit(types.ExitSystemError)
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}
	secrets, err := loadBaselineSecrets()
	if err != nil {
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	ref := strings.TrimSpace(cfg.Dashboard.Upload.APIKeyRef)
	cfg.Dashboard.Upload = dashboardUploadConfig{}
	if ref != "" && secrets.Dashboard.APIKeys != nil {
		delete(secrets.Dashboard.APIKeys, ref)
	}

	if err := saveBaselineLocalConfig(cfg); err != nil {
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		fmt.Printf("DASHBOARD DISCONNECT FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	fmt.Println("Dashboard connection removed for this project.")
	os.Exit(types.ExitSuccess)
}

func parseDashboardConnectArgs(args []string) (dashboardConnectOptions, error) {
	opts := dashboardConnectOptions{
		APIBaseURL: defaultScanUploadBaseURL(),
	}
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

func connectDashboardForCurrentProject(opts dashboardConnectOptions, stdin *os.File, stdout *os.File, interactive bool) (dashboardConnectResult, error) {
	var reader *bufio.Reader
	if interactive {
		reader = bufio.NewReader(stdin)
	}
	return connectDashboardForCurrentProjectWithReader(opts, reader, stdout, interactive)
}

func connectDashboardForCurrentProjectWithReader(opts dashboardConnectOptions, reader *bufio.Reader, stdout *os.File, interactive bool) (dashboardConnectResult, error) {
	apiBaseURL := strings.TrimSpace(opts.APIBaseURL)
	apiKey := strings.TrimSpace(opts.APIKey)
	projectID := strings.TrimSpace(opts.ProjectID)

	if interactive {
		if reader == nil {
			return dashboardConnectResult{}, errors.New("interactive dashboard connect requires an input reader")
		}
		if apiBaseURL == "" {
			prompt := fmt.Sprintf("Dashboard API URL [%s]: ", apiURLFromAPIAddr(os.Getenv("BASELINE_API_ADDR")))
			value, err := promptForInput(reader, stdout, prompt)
			if err != nil {
				return dashboardConnectResult{}, err
			}
			apiBaseURL = strings.TrimSpace(value)
			if apiBaseURL == "" {
				apiBaseURL = apiURLFromAPIAddr(os.Getenv("BASELINE_API_ADDR"))
			}
		}
		if apiKey == "" {
			value, err := promptForInput(reader, stdout, "Dashboard API key: ")
			if err != nil {
				return dashboardConnectResult{}, err
			}
			apiKey = strings.TrimSpace(value)
		}
	}

	if apiBaseURL == "" {
		apiBaseURL = defaultScanUploadBaseURL()
	}
	if strings.TrimSpace(apiBaseURL) == "" {
		return dashboardConnectResult{}, errors.New("dashboard API URL is required")
	}
	normalizedURL, err := validateAPIBaseURL(apiBaseURL)
	if err != nil {
		return dashboardConnectResult{}, err
	}
	apiBaseURL = normalizedURL
	if strings.TrimSpace(apiKey) == "" {
		return dashboardConnectResult{}, errors.New("dashboard API key is required")
	}

	client := &http.Client{Timeout: 15 * time.Second}

	resolvedProjectID, err := resolveOrCreateProjectForConnection(client, apiBaseURL, apiKey, projectID)
	if err != nil {
		return dashboardConnectResult{}, err
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return dashboardConnectResult{}, err
	}
	secrets, err := loadBaselineSecrets()
	if err != nil {
		return dashboardConnectResult{}, err
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

	if err := saveBaselineLocalConfig(cfg); err != nil {
		return dashboardConnectResult{}, err
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		return dashboardConnectResult{}, err
	}

	return dashboardConnectResult{
		APIBaseURL: apiBaseURL,
		ProjectID:  resolvedProjectID,
	}, nil
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

	result, err := connectDashboardForCurrentProjectWithReader(dashboardConnectOptions{}, reader, stdout, true)
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
		return dashboardConnectionConfig{
			APIBaseURL: strings.TrimSpace(opts.APIBaseURL),
			ProjectID:  strings.TrimSpace(opts.ProjectID),
			APIKey:     apiKey,
			Enabled:    true,
			Prompted:   true,
			Source:     "flags",
		}, nil
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return dashboardConnectionConfig{}, err
	}
	upload := cfg.Dashboard.Upload
	if upload.Prompted {
		apiKey := loadStoredDashboardAPIKey(upload.APIKeyRef)
		return dashboardConnectionConfig{
			APIBaseURL: strings.TrimSpace(upload.APIBaseURL),
			ProjectID:  strings.TrimSpace(upload.ProjectID),
			APIKey:     apiKey,
			Enabled:    upload.Enabled,
			Prompted:   upload.Prompted,
			Source:     "saved",
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

func formatDashboardUploadFailure(connection dashboardConnectionConfig, err error) string {
	if !shouldSuggestDashboardRepair(connection, err) {
		return fmt.Sprintf("API upload failed: %v", err)
	}
	return fmt.Sprintf(
		"Dashboard upload failed: %v\nRun `baseline dashboard connect` to repair this project connection.",
		err,
	)
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
	if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, ":") {
		return parseLegacyBaselineLocalConfig(trimmed), nil
	}
	var cfg baselineLocalConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return baselineLocalConfig{}, err
	}
	return cfg, nil
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
	fmt.Println("Connect the current project to a Baseline dashboard using a user-owned API key.")
}

func printDashboardStatusUsage() {
	fmt.Println("Usage: baseline dashboard status")
}

func printDashboardDisconnectUsage() {
	fmt.Println("Usage: baseline dashboard disconnect")
}
