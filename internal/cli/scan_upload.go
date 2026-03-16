package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/baseline/baseline/internal/api"
	"github.com/baseline/baseline/internal/types"
)

type scanCommandOptions struct {
	Help         bool
	APIBaseURL   string
	ProjectID    string
	APIKey       string
	ScanID       string
	CommitSHA    string
	UploadRunKey string
}

type uploadedScanDetails struct {
	BaseURL   string
	ProjectID string
	ScanID    string
}

func scanUploadConfiguredFromEnv() bool {
	if strings.TrimSpace(os.Getenv("BASELINE_SCAN_API_URL")) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("BASELINE_API_KEY")) == "" {
		return false
	}
	return strings.TrimSpace(os.Getenv("BASELINE_API_ADDR")) != ""
}

func defaultScanUploadBaseURL() string {
	if explicit := strings.TrimSpace(os.Getenv("BASELINE_SCAN_API_URL")); explicit != "" {
		return explicit
	}
	if strings.TrimSpace(os.Getenv("BASELINE_API_KEY")) == "" {
		return ""
	}
	addr := strings.TrimSpace(os.Getenv("BASELINE_API_ADDR"))
	if addr == "" {
		return ""
	}
	return apiURLFromAPIAddr(addr)
}

func parseScanArgs(args []string) (scanCommandOptions, error) {
	opts := scanCommandOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			opts.Help = true
		case "--api":
			if i+1 >= len(args) {
				return scanCommandOptions{}, fmt.Errorf("--api requires a URL")
			}
			opts.APIBaseURL = strings.TrimSpace(args[i+1])
			i++
		case "--project-id":
			if i+1 >= len(args) {
				return scanCommandOptions{}, fmt.Errorf("--project-id requires a value")
			}
			opts.ProjectID = strings.TrimSpace(args[i+1])
			i++
		case "--api-key":
			if i+1 >= len(args) {
				return scanCommandOptions{}, fmt.Errorf("--api-key requires a value")
			}
			opts.APIKey = strings.TrimSpace(args[i+1])
			i++
		case "--scan-id":
			if i+1 >= len(args) {
				return scanCommandOptions{}, fmt.Errorf("--scan-id requires a value")
			}
			opts.ScanID = strings.TrimSpace(args[i+1])
			i++
		case "--commit-sha":
			if i+1 >= len(args) {
				return scanCommandOptions{}, fmt.Errorf("--commit-sha requires a value")
			}
			opts.CommitSHA = strings.TrimSpace(args[i+1])
			i++
		default:
			return scanCommandOptions{}, fmt.Errorf("unknown flag %s", args[i])
		}
	}
	return opts, nil
}

func uploadScanResults(opts scanCommandOptions, results types.ScanResults) (uploadedScanDetails, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(opts.APIBaseURL), "/")
	if baseURL == "" {
		return uploadedScanDetails{}, fmt.Errorf("API base URL is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return uploadedScanDetails{}, fmt.Errorf("invalid API URL: %w", err)
	}

	authToken := authTokenForBaseURL(baseURL, opts.APIKey)
	if authToken == "" {
		return uploadedScanDetails{}, fmt.Errorf("API upload requires `baseline dashboard login`, `--api-key`, or BASELINE_API_KEY")
	}

	commitSHA := strings.TrimSpace(opts.CommitSHA)
	if commitSHA == "" {
		commitSHA = currentGitCommitSHA()
	}

	client := &http.Client{Timeout: 15 * time.Second}
	projectID := strings.TrimSpace(opts.ProjectID)
	if projectID == "" {
		resolved, err := resolveProjectIDForUpload(client, baseURL, authToken)
		if err != nil {
			return uploadedScanDetails{}, err
		}
		projectID = resolved
	}

	payload := api.CreateScanRequest{
		ID:           strings.TrimSpace(opts.ScanID),
		ProjectID:    projectID,
		CommitSHA:    commitSHA,
		FilesScanned: results.FilesScanned,
		Status:       deriveScanUploadStatus(results),
		Violations:   make([]api.ScanViolation, 0, len(results.Violations)),
	}
	for _, violation := range results.Violations {
		severity := strings.ToLower(strings.TrimSpace(violation.Severity))
		if severity == "" {
			severity = strings.ToLower(types.SeverityBlock)
		}
		payload.Violations = append(payload.Violations, api.ScanViolation{
			PolicyID: strings.TrimSpace(violation.PolicyID),
			Severity: severity,
			Message:  strings.TrimSpace(violation.Message),
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return uploadedScanDetails{}, fmt.Errorf("encode upload payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/scans", bytes.NewReader(body))
	if err != nil {
		return uploadedScanDetails{}, fmt.Errorf("build upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", scanUploadIdempotencyKey(payload, strings.TrimSpace(opts.UploadRunKey)))

	resp, err := client.Do(req)
	if err != nil {
		return uploadedScanDetails{}, fmt.Errorf("upload scan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var payload map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		return uploadedScanDetails{}, fmt.Errorf("upload rejected with status %d", resp.StatusCode)
	}

	var created struct {
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return uploadedScanDetails{}, fmt.Errorf("decode upload response: %w", err)
	}

	return uploadedScanDetails{
		BaseURL:   baseURL,
		ProjectID: created.ProjectID,
		ScanID:    created.ID,
	}, nil
}

func deriveScanUploadStatus(results types.ScanResults) string {
	hasWarn := false
	for _, violation := range results.Violations {
		switch strings.ToLower(strings.TrimSpace(violation.Severity)) {
		case "block":
			return "fail"
		case "warn":
			hasWarn = true
		}
	}
	if hasWarn {
		return "warn"
	}
	return "pass"
}

func scanUploadIdempotencyKey(payload api.CreateScanRequest, runKey string) string {
	normalizedRunKey := strings.TrimSpace(runKey)
	if normalizedRunKey == "" {
		normalizedRunKey = "manual"
	}
	scanID := strings.TrimSpace(payload.ID)
	if scanID == "" {
		scanID = "auto"
	}
	return fmt.Sprintf("scan-upload:%s:%s", normalizedRunKey, scanID)
}

func resolveProjectIDForUpload(client *http.Client, baseURL, authToken string) (string, error) {
	projects, err := fetchUploadProjects(client, baseURL, authToken)
	if err != nil {
		return "", err
	}
	if len(projects) == 0 {
		return "", fmt.Errorf("no projects found in API; create a project first or pass --project-id")
	}
	if len(projects) == 1 {
		return strings.TrimSpace(projects[0].ID), nil
	}

	repoName := currentRepositoryName()
	remoteURL := currentGitRemoteURL()
	matched, matchErr := matchProjectForScanUpload(projects, repoName, remoteURL)
	if matchErr != nil {
		return "", matchErr
	}
	return matched.ID, nil
}

func fetchUploadProjects(client *http.Client, baseURL, authToken string) ([]api.Project, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/projects", nil)
	if err != nil {
		return nil, fmt.Errorf("build project lookup request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("project lookup rejected with status %d", resp.StatusCode)
	}

	var payload struct {
		Projects []api.Project `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode project lookup response: %w", err)
	}
	return payload.Projects, nil
}

func matchProjectForScanUpload(projects []api.Project, repoName, remoteURL string) (api.Project, error) {
	normalizedRemote := normalizeGitURL(remoteURL)
	if normalizedRemote != "" {
		matches := make([]api.Project, 0, 1)
		for _, project := range projects {
			if normalizeGitURL(project.RepositoryURL) == normalizedRemote {
				matches = append(matches, project)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return api.Project{}, fmt.Errorf("multiple projects matched git remote %q; pass --project-id", remoteURL)
		}
	}

	normalizedName := strings.ToLower(strings.TrimSpace(repoName))
	if normalizedName != "" {
		matches := make([]api.Project, 0, 1)
		for _, project := range projects {
			if strings.ToLower(strings.TrimSpace(project.Name)) == normalizedName {
				matches = append(matches, project)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return api.Project{}, fmt.Errorf("multiple projects matched repository name %q; pass --project-id", repoName)
		}
	}

	return api.Project{}, fmt.Errorf("could not resolve a dashboard project from the current repository; pass --project-id")
}

func currentRepositoryName() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Base(cwd)
}

func currentGitRemoteURL() string {
	out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func currentGitCommitSHA() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func normalizeGitURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	value = strings.TrimSuffix(value, ".git")
	if strings.HasPrefix(value, "git@") {
		value = strings.TrimPrefix(value, "git@")
		parts := strings.SplitN(value, ":", 2)
		if len(parts) == 2 {
			value = "https://" + parts[0] + "/" + parts[1]
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return strings.ToLower(value)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	path := strings.Trim(strings.ToLower(parsed.Path), "/")
	if host == "" {
		return strings.ToLower(value)
	}
	return host + "/" + path
}
