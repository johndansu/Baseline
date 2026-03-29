package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

var openBrowserForDashboardLogin = openBrowserURL

const defaultHostedDashboardAPIURL = "https://baseline-api-95nb.onrender.com"

func handleDashboardLogin(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard login", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardLoginCommand(traceCtx, args)
	}))
}

func handleDashboardLogout(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard logout", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardLogoutCommand(traceCtx, args)
	}))
}

func handleDashboardWhoAmI(args []string) {
	connection := resolveCLITelemetryConnection()
	os.Exit(runTracedCommand("dashboard whoami", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		return runDashboardWhoAmICommand(traceCtx, args)
	}))
}

type dashboardLoginOptions struct {
	APIBaseURL string
	NoOpen     bool
}

func parseDashboardLoginArgs(args []string) (dashboardLoginOptions, error) {
	opts := dashboardLoginOptions{
		APIBaseURL: defaultDashboardLoginBaseURL(),
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			return dashboardLoginOptions{}, errDashboardHelp
		case "--api":
			if i+1 >= len(args) {
				return dashboardLoginOptions{}, errors.New("--api requires a value")
			}
			opts.APIBaseURL = strings.TrimSpace(args[i+1])
			i++
		case "--no-open":
			opts.NoOpen = true
		default:
			return dashboardLoginOptions{}, fmt.Errorf("unknown flag %s", args[i])
		}
	}
	return opts, nil
}

func runDashboardLoginCommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	parseSpan := traceCtx.HelperEnter("cli", "parseDashboardLoginArgs", "parsing dashboard login arguments", nil)
	opts, err := parseDashboardLoginArgs(args)
	if err != nil {
		if errors.Is(err, errDashboardHelp) {
			traceCtx.Branch("cli", "dashboard login", "help_requested", nil)
			traceCtx.HelperExit(parseSpan, "cli", "parseDashboardLoginArgs", "ok", "dashboard login help requested", nil)
			printDashboardLoginUsage()
			return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard login help shown"}
		}
		traceCtx.Error("cli", "parseDashboardLoginArgs", err, nil)
		traceCtx.HelperExit(parseSpan, "cli", "parseDashboardLoginArgs", "error", "dashboard login arguments invalid", nil)
		fmt.Printf("DASHBOARD LOGIN FAILED: %v\n\n", err)
		printDashboardLoginUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard login arguments invalid"}
	}
	traceCtx.HelperExit(parseSpan, "cli", "parseDashboardLoginArgs", "ok", "dashboard login arguments parsed", nil)

	validateSpan := traceCtx.HelperEnter("cli", "validateAPIBaseURL", "validating dashboard login API base URL", nil)
	baseURL, err := validateAPIBaseURL(opts.APIBaseURL)
	if err != nil {
		traceCtx.Error("cli", "validateAPIBaseURL", err, nil)
		traceCtx.HelperExit(validateSpan, "cli", "validateAPIBaseURL", "error", "dashboard login API base URL invalid", nil)
		fmt.Printf("DASHBOARD LOGIN FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard login API URL invalid"}
	}
	traceCtx.HelperExit(validateSpan, "cli", "validateAPIBaseURL", "ok", "dashboard login API base URL validated", nil)

	session, err := completeDashboardBrowserLogin(traceCtx, baseURL, "Approve this CLI session in your dashboard.", os.Stdout, opts.NoOpen)
	if err != nil {
		fmt.Printf("DASHBOARD LOGIN FAILED: %v\n", err)
		traceStatus := "system_error"
		traceMessage := "dashboard login request start failed"
		if strings.Contains(strings.ToLower(err.Error()), "approval") || strings.Contains(strings.ToLower(err.Error()), "expired") {
			traceStatus = "login_failed"
			traceMessage = "dashboard login approval failed"
		}
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: traceStatus, TraceMessage: traceMessage}
	}

	activationSpan := traceCtx.HelperEnter("cli", "activateDashboardUploadForSession", "activating dashboard upload for current project", nil)
	if err := activateDashboardUploadForSession(baseURL, session.AccessToken); err != nil {
		traceCtx.Error("cli", "activateDashboardUploadForSession", err, nil)
		traceCtx.HelperExit(activationSpan, "cli", "activateDashboardUploadForSession", "warning", "dashboard upload activation skipped", nil)
		fmt.Printf("CLI session connected, but project activation was skipped: %v\n", err)
	} else {
		traceCtx.HelperExit(activationSpan, "cli", "activateDashboardUploadForSession", "ok", "dashboard upload activated for current project", nil)
	}

	traceCtx.SetMetadata("status", "authenticated")
	fmt.Printf("CLI session connected.\n")
	if session.User != "" {
		fmt.Printf("User: %s\n", session.User)
	}
	if session.Role != "" {
		fmt.Printf("Role: %s\n", session.Role)
	}
	fmt.Printf("API: %s\n", session.APIBaseURL)
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "authenticated", TraceMessage: "CLI dashboard session connected"}
}

func completeDashboardBrowserLogin(traceCtx *clitrace.Context, baseURL, intro string, stdout *os.File, noOpen bool) (baselineDashboardCLISession, error) {
	startSpan := ""
	if traceCtx != nil {
		startSpan = traceCtx.HelperEnter("cli", "startCLISessionLogin", "starting CLI dashboard login request", nil)
	}
	started, err := startCLISessionLogin(baseURL)
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "startCLISessionLogin", err, nil)
			traceCtx.HelperExit(startSpan, "cli", "startCLISessionLogin", "error", "dashboard login request start failed", nil)
		}
		return baselineDashboardCLISession{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(startSpan, "cli", "startCLISessionLogin", "ok", "dashboard login request started", nil)
	}

	output := stdout
	if output == nil {
		output = os.Stdout
	}
	if strings.TrimSpace(intro) == "" {
		intro = "Approve this request in your dashboard."
	}
	fmt.Fprintln(output, intro)
	fmt.Fprintf(output, "User code: %s\n", started.UserCode)
	fmt.Fprintf(output, "Verification URL: %s\n", started.VerificationURL)
	fmt.Fprintf(output, "Approval URL: %s\n", started.CompleteVerificationURL)

	if !noOpen {
		if traceCtx != nil {
			traceCtx.Branch("cli", "dashboard login", "open_browser", nil)
		}
		if err := openBrowserForDashboardLogin(started.CompleteVerificationURL); err != nil {
			if traceCtx != nil {
				traceCtx.Error("cli", "openBrowser", err, nil)
			}
			fmt.Fprintf(output, "Could not open browser automatically. Open this URL manually:\n%s\n", started.CompleteVerificationURL)
		}
	}

	pollSpan := ""
	if traceCtx != nil {
		pollSpan = traceCtx.HelperEnter("cli", "pollCLISessionLogin", "waiting for CLI dashboard login approval", nil)
	}
	session, err := pollCLISessionLogin(started)
	if err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "pollCLISessionLogin", err, nil)
			traceCtx.HelperExit(pollSpan, "cli", "pollCLISessionLogin", "error", "dashboard login approval failed", nil)
		}
		return baselineDashboardCLISession{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(pollSpan, "cli", "pollCLISessionLogin", "ok", "dashboard login approved", nil)
	}

	saveSpan := ""
	if traceCtx != nil {
		saveSpan = traceCtx.HelperEnter("cli", "saveStoredDashboardCLISession", "saving CLI dashboard session", nil)
	}
	if err := saveStoredDashboardCLISession(session); err != nil {
		if traceCtx != nil {
			traceCtx.Error("cli", "saveStoredDashboardCLISession", err, nil)
			traceCtx.HelperExit(saveSpan, "cli", "saveStoredDashboardCLISession", "error", "CLI dashboard session save failed", nil)
		}
		return baselineDashboardCLISession{}, err
	}
	if traceCtx != nil {
		traceCtx.HelperExit(saveSpan, "cli", "saveStoredDashboardCLISession", "ok", "CLI dashboard session saved", nil)
	}
	return session, nil
}

func connectDashboardUploadWithBearerToken(baseURL, authToken, explicitProjectID string) (dashboardConnectResult, error) {
	normalizedBaseURL := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token := strings.TrimSpace(authToken)
	if normalizedBaseURL == "" || token == "" {
		return dashboardConnectResult{}, errors.New("dashboard session is missing API base URL or access token")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	projectID, err := resolveOrCreateProjectForConnection(client, normalizedBaseURL, token, explicitProjectID)
	if err != nil {
		return dashboardConnectResult{}, err
	}
	if err := saveSessionBackedDashboardUploadConfig(normalizedBaseURL, projectID); err != nil {
		return dashboardConnectResult{}, err
	}
	return dashboardConnectResult{
		APIBaseURL: normalizedBaseURL,
		ProjectID:  projectID,
	}, nil
}

func activateDashboardUploadForSession(baseURL, accessToken string) error {
	_, err := connectDashboardUploadWithBearerToken(baseURL, accessToken, "")
	return err
}

func saveSessionBackedDashboardUploadConfig(baseURL, projectID string) error {
	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		return err
	}
	cfg.Dashboard.Upload = dashboardUploadConfig{
		Prompted:   true,
		Enabled:    true,
		APIBaseURL: strings.TrimSpace(baseURL),
		ProjectID:  strings.TrimSpace(projectID),
		APIKeyRef:  "",
	}
	return saveBaselineLocalConfig(cfg)
}

func runDashboardLogoutCommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	if len(args) > 0 && hasHelpFlag(args) {
		printDashboardLogoutUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard logout help shown"}
	}
	if len(args) > 0 {
		fmt.Printf("DASHBOARD LOGOUT FAILED: unknown flag %s\n\n", args[0])
		printDashboardLogoutUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard logout arguments invalid"}
	}
	session := loadStoredDashboardCLISession()
	if strings.TrimSpace(session.APIBaseURL) == "" {
		fmt.Println("No stored CLI dashboard session.")
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "not_signed_in", TraceMessage: "no stored CLI dashboard session"}
	}
	revokeSpan := traceCtx.HelperEnter("cli", "revokeCLISession", "revoking CLI dashboard session", nil)
	_ = revokeCLISession(session)
	traceCtx.HelperExit(revokeSpan, "cli", "revokeCLISession", "ok", "CLI dashboard session revoked", nil)
	clearSpan := traceCtx.HelperEnter("cli", "clearStoredDashboardCLISession", "clearing stored CLI dashboard session", nil)
	if err := clearStoredDashboardCLISession(); err != nil {
		traceCtx.Error("cli", "clearStoredDashboardCLISession", err, nil)
		traceCtx.HelperExit(clearSpan, "cli", "clearStoredDashboardCLISession", "error", "stored CLI dashboard session clear failed", nil)
		fmt.Printf("DASHBOARD LOGOUT FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "stored CLI dashboard session clear failed"}
	}
	traceCtx.HelperExit(clearSpan, "cli", "clearStoredDashboardCLISession", "ok", "stored CLI dashboard session cleared", nil)
	fmt.Println("CLI dashboard session removed.")
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "logged_out", TraceMessage: "CLI dashboard session removed"}
}

func runDashboardWhoAmICommand(traceCtx *clitrace.Context, args []string) tracedCommandResult {
	if len(args) > 0 && hasHelpFlag(args) {
		printDashboardWhoAmIUsage()
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "help", TraceMessage: "dashboard whoami help shown"}
	}
	if len(args) > 0 {
		fmt.Printf("DASHBOARD WHOAMI FAILED: unknown flag %s\n\n", args[0])
		printDashboardWhoAmIUsage()
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "dashboard whoami arguments invalid"}
	}
	session, err := refreshedStoredDashboardCLISession("")
	if err != nil {
		fmt.Printf("DASHBOARD WHOAMI FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "CLI dashboard session refresh failed"}
	}
	if strings.TrimSpace(session.APIBaseURL) == "" || strings.TrimSpace(session.AccessToken) == "" {
		fmt.Println("No stored CLI dashboard session.")
		return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "not_signed_in", TraceMessage: "no stored CLI dashboard session"}
	}
	payload, err := fetchCLISessionIdentity(session)
	if err != nil {
		fmt.Printf("DASHBOARD WHOAMI FAILED: %v\n", err)
		return tracedCommandResult{ExitCode: types.ExitSystemError, TraceStatus: "system_error", TraceMessage: "CLI dashboard whoami failed"}
	}
	fmt.Printf("User: %s\n", stringOrFallback(payload.User, "(unknown)"))
	fmt.Printf("Role: %s\n", stringOrFallback(payload.Role, "(unknown)"))
	fmt.Printf("Email: %s\n", stringOrFallback(payload.Email, "(unknown)"))
	fmt.Printf("API: %s\n", session.APIBaseURL)
	return tracedCommandResult{ExitCode: types.ExitSuccess, TraceStatus: "ok", TraceMessage: "CLI dashboard identity resolved"}
}

type cliSessionLoginStart struct {
	DeviceCode              string    `json:"device_code"`
	UserCode                string    `json:"user_code"`
	VerificationURL         string    `json:"verification_url"`
	CompleteVerificationURL string    `json:"complete_verification_url"`
	ExpiresAt               time.Time `json:"expires_at"`
	IntervalSeconds         int       `json:"interval_seconds"`
	APIBaseURL              string    `json:"-"`
}

type cliSessionTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         string `json:"user"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	ClientName   string `json:"client_name"`
	ClientHost   string `json:"client_host"`
}

type authMePayload struct {
	User  string `json:"user"`
	Role  string `json:"role"`
	Email string `json:"email"`
}

func startCLISessionLogin(baseURL string) (cliSessionLoginStart, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name": defaultCLIClientName(),
		"client_host": defaultCLIClientHost(),
	})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/cli/session/start", bytes.NewReader(body))
	if err != nil {
		return cliSessionLoginStart{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return cliSessionLoginStart{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return cliSessionLoginStart{}, fmt.Errorf("dashboard login start rejected with status %d", resp.StatusCode)
	}
	var started cliSessionLoginStart
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		return cliSessionLoginStart{}, err
	}
	started.APIBaseURL = strings.TrimRight(baseURL, "/")
	started.CompleteVerificationURL = started.APIBaseURL + "/dashboard?approve_cli_login=1&user_code=" + url.QueryEscape(started.UserCode)
	if started.IntervalSeconds <= 0 {
		started.IntervalSeconds = 2
	}
	return started, nil
}

func pollCLISessionLogin(started cliSessionLoginStart) (baselineDashboardCLISession, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := started.ExpiresAt
	if deadline.IsZero() {
		deadline = time.Now().Add(2 * time.Minute)
	}
	for time.Now().Before(deadline) {
		body, _ := json.Marshal(map[string]any{"device_code": started.DeviceCode})
		req, err := http.NewRequest(http.MethodPost, started.APIBaseURL+"/v1/cli/session/poll", bytes.NewReader(body))
		if err != nil {
			return baselineDashboardCLISession{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return baselineDashboardCLISession{}, err
		}
		if resp.StatusCode == http.StatusAccepted {
			resp.Body.Close()
			time.Sleep(time.Duration(started.IntervalSeconds) * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return baselineDashboardCLISession{}, fmt.Errorf("dashboard login poll rejected with status %d", resp.StatusCode)
		}
		var tokenPayload cliSessionTokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenPayload); err != nil {
			resp.Body.Close()
			return baselineDashboardCLISession{}, err
		}
		resp.Body.Close()
		return baselineDashboardCLISession{
			APIBaseURL:   started.APIBaseURL,
			AccessToken:  tokenPayload.AccessToken,
			RefreshToken: tokenPayload.RefreshToken,
			User:         tokenPayload.User,
			Email:        tokenPayload.Email,
			Role:         tokenPayload.Role,
		}, nil
	}
	return baselineDashboardCLISession{}, errors.New("dashboard login request expired before approval")
}

func refreshedStoredDashboardCLISession(baseURL string) (baselineDashboardCLISession, error) {
	session := loadStoredDashboardCLISession()
	if strings.TrimSpace(session.APIBaseURL) == "" || strings.TrimSpace(session.RefreshToken) == "" {
		return session, nil
	}
	if strings.TrimSpace(baseURL) != "" && strings.TrimRight(strings.TrimSpace(baseURL), "/") != strings.TrimRight(strings.TrimSpace(session.APIBaseURL), "/") {
		return baselineDashboardCLISession{}, nil
	}
	body, _ := json.Marshal(map[string]any{"refresh_token": session.RefreshToken})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(session.APIBaseURL, "/")+"/v1/cli/session/refresh", bytes.NewReader(body))
	if err != nil {
		return baselineDashboardCLISession{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return baselineDashboardCLISession{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		_ = clearStoredDashboardCLISession()
		return baselineDashboardCLISession{}, errors.New("stored CLI dashboard session expired; run `baseline dashboard login` again")
	}
	if resp.StatusCode != http.StatusOK {
		return session, nil
	}
	var rotated cliSessionTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		return baselineDashboardCLISession{}, err
	}
	session.AccessToken = rotated.AccessToken
	session.RefreshToken = rotated.RefreshToken
	if strings.TrimSpace(rotated.User) != "" {
		session.User = rotated.User
	}
	if strings.TrimSpace(rotated.Email) != "" {
		session.Email = rotated.Email
	}
	if strings.TrimSpace(rotated.Role) != "" {
		session.Role = rotated.Role
	}
	if err := saveStoredDashboardCLISession(session); err != nil {
		return baselineDashboardCLISession{}, err
	}
	return session, nil
}

func revokeCLISession(session baselineDashboardCLISession) error {
	baseURL := strings.TrimRight(strings.TrimSpace(session.APIBaseURL), "/")
	if baseURL == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if token := strings.TrimSpace(session.AccessToken); token != "" {
		req, err := http.NewRequest(http.MethodDelete, baseURL+"/v1/cli/session", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
					return nil
				}
			}
		}
	}
	if token := strings.TrimSpace(session.RefreshToken); token != "" {
		body, _ := json.Marshal(map[string]any{"refresh_token": token})
		req, err := http.NewRequest(http.MethodDelete, baseURL+"/v1/cli/session", bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
					return nil
				}
			}
		}
	}
	return nil
}

func fetchCLISessionIdentity(session baselineDashboardCLISession) (authMePayload, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(session.APIBaseURL, "/")+"/v1/auth/me", nil)
	if err != nil {
		return authMePayload{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(session.AccessToken))
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return authMePayload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authMePayload{}, fmt.Errorf("whoami rejected with status %d", resp.StatusCode)
	}
	var payload authMePayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return authMePayload{}, err
	}
	return payload, nil
}

func defaultDashboardLoginBaseURL() string {
	session := loadStoredDashboardCLISession()
	if strings.TrimSpace(session.APIBaseURL) != "" {
		return strings.TrimSpace(session.APIBaseURL)
	}
	if baseURL := defaultScanUploadBaseURL(); strings.TrimSpace(baseURL) != "" {
		return baseURL
	}
	if baseURL := strings.TrimSpace(os.Getenv("BASELINE_DASHBOARD_API_URL")); baseURL != "" {
		return baseURL
	}
	if baseURL := strings.TrimSpace(os.Getenv("BASELINE_API_ADDR")); baseURL != "" {
		return apiURLFromAPIAddr(baseURL)
	}
	return defaultHostedDashboardAPIURL
}

func defaultCLIClientName() string {
	host := defaultCLIClientHost()
	if host == "" {
		return "Baseline CLI"
	}
	return "Baseline CLI on " + host
}

func defaultCLIClientHost() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(host)
}

func openBrowserURL(target string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	case "darwin":
		return exec.Command("open", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

func printDashboardLoginUsage() {
	fmt.Println("Usage: baseline dashboard login [--api <url>] [--no-open]")
}

func printDashboardLogoutUsage() {
	fmt.Println("Usage: baseline dashboard logout")
}

func printDashboardWhoAmIUsage() {
	fmt.Println("Usage: baseline dashboard whoami")
}

func stringOrFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
