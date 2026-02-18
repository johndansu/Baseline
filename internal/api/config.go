package api

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config stores API runtime configuration.
type Config struct {
	Addr                         string
	DBPath                       string
	APIKeys                      map[string]Role
	RequireHTTPS                 bool
	SelfServiceEnabled           bool
	EnrollmentTokens             map[string]Role
	EnrollmentTokenTTL           time.Duration
	EnrollmentMaxUses            int
	ReadTimeout                  time.Duration
	WriteTimeout                 time.Duration
	IdleTimeout                  time.Duration
	MaxBodyBytes                 int64
	ShutdownTimeout              time.Duration
	CORSAllowedOrigins           []string
	TrustProxyHeaders            bool
	DashboardSessionEnabled      bool
	DashboardSessionRole         Role
	DashboardSessionTTL          time.Duration
	DashboardSessionCookieSecure bool
	DashboardAuthProxyEnabled    bool
	DashboardAuthProxyUserHeader string
	DashboardAuthProxyRoleHeader string
	GitHubWebhookSecret          string
	GitLabWebhookToken           string
	GitHubAPIToken               string
	GitHubAPIBaseURL             string
	GitLabAPIToken               string
	GitLabAPIBaseURL             string
	AIEnabled                    bool
}

// DefaultConfig returns safe defaults for local development.
func DefaultConfig() Config {
	return Config{
		Addr:                         ":8080",
		DBPath:                       "baseline_api.db",
		APIKeys:                      map[string]Role{},
		RequireHTTPS:                 false,
		SelfServiceEnabled:           false,
		EnrollmentTokens:             map[string]Role{},
		EnrollmentTokenTTL:           24 * time.Hour,
		EnrollmentMaxUses:            1,
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 5 * time.Second,
		IdleTimeout:                  30 * time.Second,
		MaxBodyBytes:                 1 << 20,
		ShutdownTimeout:              10 * time.Second,
		CORSAllowedOrigins:           []string{},
		TrustProxyHeaders:            false,
		DashboardSessionEnabled:      false,
		DashboardSessionRole:         RoleViewer,
		DashboardSessionTTL:          12 * time.Hour,
		DashboardSessionCookieSecure: false,
		DashboardAuthProxyEnabled:    false,
		DashboardAuthProxyUserHeader: "X-Forwarded-User",
		DashboardAuthProxyRoleHeader: "X-Forwarded-Role",
		GitHubWebhookSecret:          "",
		GitLabWebhookToken:           "",
		GitHubAPIToken:               "",
		GitHubAPIBaseURL:             "https://api.github.com",
		GitLabAPIToken:               "",
		GitLabAPIBaseURL:             "https://gitlab.com/api/v4",
		AIEnabled:                    false,
	}
}

// ConfigFromEnv loads API settings from environment variables.
func ConfigFromEnv() Config {
	cfg := DefaultConfig()

	if v := strings.TrimSpace(os.Getenv("BASELINE_API_ADDR")); v != "" {
		cfg.Addr = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DB_PATH")); v != "" {
		cfg.DBPath = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_KEY")); v != "" {
		cfg.APIKeys[v] = RoleAdmin
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_KEYS")); v != "" {
		cfg.APIKeys = mergeRoleMaps(cfg.APIKeys, parseRolePairs(v, RoleViewer))
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_REQUIRE_HTTPS")); v != "" {
		cfg.RequireHTTPS = parseBool(v, cfg.RequireHTTPS)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_SELF_SERVICE_ENABLED")); v != "" {
		cfg.SelfServiceEnabled = parseBool(v, cfg.SelfServiceEnabled)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_ENROLLMENT_TOKENS")); v != "" {
		cfg.EnrollmentTokens = parseRolePairs(v, RoleViewer)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_ENROLLMENT_TOKEN_TTL_MINUTES")); v != "" {
		if minutes, ok := parseInt(v); ok && minutes > 0 {
			cfg.EnrollmentTokenTTL = time.Duration(minutes) * time.Minute
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_ENROLLMENT_TOKEN_MAX_USES")); v != "" {
		if uses, ok := parseInt(v); ok && uses > 0 {
			cfg.EnrollmentMaxUses = uses
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_TIMEOUT_MS")); v != "" {
		if ms, ok := parseInt(v); ok && ms > 0 {
			timeout := time.Duration(ms) * time.Millisecond
			cfg.ReadTimeout = timeout
			cfg.WriteTimeout = timeout
			if cfg.IdleTimeout < timeout {
				cfg.IdleTimeout = timeout
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_IDLE_TIMEOUT_MS")); v != "" {
		if ms, ok := parseInt(v); ok && ms > 0 {
			cfg.IdleTimeout = time.Duration(ms) * time.Millisecond
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_MAX_BODY_BYTES")); v != "" {
		if maxBytes, ok := parseInt64(v); ok && maxBytes > 0 {
			cfg.MaxBodyBytes = maxBytes
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_SHUTDOWN_TIMEOUT_MS")); v != "" {
		if ms, ok := parseInt(v); ok && ms > 0 {
			cfg.ShutdownTimeout = time.Duration(ms) * time.Millisecond
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_CORS_ALLOWED_ORIGINS")); v != "" {
		cfg.CORSAllowedOrigins = parseCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_TRUST_PROXY_HEADERS")); v != "" {
		cfg.TrustProxyHeaders = parseBool(v, cfg.TrustProxyHeaders)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_SESSION_ENABLED")); v != "" {
		cfg.DashboardSessionEnabled = parseBool(v, cfg.DashboardSessionEnabled)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_SESSION_ROLE")); v != "" {
		role := Role(strings.ToLower(v))
		if isValidRole(role) {
			cfg.DashboardSessionRole = role
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_SESSION_TTL_MINUTES")); v != "" {
		if minutes, ok := parseInt(v); ok && minutes > 0 {
			cfg.DashboardSessionTTL = time.Duration(minutes) * time.Minute
		}
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE")); v != "" {
		cfg.DashboardSessionCookieSecure = parseBool(v, cfg.DashboardSessionCookieSecure)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_AUTH_PROXY_ENABLED")); v != "" {
		cfg.DashboardAuthProxyEnabled = parseBool(v, cfg.DashboardAuthProxyEnabled)
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER")); v != "" {
		cfg.DashboardAuthProxyUserHeader = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_DASHBOARD_AUTH_PROXY_ROLE_HEADER")); v != "" {
		cfg.DashboardAuthProxyRoleHeader = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITHUB_WEBHOOK_SECRET")); v != "" {
		cfg.GitHubWebhookSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITLAB_WEBHOOK_TOKEN")); v != "" {
		cfg.GitLabWebhookToken = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITHUB_TOKEN")); v != "" {
		cfg.GitHubAPIToken = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITHUB_API_URL")); v != "" {
		cfg.GitHubAPIBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITLAB_TOKEN")); v != "" {
		cfg.GitLabAPIToken = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_GITLAB_API_URL")); v != "" {
		cfg.GitLabAPIBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("BASELINE_API_AI_ENABLED")); v != "" {
		cfg.AIEnabled = parseBool(v, cfg.AIEnabled)
	}

	return cfg
}

func parseRolePairs(raw string, fallback Role) map[string]Role {
	out := map[string]Role{}
	for _, token := range parseCSV(raw) {
		parts := strings.SplitN(token, ":", 2)
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		role := fallback
		if len(parts) == 2 {
			candidate := Role(strings.ToLower(strings.TrimSpace(parts[1])))
			if isValidRole(candidate) {
				role = candidate
			}
		}
		out[key] = role
	}
	return out
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func mergeRoleMaps(dst map[string]Role, src map[string]Role) map[string]Role {
	if dst == nil {
		dst = map[string]Role{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func parseBool(raw string, fallback bool) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func parseInt(raw string) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	return value, true
}

func parseInt64(raw string) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
