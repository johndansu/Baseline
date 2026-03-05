package api

import (
	"net"
	"net/url"
	"strings"
)

func productionStartupValidationErrors(cfg Config) []string {
	if !shouldEnforceProductionStartupGuards(cfg) {
		return nil
	}

	errors := []string{}
	if hasWildcardCORS(cfg.CORSAllowedOrigins) {
		errors = append(errors, "CORS wildcard '*' is not allowed for production startup")
	}
	if cfg.RequireHTTPS && hasNonHTTPSCORSOrigin(cfg.CORSAllowedOrigins) {
		errors = append(errors, "CORS origins must use HTTPS when BASELINE_API_REQUIRE_HTTPS=true")
	}
	if hasPlaceholderAPIKeys(cfg.APIKeys) {
		errors = append(errors, "API key configuration contains placeholder-like values")
	}
	if hasPlaceholderEnrollmentTokens(cfg.EnrollmentTokens) {
		errors = append(errors, "Enrollment token configuration contains placeholder-like values")
	}
	if secretLooksPlaceholder(cfg.GitHubWebhookSecret) {
		errors = append(errors, "GitHub webhook secret looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.GitLabWebhookToken) {
		errors = append(errors, "GitLab webhook token looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.GitHubAPIToken) {
		errors = append(errors, "GitHub API token looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.GitLabAPIToken) {
		errors = append(errors, "GitLab API token looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.OIDCClientID) {
		errors = append(errors, "OIDC client ID looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.OIDCClientSecret) {
		errors = append(errors, "OIDC client secret looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.OIDCIssuerURL) {
		errors = append(errors, "OIDC issuer URL looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.OIDCRedirectURL) {
		errors = append(errors, "OIDC redirect URL looks like a placeholder value")
	}
	if secretLooksPlaceholder(cfg.APIKeyHashSecret) {
		errors = append(errors, "API key hash secret looks like a placeholder value")
	}
	return errors
}

func shouldEnforceProductionStartupGuards(cfg Config) bool {
	if cfg.RequireHTTPS {
		return true
	}
	host := hostFromAddr(cfg.Addr)
	if strings.TrimSpace(host) == "" {
		return false
	}
	return !isLoopbackHost(host)
}

func hasWildcardCORS(origins []string) bool {
	for _, origin := range origins {
		if strings.TrimSpace(origin) == "*" {
			return true
		}
	}
	return false
}

func hasNonHTTPSCORSOrigin(origins []string) bool {
	for _, origin := range origins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" || trimmed == "*" {
			continue
		}
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return true
		}
		if !strings.EqualFold(parsed.Scheme, "https") {
			return true
		}
	}
	return false
}

func hasPlaceholderAPIKeys(keys map[string]Role) bool {
	for key := range keys {
		if secretLooksPlaceholder(key) {
			return true
		}
	}
	return false
}

func hasPlaceholderEnrollmentTokens(tokens map[string]Role) bool {
	for token := range tokens {
		if secretLooksPlaceholder(token) {
			return true
		}
	}
	return false
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

func secretLooksPlaceholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return true
	}
	return strings.Contains(v, "replace") ||
		strings.Contains(v, "changeme") ||
		strings.Contains(v, "example") ||
		strings.Contains(v, "your-") ||
		strings.Contains(v, "dummy") ||
		strings.Contains(v, "default") ||
		strings.Contains(v, "test-only") ||
		strings.Contains(v, "placeholder")
}
