package api

import (
	"testing"
	"time"
)

func TestConfigFromEnvSecurityToggles(t *testing.T) {
	t.Setenv("BASELINE_API_REQUIRE_HTTPS", "true")
	t.Setenv("BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE", "true")
	t.Setenv("BASELINE_API_GITHUB_WEBHOOK_SECRET", "gh-secret")
	t.Setenv("BASELINE_API_GITLAB_WEBHOOK_TOKEN", "gl-token")
	t.Setenv("BASELINE_API_GITHUB_TOKEN", "gh-api-token")
	t.Setenv("BASELINE_API_GITHUB_API_URL", "https://gh.example.test")
	t.Setenv("BASELINE_API_GITLAB_TOKEN", "gl-api-token")
	t.Setenv("BASELINE_API_GITLAB_API_URL", "https://gl.example.test")
	t.Setenv("BASELINE_API_RATE_LIMIT_ENABLED", "true")
	t.Setenv("BASELINE_API_RATE_LIMIT_REQUESTS", "200")
	t.Setenv("BASELINE_API_RATE_LIMIT_WINDOW_SECONDS", "120")
	t.Setenv("BASELINE_API_AUTH_RATE_LIMIT_REQUESTS", "40")
	t.Setenv("BASELINE_API_AUTH_RATE_LIMIT_WINDOW_SECONDS", "90")
	t.Setenv("BASELINE_API_UNAUTH_RATE_LIMIT_REQUESTS", "12")
	t.Setenv("BASELINE_API_UNAUTH_RATE_LIMIT_WINDOW_SECONDS", "45")
	t.Setenv("BASELINE_API_KEY_HASH_SECRET", "test-hash-secret-value")

	cfg := ConfigFromEnv()
	if !cfg.RequireHTTPS {
		t.Fatal("expected BASELINE_API_REQUIRE_HTTPS=true to enable RequireHTTPS")
	}
	if !cfg.DashboardSessionCookieSecure {
		t.Fatal("expected BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE=true to enable secure session cookie flag")
	}
	if cfg.GitHubWebhookSecret != "gh-secret" {
		t.Fatalf("expected github webhook secret to load, got %q", cfg.GitHubWebhookSecret)
	}
	if cfg.GitLabWebhookToken != "gl-token" {
		t.Fatalf("expected gitlab webhook token to load, got %q", cfg.GitLabWebhookToken)
	}
	if cfg.GitHubAPIToken != "gh-api-token" {
		t.Fatalf("expected github api token to load, got %q", cfg.GitHubAPIToken)
	}
	if cfg.GitHubAPIBaseURL != "https://gh.example.test" {
		t.Fatalf("expected github api url to load, got %q", cfg.GitHubAPIBaseURL)
	}
	if cfg.GitLabAPIToken != "gl-api-token" {
		t.Fatalf("expected gitlab api token to load, got %q", cfg.GitLabAPIToken)
	}
	if cfg.GitLabAPIBaseURL != "https://gl.example.test" {
		t.Fatalf("expected gitlab api url to load, got %q", cfg.GitLabAPIBaseURL)
	}
	if !cfg.RateLimitEnabled {
		t.Fatal("expected BASELINE_API_RATE_LIMIT_ENABLED=true to enable rate limiting")
	}
	if cfg.RateLimitRequests != 200 {
		t.Fatalf("expected rate limit requests to load, got %d", cfg.RateLimitRequests)
	}
	if cfg.RateLimitWindow != 120*time.Second {
		t.Fatalf("expected rate limit window to load, got %s", cfg.RateLimitWindow)
	}
	if cfg.AuthRateLimitRequests != 40 {
		t.Fatalf("expected auth rate limit requests to load, got %d", cfg.AuthRateLimitRequests)
	}
	if cfg.AuthRateLimitWindow != 90*time.Second {
		t.Fatalf("expected auth rate limit window to load, got %s", cfg.AuthRateLimitWindow)
	}
	if cfg.UnauthRateLimitRequests != 12 {
		t.Fatalf("expected unauth rate limit requests to load, got %d", cfg.UnauthRateLimitRequests)
	}
	if cfg.UnauthRateLimitWindow != 45*time.Second {
		t.Fatalf("expected unauth rate limit window to load, got %s", cfg.UnauthRateLimitWindow)
	}
	if cfg.APIKeyHashSecret != "test-hash-secret-value" {
		t.Fatalf("expected api key hash secret to load, got %q", cfg.APIKeyHashSecret)
	}
}
