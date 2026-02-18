package api

import "testing"

func TestConfigFromEnvSecurityToggles(t *testing.T) {
	t.Setenv("BASELINE_API_REQUIRE_HTTPS", "true")
	t.Setenv("BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE", "true")
	t.Setenv("BASELINE_API_GITHUB_WEBHOOK_SECRET", "gh-secret")
	t.Setenv("BASELINE_API_GITLAB_WEBHOOK_TOKEN", "gl-token")

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
}
