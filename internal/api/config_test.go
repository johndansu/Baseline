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
	t.Setenv("BASELINE_API_SENSITIVE_ACTION_REAUTH_ENABLED", "true")
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
	if !cfg.SensitiveActionReauthEnabled {
		t.Fatal("expected sensitive-action reauth toggle to load from environment")
	}
	if cfg.APIKeyHashSecret != "test-hash-secret-value" {
		t.Fatalf("expected api key hash secret to load, got %q", cfg.APIKeyHashSecret)
	}
}

func TestConfigFromEnvAuth0Aliases(t *testing.T) {
	t.Setenv("BASELINE_API_AUTH0_ENABLED", "true")
	t.Setenv("BASELINE_API_AUTH0_DOMAIN", "acme.us.auth0.com")
	t.Setenv("BASELINE_API_AUTH0_CLIENT_ID", "auth0-client")
	t.Setenv("BASELINE_API_AUTH0_CLIENT_SECRET", "auth0-secret")
	t.Setenv("BASELINE_API_AUTH0_CALLBACK_URL", "https://api.example.com/v1/auth/oidc/callback")
	t.Setenv("BASELINE_API_AUTH0_DEFAULT_ROLE", "operator")
	t.Setenv("BASELINE_API_AUTH0_ALLOWED_EMAIL_DOMAINS", "example.com,acme.com")

	cfg := ConfigFromEnv()
	if !cfg.OIDCEnabled {
		t.Fatal("expected Auth0 alias to enable OIDC")
	}
	if cfg.OIDCIssuerURL != "https://acme.us.auth0.com" {
		t.Fatalf("expected normalized Auth0 issuer URL, got %q", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCClientID != "auth0-client" || cfg.OIDCClientSecret != "auth0-secret" {
		t.Fatalf("expected Auth0 client credentials to map to OIDC fields")
	}
	if cfg.OIDCRedirectURL != "https://api.example.com/v1/auth/oidc/callback" {
		t.Fatalf("expected Auth0 callback alias to map to OIDC redirect URL, got %q", cfg.OIDCRedirectURL)
	}
	if cfg.OIDCDefaultRole != RoleOperator {
		t.Fatalf("expected default role from Auth0 alias to be operator, got %q", cfg.OIDCDefaultRole)
	}
	if len(cfg.OIDCAllowedEmailDomains) != 2 {
		t.Fatalf("expected allowed email domains from Auth0 alias, got %#v", cfg.OIDCAllowedEmailDomains)
	}
}

func TestConfigFromEnvSupabaseAliases(t *testing.T) {
	t.Setenv("BASELINE_API_SUPABASE_ENABLED", "true")
	t.Setenv("BASELINE_API_SUPABASE_URL", "https://xyzcompany.supabase.co")
	t.Setenv("BASELINE_API_SUPABASE_CLIENT_ID", "supabase-client")
	t.Setenv("BASELINE_API_SUPABASE_CLIENT_SECRET", "supabase-secret")
	t.Setenv("BASELINE_API_SUPABASE_CALLBACK_URL", "https://api.example.com/v1/auth/oidc/callback")
	t.Setenv("BASELINE_API_SUPABASE_DEFAULT_ROLE", "viewer")
	t.Setenv("BASELINE_API_SUPABASE_ALLOWED_EMAIL_DOMAINS", "example.com,acme.com")

	cfg := ConfigFromEnv()
	if !cfg.OIDCEnabled {
		t.Fatal("expected Supabase alias to enable OIDC")
	}
	if cfg.OIDCIssuerURL != "https://xyzcompany.supabase.co/auth/v1" {
		t.Fatalf("expected normalized Supabase issuer URL, got %q", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCClientID != "supabase-client" || cfg.OIDCClientSecret != "supabase-secret" {
		t.Fatalf("expected Supabase client credentials to map to OIDC fields")
	}
	if cfg.OIDCRedirectURL != "https://api.example.com/v1/auth/oidc/callback" {
		t.Fatalf("expected Supabase callback alias to map to OIDC redirect URL, got %q", cfg.OIDCRedirectURL)
	}
	if cfg.OIDCDefaultRole != RoleViewer {
		t.Fatalf("expected default role from Supabase alias to be viewer, got %q", cfg.OIDCDefaultRole)
	}
	if len(cfg.OIDCAllowedEmailDomains) != 2 {
		t.Fatalf("expected allowed email domains from Supabase alias, got %#v", cfg.OIDCAllowedEmailDomains)
	}
}
