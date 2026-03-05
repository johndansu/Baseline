package api

import (
	"strings"
	"testing"
)

func TestNewServerRejectsWildcardCORSInProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"prod_admin_key_123": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"*"}

	_, err := NewServer(cfg, nil)
	if err == nil {
		t.Fatal("expected startup validation error for wildcard CORS in production")
	}
	if !strings.Contains(err.Error(), "CORS wildcard '*' is not allowed for production startup") {
		t.Fatalf("expected wildcard CORS startup error, got: %v", err)
	}
}

func TestNewServerRejectsPlaceholderSecretsInProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"replace-with-real-key": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.example.org"}

	_, err := NewServer(cfg, nil)
	if err == nil {
		t.Fatal("expected startup validation error for placeholder API key in production")
	}
	if !strings.Contains(err.Error(), "API key configuration contains placeholder-like values") {
		t.Fatalf("expected placeholder API key startup error, got: %v", err)
	}
}

func TestNewServerRejectsNonHTTPSCORSOriginsWhenHTTPSRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"prod_admin_key_123": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"http://dashboard.example.org"}

	_, err := NewServer(cfg, nil)
	if err == nil {
		t.Fatal("expected startup validation error for non-HTTPS CORS origin in production")
	}
	if !strings.Contains(err.Error(), "CORS origins must use HTTPS when BASELINE_API_REQUIRE_HTTPS=true") {
		t.Fatalf("expected non-HTTPS CORS startup error, got: %v", err)
	}
}

func TestNewServerRejectsPlaceholderHashSecretInProduction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"prod_admin_key_123": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.example.org"}
	cfg.APIKeyHashSecret = "<replace-with-random-secret>"

	_, err := NewServer(cfg, nil)
	if err == nil {
		t.Fatal("expected startup validation error for placeholder API key hash secret in production")
	}
	if !strings.Contains(err.Error(), "API key hash secret looks like a placeholder value") {
		t.Fatalf("expected placeholder hash secret startup error, got: %v", err)
	}
}

func TestNewServerAllowsDevStartupWithWildcardAndPlaceholder(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = ":8080"
	cfg.RequireHTTPS = false
	cfg.APIKeys = map[string]Role{
		"replace-with-real-key": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"*"}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("expected dev startup to allow relaxed config, got error: %v", err)
	}
	if server == nil {
		t.Fatal("expected server instance")
	}
}

func TestNewServerAllowsProductionStartupWithSecureHTTPSCORS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"prod_admin_key_ABC123": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.baseline.security"}
	cfg.APIKeyHashSecret = "baseline-hash-secret-2026-prod"

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("expected startup to pass with secure HTTPS CORS, got error: %v", err)
	}
	if server == nil {
		t.Fatal("expected server instance")
	}
}

func TestNewServerAllowsProductionStartupWithHardenedConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.RequireHTTPS = true
	cfg.APIKeys = map[string]Role{
		"prod_admin_key_ABC123": RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.baseline.security"}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("expected hardened production startup to pass, got error: %v", err)
	}
	if server == nil {
		t.Fatal("expected server instance")
	}
}
