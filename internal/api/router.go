package api

import (
	"net/http"
	"strings"
)

// Handler returns the API HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.applySecurityHeaders(w, r)
		if s.handleCORS(w, r) {
			return
		}
		if s.config.RequireHTTPS && !s.isRequestSecure(r) {
			writeError(w, http.StatusForbidden, "https_required", "HTTPS is required")
			return
		}
		if !s.allowRequestByRateLimit(w, r) {
			return
		}
		s.route(w, r)
	})
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/dashboard", "/dashboard/", "/assets/baseline-logo.png", "/assets/dashboard.css", "/assets/dashboard.js":
		s.handleDashboard(w, r)
		return
	case "/openapi.yaml":
		s.handleOpenAPI(w, r)
		return
	case "/healthz", "/livez":
		s.handleHealth(w, r)
		return
	case "/readyz":
		s.handleReady(w, r)
		return
	}

	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/auth/session"):
		s.handleAuthSession(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/auth/register"):
		s.handleAuthRegister(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/api-keys"):
		s.handleAPIKeys(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/github/webhook"):
		s.handleGitHubWebhook(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/gitlab/webhook"):
		s.handleGitLabWebhook(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/github/check-runs"):
		s.handleGitHubCheckRuns(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/gitlab/statuses"):
		s.handleGitLabStatuses(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/dashboard"):
		s.handleDashboardSummary(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/projects"):
		s.handleProjects(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/scans"):
		s.handleScans(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/policies"):
		s.handlePolicies(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/rulesets"):
		s.handleRulesets(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/audit/events"):
		s.handleAuditEvents(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}
