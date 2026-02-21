package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Handler returns the API HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		requestID := s.requestID(r)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey, requestID))

		writer := &statusCapturingResponseWriter{ResponseWriter: w}
		writer.Header().Set(requestIDHeader, requestID)

		s.applySecurityHeaders(writer, r)
		if s.handleCORS(writer, r) {
			s.logRequest(r, writer.status(), writer.bytes, startedAt)
			return
		}
		if s.config.RequireHTTPS && !s.isRequestSecure(r) {
			writeError(writer, http.StatusForbidden, "https_required", "HTTPS is required")
			s.logRequest(r, writer.status(), writer.bytes, startedAt)
			return
		}
		if !s.allowRequestByRateLimit(writer, r) {
			s.logRequest(r, writer.status(), writer.bytes, startedAt)
			return
		}
		s.route(writer, r)
		s.logRequest(r, writer.status(), writer.bytes, startedAt)
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
	case "/metrics":
		s.handleMetrics(w, r)
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

	ready, checks := s.readinessChecks(r.Context())
	statusCode := http.StatusOK
	status := "ready"
	if !ready {
		statusCode = http.StatusServiceUnavailable
		status = "not_ready"
	}
	writeJSON(w, statusCode, map[string]any{
		"status": status,
		"checks": checks,
	})
}

type readinessCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (s *Server) readinessChecks(parent context.Context) (bool, map[string]readinessCheck) {
	checks := map[string]readinessCheck{}
	ready := true

	dbStatus := readinessCheck{
		Status: "ready",
		Detail: "in_memory_mode",
	}
	if s.store != nil {
		ctx, cancel := context.WithTimeout(parent, 500*time.Millisecond)
		err := s.store.Ping(ctx)
		cancel()
		if err != nil {
			dbStatus.Status = "not_ready"
			dbStatus.Detail = "unreachable"
			ready = false
		} else {
			dbStatus.Detail = "ok"
		}
	}
	checks["database"] = dbStatus

	workerStatus := readinessCheck{
		Status: "ready",
		Detail: "disabled_no_store",
	}
	if s.store != nil {
		s.workerMu.Lock()
		running := s.workerCancel != nil && s.workerDone != nil
		s.workerMu.Unlock()
		if running {
			workerStatus.Detail = "running"
		} else {
			workerStatus.Status = "not_ready"
			workerStatus.Detail = "not_running"
			ready = false
		}
	}
	checks["integration_worker"] = workerStatus

	return ready, checks
}
