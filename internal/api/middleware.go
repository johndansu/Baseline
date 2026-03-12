package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	baselinelog "github.com/baseline/baseline/internal/log"
)

func (s *Server) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	if len(s.config.CORSAllowedOrigins) == 0 {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}

	allowed := false
	for _, candidate := range s.config.CORSAllowedOrigins {
		if candidate == "*" || strings.EqualFold(strings.TrimSpace(candidate), origin) {
			allowed = true
			break
		}
	}
	if !allowed {
		if r.Method == http.MethodOptions && strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != "" {
			writeError(w, http.StatusForbidden, "cors_forbidden", "origin not allowed")
			return true
		}
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, X-Baseline-CSRF, X-Baseline-Confirm, X-Baseline-Reason, X-Baseline-Reauth")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")

	if r.Method == http.MethodOptions && strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != "" {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

type requestContextKey string

const requestIDHeader = "X-Request-ID"
const requestIDContextKey requestContextKey = "request_id"

type statusCapturingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func (w *statusCapturingResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusCapturingResponseWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytes += written
	return written, err
}

func (w *statusCapturingResponseWriter) status() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func (w *statusCapturingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusCapturingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if value, ok := ctx.Value(requestIDContextKey).(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func sanitizeRequestID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 128 {
		return ""
	}
	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_' || ch == '.':
		default:
			return ""
		}
	}
	return trimmed
}

func (s *Server) requestID(r *http.Request) string {
	if r == nil {
		return randomToken(12)
	}
	if value := sanitizeRequestID(r.Header.Get(requestIDHeader)); value != "" {
		return value
	}
	token := randomToken(12)
	if strings.TrimSpace(token) != "" {
		return token
	}
	return time.Now().UTC().Format("20060102150405.000000000")
}

func (s *Server) logRequest(r *http.Request, statusCode, bytes int, start time.Time) {
	requestID := requestIDFromContext(r.Context())
	duration := time.Since(start)
	baselinelog.Info(
		"api_request",
		"request_id", requestID,
		"method", r.Method,
		"path", r.URL.Path,
		"status", statusCode,
		"bytes", bytes,
		"duration_ms", duration.Milliseconds(),
		"remote_addr", strings.TrimSpace(r.RemoteAddr),
		"user_agent", strings.TrimSpace(r.UserAgent()),
	)
}

func (s *Server) logMutationAction(r *http.Request, statusCode int) {
	action := mutationActionForRequest(r.Method, r.URL.Path)
	if action == "" {
		return
	}

	actor := "anonymous"
	role := ""
	authSource := "none"
	if principal, err := s.requestPrincipal(r); err == nil {
		authSource = strings.TrimSpace(principal.AuthSource)
		role = string(principal.Role)
		if ownerID := strings.TrimSpace(principal.OwnerID); ownerID != "" {
			actor = ownerID
		}
	} else if session, err := s.getDashboardSession(r); err == nil {
		authSource = "session"
		role = string(session.Role)
		if ownerID := strings.TrimSpace(sessionOwnerID(session)); ownerID != "" {
			actor = ownerID
		}
	}

	outcome := "success"
	if statusCode >= http.StatusBadRequest {
		outcome = "failure"
	}

	baselinelog.Info(
		"dashboard_mutation",
		"request_id", requestIDFromContext(r.Context()),
		"actor", actor,
		"action", action,
		"outcome", outcome,
		"status", statusCode,
		"method", r.Method,
		"path", r.URL.Path,
		"auth_source", authSource,
		"role", role,
	)
}

func mutationActionForRequest(method, path string) string {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return ""
	}

	switch {
	case method == http.MethodPost && path == "/v1/projects":
		return "projects.create"
	case method == http.MethodPut && strings.HasPrefix(path, "/v1/projects/"):
		return "projects.update"
	case method == http.MethodPost && path == "/v1/scans":
		return "scans.create"
	case method == http.MethodPost && path == "/v1/api-keys":
		return "api_keys.create"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/api-keys/"):
		return "api_keys.revoke"
	case method == http.MethodPost && path == "/v1/me/api-keys":
		return "api_keys.self.create"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/me/api-keys/"):
		return "api_keys.self.revoke"
	case method == http.MethodPatch && strings.HasPrefix(path, "/v1/users/"):
		return "users.update"
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/users/") && strings.Contains(path, "/api-keys"):
		return "users.api_keys.create"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/users/") && strings.Contains(path, "/api-keys/"):
		return "users.api_keys.revoke"
	case method == http.MethodPost && path == "/v1/integrations/github/check-runs":
		return "integrations.github.check_runs.publish"
	case method == http.MethodPost && path == "/v1/integrations/gitlab/statuses":
		return "integrations.gitlab.statuses.publish"
	case method == http.MethodPost && path == "/v1/integrations/secrets":
		return "integrations.secrets.update"
	case method == http.MethodPost && path == "/v1/auth/reauth":
		return "auth.reauth.issue"
	case method == http.MethodPost && path == "/v1/auth/session":
		return "auth.session.create"
	case method == http.MethodDelete && path == "/v1/auth/session":
		return "auth.session.delete"
	case method == http.MethodPost && path == "/v1/auth/register":
		return "auth.register"
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/policies/") && strings.HasSuffix(path, "/versions"):
		return "policies.version.create"
	case method == http.MethodPost && path == "/v1/rulesets":
		return "rulesets.create"
	default:
		return ""
	}
}

func (s *Server) applySecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if isDashboardPath(r.URL.Path) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; connect-src 'self' https://*.supabase.co https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'none'")
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	}
	if s.isRequestSecure(r) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}
