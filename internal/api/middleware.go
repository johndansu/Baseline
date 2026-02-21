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
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, X-Baseline-CSRF")
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

func (s *Server) applySecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if isDashboardPath(r.URL.Path) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	}
	if s.isRequestSecure(r) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}
