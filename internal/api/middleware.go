package api

import (
	"net/http"
	"strings"
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
