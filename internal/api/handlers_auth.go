package api

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	if !s.config.DashboardSessionEnabled {
		writeError(w, http.StatusForbidden, "session_disabled", "dashboard session auth is disabled")
		return
	}

	switch r.Method {
	case http.MethodPost:
		if !s.requestBodyAllowed(w, r) {
			return
		}
		user := "local_dashboard"
		role := s.config.DashboardSessionRole
		if s.config.DashboardAuthProxyEnabled && s.config.TrustProxyHeaders {
			if v := strings.TrimSpace(r.Header.Get(s.config.DashboardAuthProxyUserHeader)); v != "" {
				user = v
			}
			if v := strings.ToLower(strings.TrimSpace(r.Header.Get(s.config.DashboardAuthProxyRoleHeader))); v != "" {
				candidate := Role(v)
				if isValidRole(candidate) {
					role = candidate
				}
			}
		}

		secureCookie := s.shouldUseSecureSessionCookie(r)
		if secureCookie && !s.isRequestSecure(r) {
			writeError(w, http.StatusForbidden, "https_required", "secure dashboard sessions require HTTPS")
			return
		}
		token := randomToken(32)
		if token == "" {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to create dashboard session")
			return
		}
		s.sessionMu.Lock()
		s.sessions[token] = dashboardSession{
			Role:      role,
			User:      user,
			ExpiresAt: time.Now().UTC().Add(s.config.DashboardSessionTTL),
		}
		s.sessionMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     dashboardSessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   secureCookie,
			Expires:  time.Now().UTC().Add(s.config.DashboardSessionTTL),
		})

		writeJSON(w, http.StatusCreated, map[string]any{
			"user":      user,
			"role":      role,
			"auth_mode": s.dashboardAuthMode(),
			"active":    true,
		})
	case http.MethodGet:
		session, err := s.getDashboardSession(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user":      session.User,
			"role":      session.Role,
			"auth_mode": s.dashboardAuthMode(),
			"active":    true,
		})
	case http.MethodDelete:
		if !s.validCSRFSentinel(r) {
			writeError(w, http.StatusForbidden, "csrf_failed", "missing required CSRF header")
			return
		}
		cookie, _ := r.Cookie(dashboardSessionCookieName)
		if cookie != nil && cookie.Value != "" {
			s.sessionMu.Lock()
			delete(s.sessions, cookie.Value)
			s.sessionMu.Unlock()
		}
		secureCookie := s.shouldUseSecureSessionCookie(r)
		http.SetCookie(w, &http.Cookie{
			Name:     dashboardSessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   secureCookie,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	if !s.config.SelfServiceEnabled {
		writeError(w, http.StatusForbidden, "self_service_disabled", "self-service registration is disabled")
		return
	}
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		APIKey          string `json:"api_key,omitempty"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.EnrollmentToken)
	if token == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "enrollment_token is required")
		return
	}
	role, ok := s.config.EnrollmentTokens[token]
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "invalid enrollment token")
		return
	}
	key, metadata, err := s.issueAPIKey(role, "self-service", "self_service", "enrollment_token")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to generate API key")
		return
	}
	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "api_key_issued",
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        metadata.ID,
		"name":      metadata.Name,
		"role":      role,
		"prefix":    metadata.Prefix,
		"api_key":   key,
		"auth_mode": "api_key",
	})
}
