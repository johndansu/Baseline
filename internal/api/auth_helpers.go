package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s *Server) authenticate(r *http.Request) (Role, error) {
	role, _, err := s.authenticateWithSource(r)
	return role, err
}

func (s *Server) authenticateWithSource(r *http.Request) (Role, string, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			s.authMu.RLock()
			if role, ok := s.config.APIKeys[token]; ok {
				s.authMu.RUnlock()
				return role, "api_key", nil
			}
			if keyID, ok := s.findKeyIDByTokenLocked(token); ok {
				if metadata, exists := s.keysByID[keyID]; exists && !metadata.Revoked {
					s.authMu.RUnlock()
					return metadata.Role, "api_key", nil
				}
			}
			s.authMu.RUnlock()
		}
	}
	session, err := s.getDashboardSession(r)
	if err == nil {
		return session.Role, "session", nil
	}
	return "", "", errors.New("missing or invalid credentials")
}

func (s *Server) getDashboardSession(r *http.Request) (dashboardSession, error) {
	if !s.config.DashboardSessionEnabled {
		return dashboardSession{}, errors.New("dashboard sessions disabled")
	}
	cookie, err := r.Cookie(dashboardSessionCookieName)
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return dashboardSession{}, errors.New("missing session cookie")
	}

	token := strings.TrimSpace(cookie.Value)
	s.sessionMu.RLock()
	session, ok := s.sessions[token]
	s.sessionMu.RUnlock()
	if !ok {
		return dashboardSession{}, errors.New("session not found")
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		s.sessionMu.Lock()
		delete(s.sessions, token)
		s.sessionMu.Unlock()
		return dashboardSession{}, errors.New("session expired")
	}
	return session, nil
}

func (s *Server) dashboardAuthMode() string {
	if s.config.DashboardAuthProxyEnabled {
		return "trusted_proxy"
	}
	return "session_cookie"
}

func (s *Server) shouldUseSecureSessionCookie(r *http.Request) bool {
	return s.config.DashboardSessionCookieSecure || s.config.RequireHTTPS || s.isRequestSecure(r)
}

func (s *Server) isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.config.TrustProxyHeaders {
		return false
	}
	forwardedProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if forwardedProto == "" {
		return false
	}
	first := strings.TrimSpace(strings.Split(forwardedProto, ",")[0])
	return strings.EqualFold(first, "https")
}

func (s *Server) validCSRFSentinel(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get(csrfHeaderName)) == csrfHeaderValue
}

func (s *Server) enforceSessionCSRF(w http.ResponseWriter, r *http.Request, authSource string) bool {
	if authSource != "session" {
		return true
	}
	if s.validCSRFSentinel(r) {
		return true
	}
	writeError(w, http.StatusForbidden, "csrf_failed", "missing required CSRF header")
	return false
}

func (s *Server) readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	maxBytes := s.config.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds configured limit")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "unable to read request body")
		}
		return nil, false
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "empty JSON request")
		return nil, false
	}
	return body, true
}

func (s *Server) requestBodyAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength > 0 && s.config.MaxBodyBytes > 0 && r.ContentLength > s.config.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds configured limit")
		return false
	}
	return true
}

func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	maxBytes := s.config.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds configured limit")
		case errors.Is(err, io.EOF):
			writeError(w, http.StatusBadRequest, "bad_request", "empty JSON request")
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		}
		return false
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return false
	}
	return true
}
