package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
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
			if session, _, ok := s.getCLISessionFromBearerToken(token); ok {
				return session.Role, cliSessionAuthSource, nil
			}
		}
	}
	session, err := s.getDashboardSession(r)
	if err == nil {
		return session.Role, "session", nil
	}
	return "", "", errors.New("missing or invalid credentials")
}

func (s *Server) getDashboardSession(r *http.Request) (dashboardSession, error) {
	if !s.config.DashboardSessionEnabled && !s.config.OIDCEnabled {
		if baseURL, publicKey := configuredSupabaseRuntime(); baseURL == "" || publicKey == "" {
			return dashboardSession{}, errors.New("dashboard sessions disabled")
		}
	}
	cookie, err := r.Cookie(dashboardSessionCookieName)
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return dashboardSession{}, errors.New("missing session cookie")
	}

	token := strings.TrimSpace(cookie.Value)
	now := time.Now().UTC()
	s.sessionMu.RLock()
	session, ok := s.sessions[token]
	s.sessionMu.RUnlock()
	if ok {
		if now.After(session.ExpiresAt) {
			s.sessionMu.Lock()
			delete(s.sessions, token)
			s.sessionMu.Unlock()
			if s.store != nil {
				_ = s.store.RevokeAuthSession(token, now)
			}
			return dashboardSession{}, errors.New("session expired")
		}
		session, err = s.syncDashboardSessionState(token, session, now)
		if err != nil {
			return dashboardSession{}, err
		}
		return session, nil
	}

	if s.store != nil {
		persisted, found, err := s.store.LoadAuthSession(token, now)
		if err == nil && found {
			persisted, err = s.syncDashboardSessionState(token, persisted, now)
			if err != nil {
				return dashboardSession{}, err
			}
			s.sessionMu.Lock()
			s.sessions[token] = persisted
			s.sessionMu.Unlock()
			return persisted, nil
		}
	}

	return dashboardSession{}, errors.New("session not found")
}

func (s *Server) syncDashboardSessionState(token string, session dashboardSession, now time.Time) (dashboardSession, error) {
	if s.store == nil {
		return session, nil
	}

	var (
		user  UserRecord
		found bool
		err   error
	)

	if userID := strings.TrimSpace(session.UserID); userID != "" {
		user, found, err = s.store.GetUserByID(userID)
	} else if email := strings.ToLower(strings.TrimSpace(session.Email)); email != "" {
		user, found, err = s.store.GetUserByEmail(email)
		if err == nil && found {
			session.UserID = strings.TrimSpace(user.ID)
		}
	} else {
		return session, nil
	}
	if err != nil {
		return dashboardSession{}, err
	}
	if !found {
		return session, nil
	}
	if user.Status == UserStatusSuspended {
		s.sessionMu.Lock()
		delete(s.sessions, token)
		s.sessionMu.Unlock()
		_ = s.store.RevokeAuthSession(token, now)
		return dashboardSession{}, errors.New("session suspended")
	}

	updated := false
	if isValidRole(user.Role) && user.Role != session.Role {
		session.Role = user.Role
		updated = true
	}
	if displayName := strings.TrimSpace(user.DisplayName); displayName != "" && displayName != session.User {
		session.User = displayName
		updated = true
	}
	if email := strings.ToLower(strings.TrimSpace(user.Email)); email != "" && email != session.Email {
		session.Email = email
		updated = true
	}
	if !updated {
		return session, nil
	}

	if err := s.store.UpsertAuthSession(token, session, now); err != nil {
		return dashboardSession{}, err
	}
	s.sessionMu.Lock()
	s.sessions[token] = session
	s.sessionMu.Unlock()
	return session, nil
}

func (s *Server) dashboardAuthMode() string {
	if s.config.DashboardAuthProxyEnabled {
		return "trusted_proxy"
	}
	return "session_cookie"
}

func (s *Server) getCLISessionFromRequest(r *http.Request) (cliSessionRecord, string, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return cliSessionRecord{}, "", errors.New("missing cli session token")
	}
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return cliSessionRecord{}, "", errors.New("missing cli session token")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return cliSessionRecord{}, "", errors.New("missing cli session token")
	}
	session, rawToken, ok := s.getCLISessionFromBearerToken(token)
	if !ok {
		return cliSessionRecord{}, "", errors.New("missing or invalid credentials")
	}
	return session, rawToken, nil
}

func (s *Server) getCLISessionFromBearerToken(token string) (cliSessionRecord, string, bool) {
	if s == nil || s.store == nil {
		return cliSessionRecord{}, "", false
	}
	session, found, err := s.store.LoadCLISessionByAccessToken(token, time.Now().UTC())
	if err != nil || !found {
		return cliSessionRecord{}, "", false
	}
	session, valid, err := s.syncCLISessionState(session, time.Now().UTC())
	if err != nil || !valid {
		return cliSessionRecord{}, "", false
	}
	return session, token, true
}

func (s *Server) noteCLISessionUsage(r *http.Request, session cliSessionRecord, cliVersion, repository, projectID, command, scanID string) {
	if s == nil || s.store == nil {
		return
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return
	}
	_ = s.store.UpdateCLISessionMetadata(
		session.SessionID,
		s.clientAddressForCLISession(r),
		cliVersion,
		repository,
		projectID,
		command,
		scanID,
		time.Now().UTC(),
	)
}

func (s *Server) clientAddressForCLISession(r *http.Request) string {
	if r == nil {
		return ""
	}
	if s.config.TrustProxyHeaders {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if first != "" {
				return first
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (s *Server) syncCLISessionState(session cliSessionRecord, now time.Time) (cliSessionRecord, bool, error) {
	if s == nil || s.store == nil {
		return session, true, nil
	}

	var (
		user  UserRecord
		found bool
		err   error
	)
	if userID := strings.TrimSpace(session.UserID); userID != "" {
		user, found, err = s.store.GetUserByID(userID)
	} else if email := strings.ToLower(strings.TrimSpace(session.Email)); email != "" {
		user, found, err = s.store.GetUserByEmail(email)
	}
	if err != nil {
		return cliSessionRecord{}, false, err
	}
	if !found {
		return session, true, nil
	}
	if user.Status == UserStatusSuspended {
		return cliSessionRecord{}, false, nil
	}
	if strings.TrimSpace(user.ID) != "" {
		session.UserID = strings.TrimSpace(user.ID)
	}
	if isValidRole(user.Role) {
		session.Role = user.Role
	}
	if displayName := strings.TrimSpace(user.DisplayName); displayName != "" {
		session.UserLabel = displayName
	}
	if email := strings.ToLower(strings.TrimSpace(user.Email)); email != "" {
		session.Email = email
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return session, true, nil
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

func (s *Server) requireSensitiveActionConfirmation(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	receivedAction := strings.ToLower(strings.TrimSpace(r.Header.Get(sensitiveConfirmHeaderName)))
	expectedAction := strings.ToLower(strings.TrimSpace(action))
	if receivedAction == "" || receivedAction != expectedAction {
		writeError(w, http.StatusPreconditionRequired, "confirmation_required", "missing required sensitive-action confirmation")
		return "", false
	}
	reason := strings.TrimSpace(r.Header.Get(sensitiveConfirmReasonHeaderName))
	if reason == "" {
		writeError(w, http.StatusPreconditionRequired, "confirmation_required", "missing required sensitive-action reason")
		return "", false
	}
	if len(reason) > 256 {
		writeError(w, http.StatusBadRequest, "bad_request", "sensitive-action reason must be 256 characters or less")
		return "", false
	}
	return reason, true
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
