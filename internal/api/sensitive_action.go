package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

type sensitiveActionGrant struct {
	Principal string
	ExpiresAt time.Time
}

func (s *Server) issueSensitiveActionReauth(principal authPrincipal) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, errors.New("server unavailable")
	}
	token := randomToken(24)
	if strings.TrimSpace(token) == "" {
		return "", time.Time{}, errors.New("unable to create re-auth token")
	}
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	sensitiveKey := s.sensitivePrincipalKey(principal)

	s.sensitiveMu.Lock()
	defer s.sensitiveMu.Unlock()
	s.pruneSensitiveReauthLocked(time.Now().UTC())
	if s.sensitiveReauth == nil {
		s.sensitiveReauth = map[string]sensitiveActionGrant{}
	}
	s.sensitiveReauth[token] = sensitiveActionGrant{
		Principal: sensitiveKey,
		ExpiresAt: expiresAt,
	}
	return token, expiresAt, nil
}

func (s *Server) requireSensitiveActionReauth(w http.ResponseWriter, r *http.Request, principal authPrincipal) bool {
	if !s.sensitiveActionReauthRequired() {
		return true
	}
	token := strings.TrimSpace(r.Header.Get(sensitiveReauthHeaderName))
	if token == "" {
		writeError(w, http.StatusPreconditionRequired, "reauth_required", "missing required sensitive-action re-auth token")
		return false
	}
	key := s.sensitivePrincipalKey(principal)
	now := time.Now().UTC()

	s.sensitiveMu.Lock()
	defer s.sensitiveMu.Unlock()
	s.pruneSensitiveReauthLocked(now)
	grant, ok := s.sensitiveReauth[token]
	if !ok || grant.ExpiresAt.Before(now) || strings.TrimSpace(grant.Principal) != strings.TrimSpace(key) {
		writeError(w, http.StatusPreconditionRequired, "reauth_required", "invalid or expired sensitive-action re-auth token")
		return false
	}
	delete(s.sensitiveReauth, token)
	return true
}

func (s *Server) sensitiveActionReauthRequired() bool {
	if s == nil {
		return false
	}
	if s.config.SensitiveActionReauthEnabled {
		return true
	}
	return shouldEnforceProductionStartupGuards(s.config)
}

func (s *Server) sensitivePrincipalKey(principal authPrincipal) string {
	source := strings.TrimSpace(principal.AuthSource)
	owner := strings.TrimSpace(principal.OwnerID)
	if source == "" {
		source = "unknown"
	}
	if owner == "" {
		return source + ":unknown"
	}
	return source + ":" + strings.ToLower(owner)
}

func (s *Server) pruneSensitiveReauthLocked(now time.Time) {
	if s == nil {
		return
	}
	if now.Sub(s.sensitiveReauthSweep) < 30*time.Second {
		return
	}
	for token, grant := range s.sensitiveReauth {
		if grant.ExpiresAt.IsZero() || now.After(grant.ExpiresAt) {
			delete(s.sensitiveReauth, token)
		}
	}
	s.sensitiveReauthSweep = now
}
