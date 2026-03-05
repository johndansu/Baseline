package api

import (
	"errors"
	"net/http"
	"strings"
)

type authPrincipal struct {
	Role       Role
	AuthSource string
	OwnerID    string
}

func (s *Server) requestPrincipal(r *http.Request) (authPrincipal, error) {
	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		return authPrincipal{}, err
	}
	principal := authPrincipal{
		Role:       role,
		AuthSource: authSource,
	}

	switch authSource {
	case "session":
		session, err := s.getDashboardSession(r)
		if err != nil {
			return authPrincipal{}, errors.New("missing or invalid credentials")
		}
		principal.OwnerID = sessionOwnerID(session)
	case "api_key":
		principal.OwnerID = s.apiKeyOwnerIDFromRequest(r)
	}
	return principal, nil
}

func (p authPrincipal) enforceOwnership() bool {
	if p.Role == RoleAdmin {
		return false
	}
	return p.AuthSource == "session" || p.AuthSource == "api_key"
}

func (p authPrincipal) canAccessOwner(ownerID string) bool {
	if !p.enforceOwnership() {
		return true
	}
	return strings.TrimSpace(ownerID) != "" && strings.TrimSpace(ownerID) == strings.TrimSpace(p.OwnerID)
}

func sessionOwnerID(session dashboardSession) string {
	if v := strings.TrimSpace(session.UserID); v != "" {
		return "user:" + strings.ToLower(v)
	}
	if v := strings.TrimSpace(session.Subject); v != "" {
		return "sub:" + strings.ToLower(v)
	}
	if v := strings.TrimSpace(session.Email); v != "" {
		return "email:" + strings.ToLower(v)
	}
	if v := strings.TrimSpace(session.User); v != "" {
		return "user:" + strings.ToLower(v)
	}
	return "session:unknown"
}

func (s *Server) apiKeyOwnerIDFromRequest(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return ""
	}
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return ""
	}

	s.authMu.RLock()
	defer s.authMu.RUnlock()
	if keyID, ok := s.findKeyIDByTokenLocked(token); ok {
		return "api_key:" + keyID
	}
	return ""
}
