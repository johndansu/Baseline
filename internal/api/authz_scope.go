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
	UserID     string
	Subject    string
	Email      string
	KeyID      string
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
		principal.UserID = strings.TrimSpace(session.UserID)
		principal.Subject = strings.TrimSpace(session.Subject)
		principal.Email = strings.ToLower(strings.TrimSpace(session.Email))
	case "api_key":
		metadata, found := s.apiKeyMetadataFromRequest(r)
		if found {
			principal.KeyID = strings.TrimSpace(metadata.ID)
			principal.UserID = strings.TrimSpace(metadata.OwnerUserID)
			principal.Subject = strings.TrimSpace(metadata.OwnerSubject)
			principal.Email = strings.ToLower(strings.TrimSpace(metadata.OwnerEmail))
			if principal.UserID != "" {
				principal.OwnerID = "user:" + strings.ToLower(principal.UserID)
			} else if principal.Subject != "" {
				principal.OwnerID = "sub:" + strings.ToLower(principal.Subject)
			} else if principal.Email != "" {
				principal.OwnerID = "email:" + principal.Email
			} else if principal.KeyID != "" {
				principal.OwnerID = "api_key:" + principal.KeyID
			}
		}
		if principal.OwnerID == "" {
			principal.OwnerID = s.apiKeyOwnerIDFromRequest(r)
		}
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
	return normalizeOwnerID(ownerID) != "" && normalizeOwnerID(ownerID) == normalizeOwnerID(p.OwnerID)
}

func normalizeOwnerID(ownerID string) string {
	return strings.ToLower(strings.TrimSpace(ownerID))
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
	metadata, found := s.apiKeyMetadataFromRequest(r)
	if found {
		if owner := strings.TrimSpace(metadata.OwnerUserID); owner != "" {
			return "user:" + strings.ToLower(owner)
		}
		if subject := strings.TrimSpace(metadata.OwnerSubject); subject != "" {
			return "sub:" + strings.ToLower(subject)
		}
		if email := strings.ToLower(strings.TrimSpace(metadata.OwnerEmail)); email != "" {
			return "email:" + email
		}
	}

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

func (s *Server) apiKeyMetadataFromRequest(r *http.Request) (APIKeyMetadata, bool) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return APIKeyMetadata{}, false
	}
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return APIKeyMetadata{}, false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return APIKeyMetadata{}, false
	}

	s.authMu.RLock()
	defer s.authMu.RUnlock()
	keyID, ok := s.findKeyIDByTokenLocked(token)
	if !ok {
		return APIKeyMetadata{}, false
	}
	metadata, exists := s.keysByID[keyID]
	if !exists {
		return APIKeyMetadata{}, false
	}
	return metadata, true
}
