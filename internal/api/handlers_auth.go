package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *Server) handleAuthReauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}
	token, expiresAt, err := s.issueSensitiveActionReauth(principal)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to issue sensitive-action re-auth token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reauth_token": token,
		"expires_at":   expiresAt,
	})
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/auth/session/exchange" {
		s.handleAuthSessionExchange(w, r)
		return
	}

	if !s.config.DashboardSessionEnabled && !s.config.OIDCEnabled {
		writeError(w, http.StatusForbidden, "session_disabled", "dashboard session auth is disabled")
		return
	}

	switch r.Method {
	case http.MethodPost:
		if !s.config.DashboardSessionEnabled {
			writeError(w, http.StatusForbidden, "session_disabled", "local dashboard session creation is disabled")
			return
		}
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

		session := dashboardSession{
			Role:       role,
			User:       user,
			AuthSource: "session_cookie",
			ExpiresAt:  time.Now().UTC().Add(s.config.DashboardSessionTTL),
		}
		if err := s.issueDashboardSession(w, r, session); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "https") {
				writeError(w, http.StatusForbidden, "https_required", err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "system_error", "unable to create dashboard session")
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"user":            user,
			"role":            role,
			"auth_mode":       s.dashboardAuthMode(),
			"identity_source": "session_cookie",
			"active":          true,
		})
	case http.MethodGet:
		session, err := s.getDashboardSession(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		resp := map[string]any{
			"user":            session.User,
			"role":            session.Role,
			"auth_mode":       s.dashboardAuthMode(),
			"identity_source": session.AuthSource,
			"active":          true,
		}
		if session.UserID != "" {
			resp["user_id"] = session.UserID
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodDelete:
		if !s.validCSRFSentinel(r) {
			writeError(w, http.StatusForbidden, "csrf_failed", "missing required CSRF header")
			return
		}
		cookie, _ := r.Cookie(dashboardSessionCookieName)
		if cookie != nil && cookie.Value != "" {
			token := strings.TrimSpace(cookie.Value)
			s.sessionMu.Lock()
			delete(s.sessions, token)
			s.sessionMu.Unlock()
			if s.store != nil {
				if err := s.store.RevokeAuthSession(token, time.Now().UTC()); err != nil {
					writeError(w, http.StatusInternalServerError, "system_error", "unable to revoke dashboard session")
					return
				}
			}
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

type supabaseUserInfo struct {
	ID               string         `json:"id"`
	Email            string         `json:"email"`
	EmailConfirmedAt string         `json:"email_confirmed_at"`
	UserMetadata     map[string]any `json:"user_metadata"`
}

func (s *Server) handleAuthSessionExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}

	var req struct {
		AccessToken string `json:"access_token"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}

	accessToken := strings.TrimSpace(req.AccessToken)
	if accessToken == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "access_token is required")
		return
	}

	supabaseUser, issuerURL, err := s.fetchSupabaseUser(r.Context(), accessToken)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	verified := strings.TrimSpace(supabaseUser.EmailConfirmedAt) != ""
	claims := oidcIDTokenClaims{
		Subject: strings.TrimSpace(supabaseUser.ID),
		Email:   strings.TrimSpace(strings.ToLower(supabaseUser.Email)),
		Name:    pickSupabaseDisplayName(supabaseUser.UserMetadata),
	}
	if claims.Name == "" {
		claims.Name = claims.Email
	}
	claims.EmailVerified = &verified

	if err := s.validateOIDCIdentity(claims); err != nil {
		writeError(w, http.StatusForbidden, "oidc_identity_rejected", "OIDC identity did not satisfy policy requirements")
		return
	}

	now := time.Now().UTC()
	userLabel := pickOIDCDisplayUser(claims)
	userID := ""
	if s.store != nil {
		persistedUserID, err := s.store.UpsertOIDCUser(
			issuerURL,
			claims.Subject,
			strings.TrimSpace(strings.ToLower(claims.Email)),
			userLabel,
			now,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to persist OIDC user")
			return
		}
		userID = strings.TrimSpace(persistedUserID)
	}

	role := s.config.OIDCDefaultRole
	if !isValidRole(role) {
		role = s.config.DashboardSessionRole
	}
	if !isValidRole(role) {
		role = RoleViewer
	}
	if s.store != nil && userID != "" {
		persistedUser, found, err := s.store.GetUserByID(userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to load persisted user")
			return
		}
		if found {
			if persistedUser.Status == UserStatusSuspended {
				writeError(w, http.StatusForbidden, "account_suspended", "account is suspended")
				return
			}
			if isValidRole(persistedUser.Role) {
				role = persistedUser.Role
			}
		}
	}

	if err := s.issueDashboardSession(w, r, dashboardSession{
		UserID:     userID,
		Role:       role,
		User:       userLabel,
		Subject:    claims.Subject,
		Email:      claims.Email,
		AuthSource: "supabase",
		ExpiresAt:  now.Add(s.config.DashboardSessionTTL),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to create dashboard session")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"authenticated": true,
		"role":          role,
		"auth_source":   "session",
		"identity": map[string]any{
			"source":  "supabase",
			"user_id": userID,
			"user":    userLabel,
			"email":   claims.Email,
			"sub":     claims.Subject,
		},
	})
}

func (s *Server) fetchSupabaseUser(parent context.Context, accessToken string) (supabaseUserInfo, string, error) {
	baseURL, publicKey := configuredSupabaseRuntime()
	if baseURL == "" || publicKey == "" {
		return supabaseUserInfo{}, "", errors.New("supabase session exchange is not configured")
	}

	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/user", nil)
	if err != nil {
		return supabaseUserInfo{}, "", errors.New("supabase session exchange failed")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("apikey", publicKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return supabaseUserInfo{}, "", errors.New("supabase session exchange failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return supabaseUserInfo{}, "", errors.New("invalid or expired external session")
	}

	var user supabaseUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return supabaseUserInfo{}, "", errors.New("supabase session exchange failed")
	}
	if strings.TrimSpace(user.ID) == "" {
		return supabaseUserInfo{}, "", errors.New("invalid or expired external session")
	}

	return user, baseURL, nil
}

func configuredSupabaseRuntime() (string, string) {
	baseURL := strings.TrimSpace(os.Getenv("BASELINE_API_SUPABASE_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	}
	publicKey := strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY"))
	if publicKey == "" {
		publicKey = strings.TrimSpace(os.Getenv("SUPABASE_PUBLISHABLE_KEY"))
	}
	if baseURL == "" || publicKey == "" {
		return "", ""
	}
	return normalizeSupabaseOIDCIssuer(baseURL), publicKey
}

func pickSupabaseDisplayName(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	for _, key := range []string{"full_name", "name", "preferred_username", "user_name"} {
		if value, ok := metadata[key]; ok {
			if text := strings.TrimSpace(toString(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
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
	key, metadata, err := s.issueAPIKey(role, "self-service", "self_service", "enrollment_token", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to generate API key")
		return
	}
	s.dataMu.Lock()
	s.appendEventLocked(s.newRequestAuditEvent(r, "enrollment_token", "api_key_issued", "", metadata.ID))
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
