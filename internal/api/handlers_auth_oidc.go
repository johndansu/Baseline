package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	baselinelog "github.com/baseline/baseline/internal/log"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type pendingOIDCLogin struct {
	CodeVerifier string
	Nonce        string
	ReturnTo     string
	CreatedAt    time.Time
}

type oidcRuntime struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

type oidcIDTokenClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	resp := map[string]any{
		"authenticated": true,
		"role":          role,
		"auth_source":   authSource,
	}

	if authSource == "session" {
		if session, err := s.getDashboardSession(r); err == nil {
			resp["user"] = session.User
			if session.UserID != "" {
				resp["user_id"] = session.UserID
			}
			if session.Subject != "" {
				resp["subject"] = session.Subject
			}
			if session.Email != "" {
				resp["email"] = session.Email
			}
			if session.AuthSource != "" {
				resp["identity_source"] = session.AuthSource
			}
			resp["expires_at"] = session.ExpiresAt
		}
	} else if authSource == "api_key" {
		resp["user"] = "api_key"
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAuthOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.config.OIDCEnabled {
		writeError(w, http.StatusForbidden, "oidc_disabled", "OIDC login is disabled")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	rt, err := s.getOIDCRuntime(ctx)
	if err != nil {
		baselinelog.Warn("OIDC login runtime unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "oidc_unavailable", oidcUnavailableMessage(err))
		return
	}

	state := randomToken(24)
	nonce := randomToken(24)
	codeVerifier := randomToken(48)
	if state == "" || nonce == "" || codeVerifier == "" {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to generate OIDC login state")
		return
	}

	returnTo := normalizeOIDCReturnTo(r.URL.Query().Get("return_to"))
	loginMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	loginHint := strings.TrimSpace(r.URL.Query().Get("login_hint"))
	now := time.Now().UTC()
	s.oidcMu.Lock()
	s.sweepExpiredOIDCStateLocked(now)
	s.oidcState[state] = pendingOIDCLogin{
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
		ReturnTo:     returnTo,
		CreatedAt:    now,
	}
	s.oidcMu.Unlock()

	authOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", pkceChallengeS256(codeVerifier)),
	}
	if loginMode == "signup" && isAuth0Issuer(s.config.OIDCIssuerURL) {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("screen_hint", "signup"))
	}
	if loginHint != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("login_hint", loginHint))
	}

	authURL := rt.oauth.AuthCodeURL(
		state,
		authOptions...,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAuthOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.config.OIDCEnabled {
		writeError(w, http.StatusForbidden, "oidc_disabled", "OIDC login is disabled")
		return
	}
	if errValue := strings.TrimSpace(r.URL.Query().Get("error")); errValue != "" {
		msg := strings.TrimSpace(r.URL.Query().Get("error_description"))
		if msg != "" {
			baselinelog.Warn("OIDC provider callback error", "provider_error", errValue, "provider_description", msg)
		} else {
			baselinelog.Warn("OIDC provider callback error", "provider_error", errValue)
		}
		writeError(w, http.StatusUnauthorized, "oidc_error", "OIDC authentication was not completed")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	stateToken := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || stateToken == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "missing code or state")
		return
	}

	pending, ok := s.consumeOIDCState(stateToken)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid or expired OIDC state")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rt, err := s.getOIDCRuntime(ctx)
	if err != nil {
		baselinelog.Warn("OIDC callback runtime unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "oidc_unavailable", oidcUnavailableMessage(err))
		return
	}

	oauthToken, err := rt.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pending.CodeVerifier))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "oidc_exchange_failed", "unable to exchange OIDC authorization code")
		return
	}
	rawIDToken, _ := oauthToken.Extra("id_token").(string)
	if strings.TrimSpace(rawIDToken) == "" {
		writeError(w, http.StatusUnauthorized, "oidc_token_invalid", "missing id_token from OIDC provider")
		return
	}
	idToken, err := rt.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "oidc_token_invalid", "unable to verify OIDC id_token")
		return
	}
	var claims oidcIDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		writeError(w, http.StatusUnauthorized, "oidc_claims_invalid", "unable to parse OIDC claims")
		return
	}
	if strings.TrimSpace(claims.Nonce) != "" && claims.Nonce != pending.Nonce {
		writeError(w, http.StatusUnauthorized, "oidc_nonce_invalid", "invalid OIDC nonce")
		return
	}
	if err := s.validateOIDCIdentity(claims); err != nil {
		baselinelog.Warn("OIDC identity rejected", "error", err)
		writeError(w, http.StatusForbidden, "oidc_identity_rejected", "OIDC identity did not satisfy policy requirements")
		return
	}

	userLabel := pickOIDCDisplayUser(claims)
	userID := ""
	if s.store != nil {
		persistedUserID, err := s.store.UpsertOIDCUser(
			s.config.OIDCIssuerURL,
			strings.TrimSpace(claims.Subject),
			strings.TrimSpace(strings.ToLower(claims.Email)),
			userLabel,
			time.Now().UTC(),
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to persist OIDC user")
			return
		}
		userID = strings.TrimSpace(persistedUserID)
	}
	if err := s.issueDashboardSession(w, r, dashboardSession{
		UserID:     userID,
		Role:       s.config.OIDCDefaultRole,
		User:       userLabel,
		Subject:    strings.TrimSpace(claims.Subject),
		Email:      strings.TrimSpace(strings.ToLower(claims.Email)),
		AuthSource: "oidc",
		ExpiresAt:  time.Now().UTC().Add(s.config.DashboardSessionTTL),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to create dashboard session")
		return
	}

	if wantsJSONResponse(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"role":          s.config.OIDCDefaultRole,
			"auth_source":   "session",
			"identity": map[string]any{
				"source":  "oidc",
				"user_id": userID,
				"user":    userLabel,
				"email":   strings.TrimSpace(strings.ToLower(claims.Email)),
				"sub":     strings.TrimSpace(claims.Subject),
			},
			"redirect_to": pending.ReturnTo,
		})
		return
	}
	http.Redirect(w, r, pending.ReturnTo, http.StatusFound)
}

func (s *Server) issueDashboardSession(w http.ResponseWriter, r *http.Request, session dashboardSession) error {
	if strings.TrimSpace(session.User) == "" {
		session.User = "local_dashboard"
	}
	if !isValidRole(session.Role) {
		session.Role = RoleViewer
	}
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = time.Now().UTC().Add(s.config.DashboardSessionTTL)
	}
	secureCookie := s.shouldUseSecureSessionCookie(r)
	if secureCookie && !s.isRequestSecure(r) {
		return errors.New("secure dashboard sessions require HTTPS")
	}
	token := randomToken(32)
	if token == "" {
		return errors.New("unable to create dashboard session token")
	}
	now := time.Now().UTC()
	if s.store != nil {
		if err := s.store.UpsertAuthSession(token, session, now); err != nil {
			return err
		}
	}
	s.sessionMu.Lock()
	s.sessions[token] = session
	s.sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     dashboardSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secureCookie,
		Expires:  session.ExpiresAt,
	})
	return nil
}

func (s *Server) getOIDCRuntime(ctx context.Context) (*oidcRuntime, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc != nil {
		return s.oidc, nil
	}
	if !s.config.OIDCEnabled {
		return nil, errors.New("oidc disabled")
	}

	provider, err := oidc.NewProvider(ctx, s.config.OIDCIssuerURL)
	if err != nil {
		return nil, err
	}
	scopes := append([]string{}, s.config.OIDCScopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	rt := &oidcRuntime{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: s.config.OIDCClientID}),
		oauth: &oauth2.Config{
			ClientID:     s.config.OIDCClientID,
			ClientSecret: s.config.OIDCClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  s.config.OIDCRedirectURL,
			Scopes:       scopes,
		},
	}
	s.oidc = rt
	return rt, nil
}

func (s *Server) consumeOIDCState(state string) (pendingOIDCLogin, bool) {
	now := time.Now().UTC()
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	s.sweepExpiredOIDCStateLocked(now)
	pending, ok := s.oidcState[state]
	if !ok {
		return pendingOIDCLogin{}, false
	}
	delete(s.oidcState, state)
	return pending, true
}

func (s *Server) sweepExpiredOIDCStateLocked(now time.Time) {
	for token, pending := range s.oidcState {
		if now.Sub(pending.CreatedAt) > 10*time.Minute {
			delete(s.oidcState, token)
		}
	}
}

func (s *Server) validateOIDCIdentity(claims oidcIDTokenClaims) error {
	email := strings.TrimSpace(strings.ToLower(claims.Email))
	if s.config.OIDCRequireVerifiedEmail {
		if claims.EmailVerified == nil || !*claims.EmailVerified {
			return errors.New("OIDC email is not verified")
		}
	}
	if len(s.config.OIDCAllowedEmailDomains) > 0 {
		if email == "" || !strings.Contains(email, "@") {
			return errors.New("OIDC email is required for domain restriction")
		}
		domain := strings.TrimSpace(strings.ToLower(strings.SplitN(email, "@", 2)[1]))
		allowed := false
		for _, candidate := range s.config.OIDCAllowedEmailDomains {
			if strings.EqualFold(strings.TrimSpace(candidate), domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("OIDC email domain %q is not allowed", domain)
		}
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return errors.New("OIDC subject (sub) is missing")
	}
	return nil
}

func pickOIDCDisplayUser(claims oidcIDTokenClaims) string {
	if v := strings.TrimSpace(claims.Email); v != "" {
		return v
	}
	if v := strings.TrimSpace(claims.PreferredUsername); v != "" {
		return v
	}
	if v := strings.TrimSpace(claims.Name); v != "" {
		return v
	}
	if v := strings.TrimSpace(claims.Subject); v != "" {
		return v
	}
	return "oidc_user"
}

func normalizeOIDCReturnTo(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "/"
	}
	u, err := url.Parse(value)
	if err != nil {
		return "/"
	}
	if strings.HasPrefix(value, "//") {
		return "/"
	}
	if u.IsAbs() {
		if isSafeAbsoluteOIDCReturnTo(u) {
			return u.String()
		}
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		return "/"
	}
	if !isAllowedRelativeOIDCReturnPath(u.Path) {
		return "/"
	}
	return value
}

func isAllowedRelativeOIDCReturnPath(path string) bool {
	switch strings.TrimSpace(path) {
	case "/", "/index.html", "/signin", "/signin.html", "/signup", "/signup.html":
		return true
	default:
		return false
	}
}

func isSafeAbsoluteOIDCReturnTo(u *url.URL) bool {
	if u == nil {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func wantsJSONResponse(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	return strings.Contains(accept, "application/json")
}

func isAuth0Issuer(issuer string) bool {
	value := strings.ToLower(strings.TrimSpace(issuer))
	return strings.Contains(value, ".auth0.com")
}

func oidcUnavailableMessage(err error) string {
	return "unable to initialize OIDC provider; check OIDC/Auth0/Supabase auth configuration"
}
