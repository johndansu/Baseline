package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Store is a placeholder for persistence.
type Store struct{}

type dashboardSession struct {
	Role      Role
	User      string
	ExpiresAt time.Time
}

const dashboardSessionCookieName = "baseline_dashboard_session"

// Server provides a lightweight Baseline API for dashboard use.
type Server struct {
	config     Config
	httpServer *http.Server

	sessionMu sync.RWMutex
	sessions  map[string]dashboardSession

	dataMu   sync.RWMutex
	projects []Project
	scans    []ScanSummary
	events   []AuditEvent
}

// NewServer creates a new API server.
func NewServer(config Config, _ *Store) (*Server, error) {
	if !isValidRole(config.DashboardSessionRole) {
		config.DashboardSessionRole = RoleViewer
	}
	if config.DashboardSessionTTL <= 0 {
		config.DashboardSessionTTL = 12 * time.Hour
	}
	if !config.SelfServiceEnabled && len(config.APIKeys) == 0 && !config.DashboardSessionEnabled {
		return nil, errors.New("no API keys configured. Set BASELINE_API_KEY/BASELINE_API_KEYS or enable BASELINE_API_DASHBOARD_SESSION_ENABLED")
	}
	if config.SelfServiceEnabled && len(config.EnrollmentTokens) == 0 {
		return nil, errors.New("self-service enabled but no enrollment tokens configured. Set BASELINE_API_ENROLLMENT_TOKENS")
	}
	if config.DashboardAuthProxyEnabled && !config.TrustProxyHeaders {
		return nil, errors.New("dashboard auth proxy requires BASELINE_API_TRUST_PROXY_HEADERS=true")
	}

	now := time.Now().UTC()
	s := &Server{
		config:   config,
		sessions: map[string]dashboardSession{},
		projects: []Project{},
		scans:    []ScanSummary{},
		events: []AuditEvent{
			{EventType: "dashboard_initialized", CreatedAt: now},
		},
	}
	s.httpServer = &http.Server{
		Addr:         config.Addr,
		Handler:      s.Handler(),
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}
	return s, nil
}

// Handler returns the API HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.applySecurityHeaders(w, r)
		if s.handleCORS(w, r) {
			return
		}
		s.route(w, r)
	})
}

// ListenAndServe starts serving API requests.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/dashboard", "/dashboard/", "/assets/baseline-logo.png", "/assets/dashboard.css", "/assets/dashboard.js":
		s.handleDashboard(w, r)
		return
	case "/healthz", "/livez":
		s.handleHealth(w, r)
		return
	case "/readyz":
		s.handleReady(w, r)
		return
	}

	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/auth/session"):
		s.handleAuthSession(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/auth/register"):
		s.handleAuthRegister(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/dashboard"):
		s.handleDashboardSummary(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/projects"):
		s.handleProjects(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/scans"):
		s.handleScans(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	if !s.config.DashboardSessionEnabled {
		writeError(w, http.StatusForbidden, "session_disabled", "dashboard session auth is disabled")
		return
	}

	switch r.Method {
	case http.MethodPost:
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

		token := randomToken(32)
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
			SameSite: http.SameSiteLaxMode,
			Secure:   false,
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
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user":      session.User,
			"role":      session.Role,
			"auth_mode": s.dashboardAuthMode(),
			"active":    true,
		})
	case http.MethodDelete:
		cookie, _ := r.Cookie(dashboardSessionCookieName)
		if cookie != nil && cookie.Value != "" {
			s.sessionMu.Lock()
			delete(s.sessions, cookie.Value)
			s.sessionMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{
			Name:     dashboardSessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
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
	if !s.config.SelfServiceEnabled {
		writeError(w, http.StatusForbidden, "self_service_disabled", "self-service registration is disabled")
		return
	}
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		APIKey          string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return
	}
	token := strings.TrimSpace(req.EnrollmentToken)
	key := strings.TrimSpace(req.APIKey)
	if token == "" || key == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "enrollment_token and api_key are required")
		return
	}
	role, ok := s.config.EnrollmentTokens[token]
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "invalid enrollment token")
		return
	}
	if s.config.APIKeys == nil {
		s.config.APIKeys = map[string]Role{}
	}
	s.config.APIKeys[key] = role
	writeJSON(w, http.StatusCreated, map[string]any{
		"role": role,
	})
}

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if _, err := s.authenticate(r); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	s.dataMu.RLock()
	projects := append([]Project(nil), s.projects...)
	scans := append([]ScanSummary(nil), s.scans...)
	events := append([]AuditEvent(nil), s.events...)
	s.dataMu.RUnlock()

	violations := map[string]int{}
	failingScans := 0
	blocking := 0
	for _, scan := range scans {
		if strings.EqualFold(scan.Status, "fail") {
			failingScans++
		}
		for _, v := range scan.Violations {
			violations[v]++
			blocking++
		}
	}
	top := make([]DashboardViolationCount, 0, len(violations))
	for policyID, count := range violations {
		top = append(top, DashboardViolationCount{PolicyID: policyID, Count: count})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"metrics": DashboardMetrics{
			Projects:           len(projects),
			Scans:              len(scans),
			FailingScans:       failingScans,
			BlockingViolations: blocking,
		},
		"recent_scans":   scans,
		"top_violations": top,
		"recent_events":  events,
	})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, err := s.authenticate(r); err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		s.dataMu.RLock()
		projects := append([]Project(nil), s.projects...)
		s.dataMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		role, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		if role == RoleViewer {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var req struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			DefaultBranch string `json:"default_branch"`
			PolicySet     string `json:"policy_set"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "project name is required")
			return
		}
		project := Project{
			ID:            strings.TrimSpace(req.ID),
			Name:          strings.TrimSpace(req.Name),
			DefaultBranch: strings.TrimSpace(req.DefaultBranch),
			PolicySet:     strings.TrimSpace(req.PolicySet),
		}
		if project.ID == "" {
			project.ID = randomToken(8)
		}
		if project.DefaultBranch == "" {
			project.DefaultBranch = "main"
		}
		if project.PolicySet == "" {
			project.PolicySet = "baseline:prod"
		}
		s.dataMu.Lock()
		s.projects = append(s.projects, project)
		s.events = append([]AuditEvent{{EventType: "project_created", CreatedAt: time.Now().UTC()}}, s.events...)
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, project)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if _, err := s.authenticate(r); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	s.dataMu.RLock()
	scans := append([]ScanSummary(nil), s.scans...)
	s.dataMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (s *Server) authenticate(r *http.Request) (Role, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			if role, ok := s.config.APIKeys[token]; ok {
				return role, nil
			}
		}
	}
	session, err := s.getDashboardSession(r)
	if err == nil {
		return session.Role, nil
	}
	return "", errors.New("missing or invalid credentials")
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
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
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
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func randomToken(size int) string {
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
