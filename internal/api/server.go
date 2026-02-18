package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dashboardSession struct {
	Role      Role
	User      string
	ExpiresAt time.Time
}

const dashboardSessionCookieName = "baseline_dashboard_session"
const csrfHeaderName = "X-Baseline-CSRF"
const csrfHeaderValue = "1"

// Server provides a lightweight Baseline API for dashboard use.
type Server struct {
	config     Config
	httpServer *http.Server
	store      *Store

	authMu    sync.RWMutex
	keyIndex  map[string]string
	keysByID  map[string]APIKeyMetadata
	sessionMu sync.RWMutex
	sessions  map[string]dashboardSession

	dataMu   sync.RWMutex
	projects []Project
	scans    []ScanSummary
	policies map[string][]PolicyVersion
	rulesets []RulesetVersion
	events   []AuditEvent
}

// NewServer creates a new API server.
func NewServer(config Config, store *Store) (*Server, error) {
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
	if config.APIKeys == nil {
		config.APIKeys = map[string]Role{}
	}
	copiedAPIKeys := make(map[string]Role, len(config.APIKeys))
	for key, role := range config.APIKeys {
		copiedAPIKeys[key] = role
	}
	config.APIKeys = copiedAPIKeys
	copiedEnrollments := make(map[string]Role, len(config.EnrollmentTokens))
	for token, role := range config.EnrollmentTokens {
		copiedEnrollments[token] = role
	}
	config.EnrollmentTokens = copiedEnrollments

	now := time.Now().UTC()
	s := &Server{
		config:   config,
		store:    store,
		keyIndex: map[string]string{},
		keysByID: map[string]APIKeyMetadata{},
		sessions: map[string]dashboardSession{},
		projects: []Project{},
		scans:    []ScanSummary{},
		policies: map[string][]PolicyVersion{},
		rulesets: []RulesetVersion{},
		events: []AuditEvent{
			{EventType: "dashboard_initialized", CreatedAt: now},
		},
	}
	for key, role := range config.APIKeys {
		id := nextKeyID()
		if id == "" {
			id = "key_bootstrap"
		}
		for {
			if _, exists := s.keysByID[id]; !exists {
				break
			}
			id = nextKeyID()
			if id == "" {
				id = fmt.Sprintf("key_bootstrap_%d", time.Now().UTC().UnixNano())
				break
			}
		}
		s.keyIndex[key] = id
		s.keysByID[id] = APIKeyMetadata{
			ID:        id,
			Role:      role,
			Prefix:    keyPrefix(key),
			Source:    "bootstrap",
			CreatedAt: now,
			CreatedBy: "env",
			Revoked:   false,
		}
	}
	if err := s.loadPersistentState(); err != nil {
		return nil, fmt.Errorf("unable to load persistent API state: %w", err)
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
		if s.config.RequireHTTPS && !s.isRequestSecure(r) {
			writeError(w, http.StatusForbidden, "https_required", "HTTPS is required")
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
	case "/openapi.yaml":
		s.handleOpenAPI(w, r)
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
	case strings.HasPrefix(r.URL.Path, "/v1/api-keys"):
		s.handleAPIKeys(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/github/webhook"):
		s.handleGitHubWebhook(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/integrations/gitlab/webhook"):
		s.handleGitLabWebhook(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/dashboard"):
		s.handleDashboardSummary(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/projects"):
		s.handleProjects(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/scans"):
		s.handleScans(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/policies"):
		s.handlePolicies(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/rulesets"):
		s.handleRulesets(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/audit/events"):
		s.handleAuditEvents(w, r)
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

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/api-keys")
	pathSuffix = strings.Trim(pathSuffix, "/")

	switch r.Method {
	case http.MethodGet:
		if pathSuffix != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if _, err := s.authenticate(r); err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		s.authMu.RLock()
		keys := make([]APIKeyMetadata, 0, len(s.keysByID))
		for _, item := range s.keysByID {
			keys = append(keys, item)
		}
		s.authMu.RUnlock()
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"api_keys": keys,
		})
	case http.MethodPost:
		if pathSuffix != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		role, authSource, err := s.authenticateWithSource(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		if role != RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		targetRole := Role(strings.ToLower(strings.TrimSpace(req.Role)))
		if targetRole == "" {
			targetRole = RoleViewer
		}
		if !isValidRole(targetRole) {
			writeError(w, http.StatusBadRequest, "bad_request", "role must be one of viewer|operator|admin")
			return
		}
		key, metadata, err := s.issueAPIKey(targetRole, strings.TrimSpace(req.Name), "managed", string(role))
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
			"id":         metadata.ID,
			"name":       metadata.Name,
			"role":       metadata.Role,
			"prefix":     metadata.Prefix,
			"source":     metadata.Source,
			"created_at": metadata.CreatedAt,
			"api_key":    key,
		})
	case http.MethodDelete:
		if pathSuffix == "" {
			writeError(w, http.StatusNotFound, "not_found", "api key id is required")
			return
		}
		role, authSource, err := s.authenticateWithSource(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		if role != RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}

		s.authMu.Lock()
		metadata, exists := s.keysByID[pathSuffix]
		if !exists {
			s.authMu.Unlock()
			writeError(w, http.StatusNotFound, "not_found", "api key not found")
			return
		}
		if metadata.Source == "bootstrap" {
			s.authMu.Unlock()
			writeError(w, http.StatusConflict, "conflict", "bootstrap API key must be removed from environment and server restarted")
			return
		}
		if metadata.Revoked {
			s.authMu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      metadata.ID,
				"revoked": true,
			})
			return
		}
		now := time.Now().UTC()
		if s.store != nil {
			if err := s.store.RevokeAPIKey(metadata.ID, now); err != nil {
				s.authMu.Unlock()
				writeError(w, http.StatusInternalServerError, "system_error", "unable to persist API key revocation")
				return
			}
		}
		metadata.Revoked = true
		metadata.RevokedAt = &now
		s.keysByID[pathSuffix] = metadata
		for key, id := range s.keyIndex {
			if id != pathSuffix {
				continue
			}
			delete(s.keyIndex, key)
			delete(s.config.APIKeys, key)
			break
		}
		s.authMu.Unlock()

		s.dataMu.Lock()
		s.appendEventLocked(AuditEvent{
			EventType: "api_key_revoked",
			CreatedAt: now,
		})
		s.dataMu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"id":      metadata.ID,
			"revoked": true,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	secret := strings.TrimSpace(s.config.GitHubWebhookSecret)
	if secret == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "github webhook integration is disabled")
		return
	}

	body, ok := s.readRequestBody(w, r)
	if !ok {
		return
	}
	signature := strings.TrimSpace(r.Header.Get("X-Hub-Signature-256"))
	if !validGitHubSignature(body, secret, signature) {
		writeError(w, http.StatusForbidden, "forbidden", "invalid github webhook signature")
		return
	}

	var payload struct {
		Action      string `json:"action"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return
	}
	eventName := sanitizeEventToken(r.Header.Get("X-GitHub-Event"), "unknown")
	repository := strings.TrimSpace(payload.Repository.FullName)
	action := sanitizeEventToken(payload.Action, "unknown")
	prNumber := payload.PullRequest.Number

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "github_webhook_received",
		ProjectID: repository,
		ScanID:    integrationRef(prNumber),
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "github",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"pr_number":  prNumber,
	})
}

func (s *Server) handleGitLabWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	token := strings.TrimSpace(s.config.GitLabWebhookToken)
	if token == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "gitlab webhook integration is disabled")
		return
	}
	headerToken := strings.TrimSpace(r.Header.Get("X-Gitlab-Token"))
	if !secureEquals(headerToken, token) {
		writeError(w, http.StatusForbidden, "forbidden", "invalid gitlab webhook token")
		return
	}
	body, ok := s.readRequestBody(w, r)
	if !ok {
		return
	}

	var payload struct {
		ObjectKind       string `json:"object_kind"`
		ObjectAttributes struct {
			Action string `json:"action"`
			IID    int    `json:"iid"`
		} `json:"object_attributes"`
		Project struct {
			PathWithNamespace string `json:"path_with_namespace"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return
	}
	eventName := sanitizeEventToken(r.Header.Get("X-Gitlab-Event"), payload.ObjectKind)
	repository := strings.TrimSpace(payload.Project.PathWithNamespace)
	action := sanitizeEventToken(payload.ObjectAttributes.Action, "unknown")
	mrIID := payload.ObjectAttributes.IID

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "gitlab_webhook_received",
		ProjectID: repository,
		ScanID:    integrationRef(mrIID),
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "gitlab",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"mr_iid":     mrIID,
	})
}

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if _, err := s.authenticate(r); err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	s.dataMu.RLock()
	projects := append([]Project(nil), s.projects...)
	scans := append([]ScanSummary(nil), s.scans...)
	events := append([]AuditEvent(nil), s.events...)
	policies := clonePoliciesLocked(s.policies)
	s.dataMu.RUnlock()

	violations := map[string]int{}
	failingScans := 0
	blocking := 0
	for _, scan := range scans {
		if strings.EqualFold(scan.Status, "fail") {
			failingScans++
		}
		for _, v := range scan.Violations {
			policyID := strings.TrimSpace(v.PolicyID)
			if policyID == "" {
				policyID = "unknown"
			}
			violations[policyID]++
			if strings.EqualFold(strings.TrimSpace(v.Severity), "block") {
				blocking++
			}
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
		"policies":       summarizePolicies(policies),
	})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/projects"))
	projectID = strings.TrimPrefix(projectID, "/")

	switch r.Method {
	case http.MethodGet:
		if _, err := s.authenticate(r); err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		s.dataMu.RLock()
		projects := append([]Project(nil), s.projects...)
		s.dataMu.RUnlock()

		if projectID != "" {
			for _, project := range projects {
				if project.ID == projectID {
					writeJSON(w, http.StatusOK, project)
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found", "project not found")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		if projectID != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		role, authSource, err := s.authenticateWithSource(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		if role == RoleViewer {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var req struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			RepositoryURL string `json:"repository_url"`
			DefaultBranch string `json:"default_branch"`
			PolicySet     string `json:"policy_set"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "project name is required")
			return
		}
		project := Project{
			ID:            strings.TrimSpace(req.ID),
			Name:          strings.TrimSpace(req.Name),
			RepositoryURL: strings.TrimSpace(req.RepositoryURL),
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
		s.appendEventLocked(AuditEvent{
			EventType: "project_registered",
			ProjectID: project.ID,
			CreatedAt: time.Now().UTC(),
		})
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, project)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/scans")
	pathSuffix = strings.Trim(pathSuffix, "/")

	switch r.Method {
	case http.MethodGet:
		if _, err := s.authenticate(r); err != nil {
			writeUnauthorized(w, err.Error())
			return
		}

		if strings.HasSuffix(pathSuffix, "/report") {
			scanID := strings.TrimSuffix(pathSuffix, "/report")
			scanID = strings.TrimSuffix(scanID, "/")
			if strings.TrimSpace(scanID) == "" {
				writeError(w, http.StatusNotFound, "not_found", "scan not found")
				return
			}
			s.handleScanReport(w, r, scanID)
			return
		}

		s.dataMu.RLock()
		scans := append([]ScanSummary(nil), s.scans...)
		s.dataMu.RUnlock()

		if strings.TrimSpace(pathSuffix) != "" {
			for _, scan := range scans {
				if scan.ID == pathSuffix {
					writeJSON(w, http.StatusOK, scan)
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}

		projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
		if projectID != "" {
			filtered := make([]ScanSummary, 0, len(scans))
			for _, scan := range scans {
				if scan.ProjectID == projectID {
					filtered = append(filtered, scan)
				}
			}
			scans = filtered
		}

		writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
	case http.MethodPost:
		if strings.TrimSpace(pathSuffix) != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		role, authSource, err := s.authenticateWithSource(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		if role == RoleViewer {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		var req struct {
			ID         string          `json:"id"`
			ProjectID  string          `json:"project_id"`
			CommitSHA  string          `json:"commit_sha"`
			Status     string          `json:"status"`
			Violations []ScanViolation `json:"violations"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.ProjectID) == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "project_id is required")
			return
		}
		projectExists := false
		s.dataMu.RLock()
		for _, project := range s.projects {
			if project.ID == strings.TrimSpace(req.ProjectID) {
				projectExists = true
				break
			}
		}
		s.dataMu.RUnlock()
		if !projectExists {
			writeError(w, http.StatusBadRequest, "bad_request", "project_id does not exist")
			return
		}
		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status == "" {
			status = "pass"
		}
		if status != "pass" && status != "fail" && status != "warn" {
			writeError(w, http.StatusBadRequest, "bad_request", "status must be one of pass|fail|warn")
			return
		}

		scan := ScanSummary{
			ID:         strings.TrimSpace(req.ID),
			ProjectID:  strings.TrimSpace(req.ProjectID),
			CommitSHA:  strings.TrimSpace(req.CommitSHA),
			Status:     status,
			Violations: normalizeViolations(req.Violations),
			CreatedAt:  time.Now().UTC(),
		}
		if scan.ID == "" {
			scan.ID = randomToken(8)
		}

		s.dataMu.Lock()
		s.scans = append([]ScanSummary{scan}, s.scans...)
		s.appendEventLocked(AuditEvent{
			EventType: "scan_uploaded",
			ProjectID: scan.ProjectID,
			ScanID:    scan.ID,
			CreatedAt: time.Now().UTC(),
		})
		if strings.EqualFold(scan.Status, "fail") {
			s.appendEventLocked(AuditEvent{
				EventType: "enforcement_failed",
				ProjectID: scan.ProjectID,
				ScanID:    scan.ID,
				CreatedAt: time.Now().UTC(),
			})
		}
		s.dataMu.Unlock()

		writeJSON(w, http.StatusCreated, scan)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request, scanID string) {
	s.dataMu.RLock()
	scans := append([]ScanSummary(nil), s.scans...)
	s.dataMu.RUnlock()

	var scan *ScanSummary
	for i := range scans {
		if scans[i].ID == scanID {
			scan = &scans[i]
			break
		}
	}
	if scan == nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(renderScanTextReport(*scan)))
	case "sarif":
		writeJSON(w, http.StatusOK, renderScanSARIF(*scan))
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "unsupported report format; use json|text|sarif")
	}
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/policies")
	pathSuffix = strings.Trim(pathSuffix, "/")

	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	if pathSuffix == "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		s.dataMu.RLock()
		policies := clonePoliciesLocked(s.policies)
		s.dataMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"policies": summarizePolicies(policies)})
		return
	}

	parts := strings.Split(pathSuffix, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	policyName := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	if policyName == "" {
		writeError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}

	switch action {
	case "versions":
		switch r.Method {
		case http.MethodGet:
			s.dataMu.RLock()
			versions := append([]PolicyVersion(nil), s.policies[policyName]...)
			s.dataMu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"name": policyName, "versions": versions})
		case http.MethodPost:
			if role != RoleAdmin {
				writeError(w, http.StatusForbidden, "forbidden", "admin role required")
				return
			}
			if !s.requestBodyAllowed(w, r) {
				return
			}
			if !s.enforceSessionCSRF(w, r, authSource) {
				return
			}
			var req struct {
				Version     string                 `json:"version"`
				Description string                 `json:"description"`
				Content     map[string]any         `json:"content"`
				Metadata    map[string]interface{} `json:"metadata"`
			}
			if !s.decodeJSONBody(w, r, &req) {
				return
			}
			version := strings.TrimSpace(req.Version)
			if version == "" {
				version = "v" + time.Now().UTC().Format("20060102150405")
			}

			s.dataMu.Lock()
			existing := s.policies[policyName]
			for _, item := range existing {
				if item.Version == version {
					s.dataMu.Unlock()
					writeError(w, http.StatusConflict, "conflict", "policy version already exists")
					return
				}
			}
			item := PolicyVersion{
				Name:        policyName,
				Version:     version,
				Description: strings.TrimSpace(req.Description),
				Content:     req.Content,
				Metadata:    req.Metadata,
				PublishedAt: time.Now().UTC(),
				PublishedBy: "api",
			}
			s.policies[policyName] = append(existing, item)
			s.appendEventLocked(AuditEvent{
				EventType: "policy_updated",
				CreatedAt: time.Now().UTC(),
			})
			s.dataMu.Unlock()
			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}
	case "latest":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		s.dataMu.RLock()
		versions := append([]PolicyVersion(nil), s.policies[policyName]...)
		s.dataMu.RUnlock()
		if len(versions) == 0 {
			writeError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		writeJSON(w, http.StatusOK, versions[len(versions)-1])
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleRulesets(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/rulesets")
	pathSuffix = strings.Trim(pathSuffix, "/")

	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	if pathSuffix == "" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if role != RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		var req struct {
			Version     string   `json:"version"`
			Description string   `json:"description"`
			PolicyNames []string `json:"policy_names"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		version := strings.TrimSpace(req.Version)
		if version == "" {
			version = "v" + time.Now().UTC().Format("20060102150405")
		}

		s.dataMu.Lock()
		for _, existing := range s.rulesets {
			if existing.Version == version {
				s.dataMu.Unlock()
				writeError(w, http.StatusConflict, "conflict", "ruleset version already exists")
				return
			}
		}
		item := RulesetVersion{
			Version:     version,
			Description: strings.TrimSpace(req.Description),
			PolicyNames: dedupeNonEmpty(req.PolicyNames),
			CreatedAt:   time.Now().UTC(),
			CreatedBy:   "api",
		}
		s.rulesets = append(s.rulesets, item)
		s.appendEventLocked(AuditEvent{
			EventType: "ruleset_updated",
			CreatedAt: time.Now().UTC(),
		})
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, item)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	s.dataMu.RLock()
	rulesets := append([]RulesetVersion(nil), s.rulesets...)
	s.dataMu.RUnlock()

	if pathSuffix == "latest" {
		if len(rulesets) == 0 {
			writeError(w, http.StatusNotFound, "not_found", "ruleset not found")
			return
		}
		writeJSON(w, http.StatusOK, rulesets[len(rulesets)-1])
		return
	}

	for _, item := range rulesets {
		if item.Version == pathSuffix {
			writeJSON(w, http.StatusOK, item)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "ruleset not found")
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if _, err := s.authenticate(r); err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	limitRaw := strings.TrimSpace(r.URL.Query().Get("limit"))

	s.dataMu.RLock()
	events := append([]AuditEvent(nil), s.events...)
	s.dataMu.RUnlock()

	if projectID != "" {
		filtered := make([]AuditEvent, 0, len(events))
		for _, event := range events {
			if event.ProjectID == projectID {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	if limitRaw != "" {
		if limit, err := strconv.Atoi(limitRaw); err == nil && limit > 0 && len(events) > limit {
			events = events[:limit]
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) appendEventLocked(event AuditEvent) {
	s.events = append([]AuditEvent{event}, s.events...)
	if len(s.events) > 500 {
		s.events = s.events[:500]
	}
	if s.store != nil {
		_ = s.store.AppendAuditEvent(event)
	}
}

func (s *Server) loadPersistentState() error {
	if s.store == nil {
		return nil
	}

	// Persist bootstrap keys supplied via environment and then load full key state.
	for key, id := range s.keyIndex {
		meta, ok := s.keysByID[id]
		if !ok {
			continue
		}
		if err := s.store.EnsureBootstrapAPIKey(key, meta); err != nil {
			return err
		}
	}

	keys, err := s.store.LoadAPIKeys()
	if err != nil {
		return err
	}
	for _, item := range keys {
		s.keysByID[item.Metadata.ID] = item.Metadata
		if item.Metadata.Revoked {
			continue
		}
		s.keyIndex[item.Key] = item.Metadata.ID
		s.config.APIKeys[item.Key] = item.Metadata.Role
	}

	events, err := s.store.LoadAuditEvents(500)
	if err != nil {
		return err
	}
	if len(events) > 0 {
		s.events = events
		return nil
	}
	if len(s.events) > 0 {
		_ = s.store.AppendAuditEvent(s.events[0])
	}
	return nil
}

func clonePoliciesLocked(src map[string][]PolicyVersion) map[string][]PolicyVersion {
	out := make(map[string][]PolicyVersion, len(src))
	for name, versions := range src {
		out[name] = append([]PolicyVersion(nil), versions...)
	}
	return out
}

func summarizePolicies(policies map[string][]PolicyVersion) []PolicySummary {
	out := make([]PolicySummary, 0, len(policies))
	for name, versions := range policies {
		if len(versions) == 0 {
			continue
		}
		latest := versions[len(versions)-1]
		out = append(out, PolicySummary{
			Name:          name,
			LatestVersion: latest.Version,
			UpdatedAt:     latest.PublishedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizeViolations(in []ScanViolation) []ScanViolation {
	out := make([]ScanViolation, 0, len(in))
	for _, item := range in {
		policyID := strings.TrimSpace(item.PolicyID)
		if policyID == "" {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(item.Severity))
		if severity == "" {
			severity = "block"
		}
		out = append(out, ScanViolation{
			PolicyID: policyID,
			Severity: severity,
			Message:  strings.TrimSpace(item.Message),
		})
	}
	return out
}

func dedupeNonEmpty(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func renderScanTextReport(scan ScanSummary) string {
	lines := []string{
		fmt.Sprintf("scan_id: %s", scan.ID),
		fmt.Sprintf("project_id: %s", scan.ProjectID),
		fmt.Sprintf("commit_sha: %s", scan.CommitSHA),
		fmt.Sprintf("status: %s", scan.Status),
		fmt.Sprintf("created_at: %s", scan.CreatedAt.Format(time.RFC3339)),
		fmt.Sprintf("violations: %d", len(scan.Violations)),
	}
	for _, violation := range scan.Violations {
		lines = append(lines,
			fmt.Sprintf("- [%s] %s (%s)", violation.PolicyID, violation.Message, violation.Severity),
		)
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderScanSARIF(scan ScanSummary) map[string]any {
	results := make([]map[string]any, 0, len(scan.Violations))
	rules := make([]map[string]any, 0, len(scan.Violations))
	ruleSeen := map[string]struct{}{}

	for _, violation := range scan.Violations {
		if _, ok := ruleSeen[violation.PolicyID]; !ok {
			ruleSeen[violation.PolicyID] = struct{}{}
			rules = append(rules, map[string]any{
				"id": violation.PolicyID,
				"shortDescription": map[string]any{
					"text": violation.PolicyID + " policy violation",
				},
				"properties": map[string]any{
					"severity": violation.Severity,
				},
			})
		}

		results = append(results, map[string]any{
			"ruleId": violation.PolicyID,
			"level":  sarifLevelFromSeverity(violation.Severity),
			"message": map[string]any{
				"text": violation.Message,
			},
		})
	}

	return map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "Baseline API",
						"informationUri": "https://github.com/baseline/baseline",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
}

func sarifLevelFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "block":
		return "error"
	case "warn":
		return "warning"
	default:
		return "note"
	}
}

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

func validGitHubSignature(body []byte, secret, signature string) bool {
	sig := strings.TrimSpace(signature)
	if !strings.HasPrefix(strings.ToLower(sig), "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
	return secureEquals(sig, expected)
}

func secureEquals(a, b string) bool {
	left := []byte(strings.TrimSpace(a))
	right := []byte(strings.TrimSpace(b))
	return hmac.Equal(left, right)
}

func sanitizeEventToken(raw, fallback string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return fallback
	}
	out := strings.Builder{}
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			out.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			out.WriteRune(ch)
		case ch == '_' || ch == '-' || ch == ':':
			out.WriteRune(ch)
		}
	}
	sanitized := strings.TrimSpace(out.String())
	if sanitized == "" {
		return fallback
	}
	return sanitized
}

func integrationRef(number int) string {
	if number <= 0 {
		return ""
	}
	return strconv.Itoa(number)
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

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="baseline-api", error="invalid_token"`)
	writeError(w, http.StatusUnauthorized, "unauthorized", message)
}

func (s *Server) issueAPIKey(role Role, name, source, createdBy string) (string, APIKeyMetadata, error) {
	if !isValidRole(role) {
		return "", APIKeyMetadata{}, errors.New("invalid role")
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.config.APIKeys == nil {
		s.config.APIKeys = map[string]Role{}
	}
	if s.keyIndex == nil {
		s.keyIndex = map[string]string{}
	}
	if s.keysByID == nil {
		s.keysByID = map[string]APIKeyMetadata{}
	}

	key := ""
	for attempts := 0; attempts < 10; attempts++ {
		candidate := randomToken(32)
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, exists := s.config.APIKeys[candidate]; exists {
			continue
		}
		key = candidate
		break
	}
	if key == "" {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key")
	}

	id := ""
	for attempts := 0; attempts < 10; attempts++ {
		candidate := nextKeyID()
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, exists := s.keysByID[candidate]; exists {
			continue
		}
		id = candidate
		break
	}
	if id == "" {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key id")
	}

	now := time.Now().UTC()
	metadata := APIKeyMetadata{
		ID:        id,
		Name:      strings.TrimSpace(name),
		Role:      role,
		Prefix:    keyPrefix(key),
		Source:    strings.TrimSpace(source),
		CreatedAt: now,
		CreatedBy: strings.TrimSpace(createdBy),
		Revoked:   false,
	}
	s.config.APIKeys[key] = role
	s.keyIndex[key] = id
	s.keysByID[id] = metadata
	if s.store != nil {
		if err := s.store.UpsertAPIKey(key, metadata); err != nil {
			delete(s.config.APIKeys, key)
			delete(s.keyIndex, key)
			delete(s.keysByID, id)
			return "", APIKeyMetadata{}, err
		}
	}
	return key, metadata, nil
}

func nextKeyID() string {
	fragment := randomToken(6)
	if strings.TrimSpace(fragment) == "" {
		return ""
	}
	return "key_" + fragment
}

func keyPrefix(key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	if len(k) <= 6 {
		return k
	}
	return k[:6] + "..."
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
