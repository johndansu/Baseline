package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
	client     *http.Client

	authMu    sync.RWMutex
	keyIndex  map[string]string
	keyHashes map[string]string
	keysByID  map[string]APIKeyMetadata
	sessionMu sync.RWMutex
	sessions  map[string]dashboardSession
	rateMu    sync.Mutex
	rateState map[string]rateWindowCounter
	rateSweep time.Time

	dataMu               sync.RWMutex
	projects             []Project
	scans                []ScanSummary
	scanIdempotency      map[string]scanIdempotencyEntry
	scanIdempotencyTTL   time.Duration
	scanIdempotencySweep time.Time
	policies             map[string][]PolicyVersion
	rulesets             []RulesetVersion
	events               []AuditEvent

	workerMu                sync.Mutex
	workerCancel            context.CancelFunc
	workerDone              chan struct{}
	integrationPollInterval time.Duration
	integrationRetryBase    time.Duration
	integrationRetryMax     time.Duration
}

// NewServer creates a new API server.
func NewServer(config Config, store *Store) (*Server, error) {
	if !isValidRole(config.DashboardSessionRole) {
		config.DashboardSessionRole = RoleViewer
	}
	if config.DashboardSessionTTL <= 0 {
		config.DashboardSessionTTL = 12 * time.Hour
	}
	if config.RateLimitRequests <= 0 {
		config.RateLimitRequests = 120
	}
	if config.RateLimitWindow <= 0 {
		config.RateLimitWindow = 1 * time.Minute
	}
	if config.AuthRateLimitRequests <= 0 {
		config.AuthRateLimitRequests = 20
	}
	if config.AuthRateLimitWindow <= 0 {
		config.AuthRateLimitWindow = 1 * time.Minute
	}
	if config.UnauthRateLimitRequests <= 0 {
		config.UnauthRateLimitRequests = 30
	}
	if config.UnauthRateLimitWindow <= 0 {
		config.UnauthRateLimitWindow = 1 * time.Minute
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
	if store != nil {
		store.SetAPIKeyHashSecret(config.APIKeyHashSecret)
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
		config:             config,
		store:              store,
		client:             &http.Client{Timeout: 10 * time.Second},
		keyIndex:           map[string]string{},
		keyHashes:          map[string]string{},
		keysByID:           map[string]APIKeyMetadata{},
		sessions:           map[string]dashboardSession{},
		rateState:          map[string]rateWindowCounter{},
		projects:           []Project{},
		scans:              []ScanSummary{},
		scanIdempotency:    map[string]scanIdempotencyEntry{},
		scanIdempotencyTTL: 24 * time.Hour,
		policies:           map[string][]PolicyVersion{},
		rulesets:           []RulesetVersion{},
		events: []AuditEvent{
			{EventType: "dashboard_initialized", CreatedAt: now},
		},
		integrationPollInterval: 500 * time.Millisecond,
		integrationRetryBase:    1 * time.Second,
		integrationRetryMax:     30 * time.Second,
	}
	for key, role := range config.APIKeys {
		keyHash := hashAPIKey(key, config.APIKeyHashSecret)
		if keyHash == "" {
			continue
		}
		id := bootstrapKeyID(legacyAPIKeyHash(key))
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
		s.keyHashes[keyHash] = id
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

// ListenAndServe starts serving API requests.
func (s *Server) ListenAndServe() error {
	s.startIntegrationWorker()
	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.stopIntegrationWorker()
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.stopIntegrationWorker()
	return s.httpServer.Shutdown(ctx)
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
			ScanID:    metadata.ID,
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
		for keyHash, id := range s.keyHashes {
			if id == pathSuffix {
				delete(s.keyHashes, keyHash)
				break
			}
		}
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
			ScanID:    metadata.ID,
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
