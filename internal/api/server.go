package api

import (
	"bytes"
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
	"net/url"
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
	jobID, err := s.enqueueIntegrationJob(IntegrationJob{
		Provider:    "github",
		JobType:     "webhook_event",
		ProjectRef:  repository,
		ExternalRef: integrationRef(prNumber),
		Payload:     string(body),
		MaxAttempts: 5,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to enqueue integration job")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "github",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"pr_number":  prNumber,
		"job_id":     jobID,
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
	jobID, err := s.enqueueIntegrationJob(IntegrationJob{
		Provider:    "gitlab",
		JobType:     "webhook_event",
		ProjectRef:  repository,
		ExternalRef: integrationRef(mrIID),
		Payload:     string(body),
		MaxAttempts: 5,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to enqueue integration job")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "gitlab",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"mr_iid":     mrIID,
		"job_id":     jobID,
	})
}

func (s *Server) handleGitHubCheckRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
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
	if role == RoleViewer {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	if !s.enforceSessionCSRF(w, r, authSource) {
		return
	}

	token := strings.TrimSpace(s.config.GitHubAPIToken)
	baseURL := strings.TrimSpace(s.config.GitHubAPIBaseURL)
	if token == "" || baseURL == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "github status publishing is disabled")
		return
	}

	var req struct {
		Owner      string `json:"owner"`
		Repository string `json:"repository"`
		HeadSHA    string `json:"head_sha"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		DetailsURL string `json:"details_url"`
		ExternalID string `json:"external_id"`
		Output     struct {
			Title   string `json:"title"`
			Summary string `json:"summary"`
		} `json:"output"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	repo := strings.TrimSpace(req.Repository)
	headSHA := strings.TrimSpace(req.HeadSHA)
	name := strings.TrimSpace(req.Name)
	if owner == "" || repo == "" || headSHA == "" || name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "owner, repository, head_sha, and name are required")
		return
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "completed"
	}
	switch status {
	case "queued", "in_progress", "completed":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "status must be one of queued|in_progress|completed")
		return
	}

	conclusion := strings.ToLower(strings.TrimSpace(req.Conclusion))
	if status == "completed" && conclusion == "" {
		conclusion = "neutral"
	}

	payload := map[string]any{
		"name":     name,
		"head_sha": headSHA,
		"status":   status,
	}
	if conclusion != "" {
		payload["conclusion"] = conclusion
	}
	if detailsURL := strings.TrimSpace(req.DetailsURL); detailsURL != "" {
		payload["details_url"] = detailsURL
	}
	if externalID := strings.TrimSpace(req.ExternalID); externalID != "" {
		payload["external_id"] = externalID
	}
	title := strings.TrimSpace(req.Output.Title)
	summary := strings.TrimSpace(req.Output.Summary)
	if title != "" || summary != "" {
		payload["output"] = map[string]any{
			"title":   title,
			"summary": summary,
		}
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to encode github check run payload")
		return
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/check-runs"
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(rawPayload))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to build github api request")
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Accept", "application/vnd.github+json")
	upstreamReq.Header.Set("Authorization", "Bearer "+token)
	upstreamReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	upstreamResp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "integration_failed", "failed to call github api")
		return
	}
	defer upstreamResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(upstreamResp.Body, s.config.MaxBodyBytes))
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "integration_failed", fmt.Sprintf("github api returned status %d", upstreamResp.StatusCode))
		return
	}

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "github_check_published",
		ProjectID: owner + "/" + repo,
		ScanID:    headSHA,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":        true,
		"provider":        "github",
		"repository":      owner + "/" + repo,
		"head_sha":        headSHA,
		"upstream_status": upstreamResp.StatusCode,
	})
}

func (s *Server) handleGitLabStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
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
	if role == RoleViewer {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	if !s.enforceSessionCSRF(w, r, authSource) {
		return
	}

	token := strings.TrimSpace(s.config.GitLabAPIToken)
	baseURL := strings.TrimSpace(s.config.GitLabAPIBaseURL)
	if token == "" || baseURL == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "gitlab status publishing is disabled")
		return
	}

	var req struct {
		ProjectID   string `json:"project_id"`
		SHA         string `json:"sha"`
		State       string `json:"state"`
		Name        string `json:"name"`
		TargetURL   string `json:"target_url"`
		Description string `json:"description"`
		Ref         string `json:"ref"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	projectID := strings.TrimSpace(req.ProjectID)
	sha := strings.TrimSpace(req.SHA)
	state := strings.ToLower(strings.TrimSpace(req.State))
	if projectID == "" || sha == "" || state == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "project_id, sha, and state are required")
		return
	}
	switch state {
	case "pending", "running", "success", "failed", "canceled", "skipped":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "state must be one of pending|running|success|failed|canceled|skipped")
		return
	}

	params := url.Values{}
	params.Set("state", state)
	if value := strings.TrimSpace(req.Name); value != "" {
		params.Set("name", value)
	}
	if value := strings.TrimSpace(req.TargetURL); value != "" {
		params.Set("target_url", value)
	}
	if value := strings.TrimSpace(req.Description); value != "" {
		params.Set("description", value)
	}
	if value := strings.TrimSpace(req.Ref); value != "" {
		params.Set("ref", value)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/projects/" + url.PathEscape(projectID) + "/statuses/" + url.PathEscape(sha) + "?" + params.Encode()
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to build gitlab api request")
		return
	}
	upstreamReq.Header.Set("Accept", "application/json")
	upstreamReq.Header.Set("PRIVATE-TOKEN", token)

	upstreamResp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "integration_failed", "failed to call gitlab api")
		return
	}
	defer upstreamResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(upstreamResp.Body, s.config.MaxBodyBytes))
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "integration_failed", fmt.Sprintf("gitlab api returned status %d", upstreamResp.StatusCode))
		return
	}

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "gitlab_status_published",
		ProjectID: projectID,
		ScanID:    sha,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":        true,
		"provider":        "gitlab",
		"project_id":      projectID,
		"sha":             sha,
		"upstream_status": upstreamResp.StatusCode,
	})
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

func (s *Server) enqueueIntegrationJob(job IntegrationJob) (string, error) {
	if s.store == nil {
		return "", nil
	}
	created, err := s.store.EnqueueIntegrationJob(job)
	if err != nil {
		return "", err
	}
	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "integration_job_enqueued",
		ProjectID: created.ProjectRef,
		ScanID:    created.ExternalRef,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()
	return created.ID, nil
}

func (s *Server) startIntegrationWorker() {
	if s.store == nil {
		return
	}
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.workerCancel = cancel
	s.workerDone = done
	go s.runIntegrationWorker(ctx, done)
}

func (s *Server) stopIntegrationWorker() {
	s.workerMu.Lock()
	cancel := s.workerCancel
	done := s.workerDone
	s.workerCancel = nil
	s.workerDone = nil
	s.workerMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Server) runIntegrationWorker(ctx context.Context, done chan struct{}) {
	defer close(done)
	interval := s.integrationPollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runIntegrationWorkerCycle(ctx)
		}
	}
}

func (s *Server) runIntegrationWorkerCycle(ctx context.Context) {
	if s.store == nil {
		return
	}
	job, err := s.store.ClaimDueIntegrationJob(time.Now().UTC())
	if err != nil || job == nil {
		return
	}
	now := time.Now().UTC()
	processErr := s.processIntegrationJob(ctx, *job)
	if processErr == nil {
		_ = s.store.MarkIntegrationJobSucceeded(job.ID, now)
		s.dataMu.Lock()
		s.appendEventLocked(AuditEvent{
			EventType: "integration_job_succeeded",
			ProjectID: job.ProjectRef,
			ScanID:    job.ExternalRef,
			CreatedAt: now,
		})
		s.dataMu.Unlock()
		return
	}

	if isRetryableIntegrationError(processErr) && job.AttemptCount < job.MaxAttempts {
		nextAttempt := now.Add(s.integrationBackoff(job.AttemptCount))
		_ = s.store.MarkIntegrationJobRetry(job.ID, processErr.Error(), nextAttempt, now)
		s.dataMu.Lock()
		s.appendEventLocked(AuditEvent{
			EventType: "integration_job_retry_scheduled",
			ProjectID: job.ProjectRef,
			ScanID:    job.ExternalRef,
			CreatedAt: now,
		})
		s.dataMu.Unlock()
		return
	}

	_ = s.store.MarkIntegrationJobFailed(job.ID, processErr.Error(), now)
	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "integration_job_failed",
		ProjectID: job.ProjectRef,
		ScanID:    job.ExternalRef,
		CreatedAt: now,
	})
	s.dataMu.Unlock()
}

func (s *Server) processIntegrationJob(_ context.Context, job IntegrationJob) error {
	if strings.TrimSpace(job.JobType) != "webhook_event" {
		return nil
	}
	if strings.TrimSpace(job.Payload) == "" {
		return &integrationRetryableError{msg: "missing job payload"}
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return err
	}
	retryCount := 0
	if raw, ok := payload["simulate_transient_failures"]; ok {
		switch v := raw.(type) {
		case float64:
			retryCount = int(v)
		case int:
			retryCount = v
		}
	}
	if retryCount > 0 && job.AttemptCount <= retryCount {
		return &integrationRetryableError{msg: "transient integration processing failure"}
	}
	return nil
}

func (s *Server) integrationBackoff(attempt int) time.Duration {
	base := s.integrationRetryBase
	if base <= 0 {
		base = 1 * time.Second
	}
	maxDelay := s.integrationRetryMax
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
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
		keyHash := normalizeStoredAPIKeyHash(item.KeyHash)
		if keyHash != "" {
			if currentID, exists := s.keyHashes[keyHash]; exists && currentID != item.Metadata.ID {
				delete(s.keysByID, currentID)
				for rawKey, indexedID := range s.keyIndex {
					if indexedID == currentID {
						s.keyIndex[rawKey] = item.Metadata.ID
					}
				}
			}
			if item.Metadata.Revoked {
				delete(s.keyHashes, keyHash)
			} else {
				s.keyHashes[keyHash] = item.Metadata.ID
			}
		}
		s.keysByID[item.Metadata.ID] = item.Metadata
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

type integrationRetryableError struct {
	msg string
}

func (e *integrationRetryableError) Error() string {
	return strings.TrimSpace(e.msg)
}

func isRetryableIntegrationError(err error) bool {
	var target *integrationRetryableError
	return errors.As(err, &target)
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
	if s.keyHashes == nil {
		s.keyHashes = map[string]string{}
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
		if s.hasTokenHashCollisionLocked(candidate) {
			continue
		}
		key = candidate
		break
	}
	if key == "" {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key")
	}
	keyHash := hashAPIKey(key, s.config.APIKeyHashSecret)
	if keyHash == "" {
		return "", APIKeyMetadata{}, errors.New("unable to hash generated API key")
	}
	if s.hasTokenHashCollisionLocked(key) {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key hash")
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
	s.keyHashes[keyHash] = id
	s.keysByID[id] = metadata
	if s.store != nil {
		if err := s.store.UpsertAPIKey(key, metadata); err != nil {
			delete(s.config.APIKeys, key)
			delete(s.keyIndex, key)
			delete(s.keyHashes, keyHash)
			delete(s.keysByID, id)
			return "", APIKeyMetadata{}, err
		}
	}
	return key, metadata, nil
}

func (s *Server) findKeyIDByTokenLocked(token string) (string, bool) {
	candidates := apiKeyHashCandidates(token, s.config.APIKeyHashSecret)
	if len(candidates) == 0 {
		return "", false
	}
	for storedHash, keyID := range s.keyHashes {
		for _, candidate := range candidates {
			if constantTimeAPIKeyHashEqual(storedHash, candidate) {
				return keyID, true
			}
		}
	}
	return "", false
}

func (s *Server) hasTokenHashCollisionLocked(token string) bool {
	_, exists := s.findKeyIDByTokenLocked(token)
	return exists
}

func nextKeyID() string {
	fragment := randomToken(6)
	if strings.TrimSpace(fragment) == "" {
		return ""
	}
	return "key_" + fragment
}

func bootstrapKeyID(keyHash string) string {
	trimmed := strings.TrimSpace(keyHash)
	if len(trimmed) < 12 {
		return "key_bootstrap"
	}
	return "key_bootstrap_" + trimmed[:12]
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
