package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/baseline/baseline/internal/version"
)

const (
	cliSessionAccessTTL  = 30 * time.Minute
	cliSessionRefreshTTL = 14 * 24 * time.Hour
	cliSessionLoginTTL   = 10 * time.Minute
)

func (s *Server) handleCLISession(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "cli session storage unavailable")
		return
	}
	switch {
	case r.URL.Path == "/v1/cli/session/start":
		s.handleCLISessionStart(w, r)
	case r.URL.Path == "/v1/cli/session/approve":
		s.handleCLISessionApprove(w, r)
	case r.URL.Path == "/v1/cli/session/poll":
		s.handleCLISessionPoll(w, r)
	case r.URL.Path == "/v1/cli/session/refresh":
		s.handleCLISessionRefresh(w, r)
	case r.URL.Path == "/v1/cli/session":
		if r.Method == http.MethodGet {
			s.handleCLISessionList(w, r)
			return
		}
		s.handleCLISessionDelete(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/cli/session/"):
		if strings.HasPrefix(r.URL.Path, "/v1/cli/session/owner/") {
			s.handleCLISessionsByOwnerKey(w, r)
			return
		}
		s.handleCLISessionByID(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleCLISessionStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	var req struct {
		ClientName string `json:"client_name"`
		ClientHost string `json:"client_host"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	deviceCode := randomToken(24)
	userCode := randomCLIUserCode()
	if strings.TrimSpace(deviceCode) == "" || strings.TrimSpace(userCode) == "" {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to create cli login request")
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(cliSessionLoginTTL)
	if err := s.store.CreateCLIAuthRequest(deviceCode, userCode, trimMax(req.ClientName, 120), trimMax(req.ClientHost, 120), expiresAt, now); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to persist cli login request")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_code":      deviceCode,
		"user_code":        userCode,
		"verification_url": s.cliVerificationURL(r),
		"expires_at":       expiresAt,
		"interval_seconds": 2,
	})
}

func (s *Server) handleCLISessionApprove(w http.ResponseWriter, r *http.Request) {
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
	if principal.AuthSource != "session" {
		writeError(w, http.StatusForbidden, "forbidden", "cli login approval requires a dashboard session")
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}
	var req struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	deviceCode := strings.TrimSpace(req.DeviceCode)
	userCode := strings.TrimSpace(strings.ToUpper(req.UserCode))
	if deviceCode == "" && userCode == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "device_code or user_code is required")
		return
	}
	session, err := s.getDashboardSession(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	approved, err := s.store.ApproveCLIAuthRequest(deviceCode, userCode, cliSessionRecord{
		UserID:    strings.TrimSpace(principal.UserID),
		Role:      principal.Role,
		UserLabel: session.User,
		Subject:   session.Subject,
		Email:     session.Email,
	}, time.Now().UTC())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not_found", "cli login request not found")
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "pending") {
			writeError(w, http.StatusConflict, "conflict", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "system_error", "unable to approve cli login request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approved":    true,
		"user_code":   approved.UserCodeDisplay,
		"role":        approved.ApprovedRole,
		"user":        approved.ApprovedUserLabel,
		"approved_at": approved.ApprovedAt,
	})
}

func (s *Server) handleCLISessionPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	deviceCode := strings.TrimSpace(req.DeviceCode)
	if deviceCode == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "device_code is required")
		return
	}
	now := time.Now().UTC()
	record, found, err := s.store.GetCLIAuthRequest(deviceCode, "", now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load cli login request")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "cli login request not found")
		return
	}
	if record.Status == cliAuthRequestStatusPending {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"approved":   false,
			"expires_at": record.ExpiresAt,
			"status":     record.Status,
		})
		return
	}
	if record.Status != cliAuthRequestStatusApproved {
		writeError(w, http.StatusConflict, "conflict", "cli login request is not approvable")
		return
	}
	accessToken := randomToken(32)
	refreshToken := randomToken(32)
	if accessToken == "" || refreshToken == "" {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to issue cli session")
		return
	}
	cliSession := cliSessionRecord{
		SessionID:        "cli_sess_" + randomToken(8),
		UserID:           record.ApprovedUserID,
		Role:             record.ApprovedRole,
		UserLabel:        fallbackCLIUserLabel(record),
		Subject:          record.ApprovedSubject,
		Email:            record.ApprovedEmail,
		ClientName:       record.ClientName,
		ClientHost:       record.ClientHost,
		CreatedAt:        now,
		ApprovedAt:       record.ApprovedAt,
		LastUsedAt:       now,
		AccessExpiresAt:  now.Add(cliSessionAccessTTL),
		RefreshExpiresAt: now.Add(cliSessionRefreshTTL),
	}
	if err := s.store.CreateCLISession(accessToken, refreshToken, cliSession, now); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to persist cli session")
		return
	}
	if err := s.store.ConsumeCLIAuthRequest(deviceCode, now); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to finalize cli login request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_at":    cliSession.AccessExpiresAt,
		"role":          cliSession.Role,
		"user":          cliSession.UserLabel,
		"user_id":       cliSession.UserID,
		"email":         cliSession.Email,
		"client_name":   cliSession.ClientName,
		"client_host":   cliSession.ClientHost,
	})
}

func (s *Server) handleCLISessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if refreshToken == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "refresh_token is required")
		return
	}
	now := time.Now().UTC()
	session, found, err := s.store.LoadCLISessionByRefreshToken(refreshToken, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load cli session")
		return
	}
	if !found {
		writeUnauthorized(w, "invalid or expired cli refresh token")
		return
	}
	session, valid, err := s.syncCLISessionState(session, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to refresh cli session identity")
		return
	}
	if !valid {
		_ = s.store.RevokeCLISessionByRefreshToken(refreshToken, now)
		writeUnauthorized(w, "invalid or expired cli refresh token")
		return
	}
	newAccessToken := randomToken(32)
	newRefreshToken := randomToken(32)
	if newAccessToken == "" || newRefreshToken == "" {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to rotate cli session")
		return
	}
	session.LastUsedAt = now
	session.AccessExpiresAt = now.Add(cliSessionAccessTTL)
	session.RefreshExpiresAt = now.Add(cliSessionRefreshTTL)
	if err := s.store.RotateCLISession(session, newAccessToken, newRefreshToken, now); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to persist cli session rotation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_at":    session.AccessExpiresAt,
		"role":          session.Role,
		"user":          session.UserLabel,
		"user_id":       session.UserID,
		"email":         session.Email,
		"client_name":   session.ClientName,
		"client_host":   session.ClientHost,
	})
}

func (s *Server) handleCLISessionDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		session, token, err := s.getCLISessionFromRequest(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if err := s.store.RevokeCLISessionByAccessToken(token, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to revoke cli session")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"revoked":     true,
			"user":        session.UserLabel,
			"client_name": session.ClientName,
		})
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "refresh_token is required")
		return
	}
	if err := s.store.RevokeCLISessionByRefreshToken(strings.TrimSpace(req.RefreshToken), time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to revoke cli session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (s *Server) handleCLISessionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, 500)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive integer up to 500")
			return
		}
		limit = parsed
	}
	sessions, err := s.store.ListCLISessions(limit, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to list cli sessions")
		return
	}
	items := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, map[string]any{
			"session_id":         session.SessionID,
			"user_id":            session.UserID,
			"user":               session.UserLabel,
			"email":              session.Email,
			"role":               session.Role,
			"owner_key":          cliSessionOwnerID(session),
			"client_name":        session.ClientName,
			"client_host":        session.ClientHost,
			"last_ip":            session.LastIP,
			"cli_version":        session.CLIVersion,
			"last_repository":    session.LastRepository,
			"last_project_id":    session.LastProjectID,
			"last_command":       session.LastCommand,
			"last_scan_id":       session.LastScanID,
			"created_at":         session.CreatedAt,
			"approved_at":        session.ApprovedAt,
			"last_used_at":       session.LastUsedAt,
			"access_expires_at":  session.AccessExpiresAt,
			"refresh_expires_at": session.RefreshExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": items,
	})
}

func (s *Server) handleCLISessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleCLISessionDetail(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}
	sessionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/cli/session/"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "session id is required")
		return
	}
	revoked, err := s.store.RevokeCLISessionByID(sessionID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to revoke cli session")
		return
	}
	if !revoked {
		writeError(w, http.StatusNotFound, "not_found", "cli session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":    true,
		"session_id": sessionID,
	})
}

func (s *Server) handleCLISessionDetail(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	sessionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/cli/session/"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "session id is required")
		return
	}
	sessions, err := s.store.ListCLISessions(500, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load cli session")
		return
	}
	var matched *cliSessionRecord
	for i := range sessions {
		if strings.TrimSpace(sessions[i].SessionID) == sessionID {
			matched = &sessions[i]
			break
		}
	}
	if matched == nil {
		writeError(w, http.StatusNotFound, "not_found", "cli session not found")
		return
	}
	traces, err := s.store.ListCLITracesBySessionID(sessionID, 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load cli session activity")
		return
	}
	timeline := buildCLISessionTimeline(*matched, traces)
	writeJSON(w, http.StatusOK, map[string]any{
		"session": map[string]any{
			"session_id":         matched.SessionID,
			"user_id":            matched.UserID,
			"user":               matched.UserLabel,
			"email":              matched.Email,
			"role":               matched.Role,
			"owner_key":          cliSessionOwnerID(*matched),
			"client_name":        matched.ClientName,
			"client_host":        matched.ClientHost,
			"last_ip":            matched.LastIP,
			"cli_version":        matched.CLIVersion,
			"last_repository":    matched.LastRepository,
			"last_project_id":    matched.LastProjectID,
			"last_command":       matched.LastCommand,
			"last_scan_id":       matched.LastScanID,
			"created_at":         matched.CreatedAt,
			"approved_at":        matched.ApprovedAt,
			"last_used_at":       matched.LastUsedAt,
			"access_expires_at":  matched.AccessExpiresAt,
			"refresh_expires_at": matched.RefreshExpiresAt,
		},
		"anomaly_flags": buildCLISessionAnomalyFlags(*matched, traces),
		"recent_traces": traces,
		"risk_signals":  buildCLISessionRiskSignals(*matched, traces),
		"timeline":      timeline,
	})
}

func buildCLISessionRiskSignals(session cliSessionRecord, traces []CLITraceSummary) []map[string]any {
	signals := make([]map[string]any, 0, 4)
	add := func(id, severity, title, detail string) {
		signals = append(signals, map[string]any{
			"id":       id,
			"severity": severity,
			"title":    title,
			"detail":   detail,
		})
	}

	now := time.Now().UTC()
	if !session.RefreshExpiresAt.IsZero() {
		remaining := session.RefreshExpiresAt.Sub(now)
		if remaining > 0 && remaining <= 72*time.Hour {
			add(
				"refresh_expiring",
				"warning",
				"Refresh token expires soon",
				fmt.Sprintf("This CLI session refresh expires on %s.", session.RefreshExpiresAt.Format(time.RFC1123)),
			)
		}
	}

	if !session.LastUsedAt.IsZero() && now.Sub(session.LastUsedAt) > 7*24*time.Hour {
		add(
			"dormant_session",
			"warning",
			"Session has gone dormant",
			fmt.Sprintf("No CLI activity has been recorded since %s.", session.LastUsedAt.Format(time.RFC1123)),
		)
	}

	currentVersion := strings.TrimSpace(version.Short())
	sessionVersion := strings.TrimSpace(session.CLIVersion)
	if currentVersion != "" && sessionVersion != "" && currentVersion != sessionVersion {
		add(
			"stale_cli_version",
			"warning",
			"CLI version differs from current build",
			fmt.Sprintf("Session last reported CLI %s while the current build is %s.", sessionVersion, currentVersion),
		)
	}

	for _, trace := range traces {
		if strings.EqualFold(strings.TrimSpace(trace.Status), "error") {
			add(
				"recent_failed_command",
				"error",
				"Recent command failed",
				fmt.Sprintf("%s failed at %s.", strings.TrimSpace(trace.Command), trace.StartedAt.Format(time.RFC1123)),
			)
			break
		}
	}

	return signals
}

func buildCLISessionAnomalyFlags(session cliSessionRecord, traces []CLITraceSummary) []map[string]any {
	flags := make([]map[string]any, 0, 4)
	add := func(id, severity, title, detail string) {
		flags = append(flags, map[string]any{
			"id":       id,
			"severity": severity,
			"title":    title,
			"detail":   detail,
		})
	}

	if len(traces) == 0 {
		return flags
	}

	errorCount := 0
	repositories := map[string]struct{}{}
	projects := map[string]struct{}{}
	versions := map[string]struct{}{}
	recentWindowCount := 0
	latestStartedAt := traces[0].StartedAt

	for _, trace := range traces {
		if status := strings.ToLower(strings.TrimSpace(trace.Status)); status == "error" {
			errorCount++
		}
		if repository := strings.TrimSpace(trace.Repository); repository != "" {
			repositories[repository] = struct{}{}
		}
		if projectID := strings.TrimSpace(trace.ProjectID); projectID != "" {
			projects[projectID] = struct{}{}
		}
		if versionText := strings.TrimSpace(trace.Version); versionText != "" {
			versions[versionText] = struct{}{}
		}
		if !latestStartedAt.IsZero() && !trace.StartedAt.IsZero() && latestStartedAt.Sub(trace.StartedAt) <= 10*time.Minute {
			recentWindowCount++
		}
	}

	if sessionVersion := strings.TrimSpace(session.CLIVersion); sessionVersion != "" {
		versions[sessionVersion] = struct{}{}
	}
	if sessionRepo := strings.TrimSpace(session.LastRepository); sessionRepo != "" {
		repositories[sessionRepo] = struct{}{}
	}
	if sessionProject := strings.TrimSpace(session.LastProjectID); sessionProject != "" {
		projects[sessionProject] = struct{}{}
	}

	if errorCount >= 2 {
		add(
			"repeated_failures",
			"error",
			"Repeated command failures",
			fmt.Sprintf("%d recent traced commands ended in error for this session.", errorCount),
		)
	}
	if len(repositories) > 1 || len(projects) > 1 {
		add(
			"multi_target_activity",
			"warning",
			"Session touched multiple targets recently",
			fmt.Sprintf("Recent activity spans %d repositories and %d projects.", len(repositories), len(projects)),
		)
	}
	if len(versions) > 1 {
		add(
			"version_churn",
			"warning",
			"CLI version changed within one session",
			fmt.Sprintf("Recent activity reported %d distinct CLI versions.", len(versions)),
		)
	}
	if recentWindowCount >= 3 {
		add(
			"burst_activity",
			"info",
			"High command volume in a short window",
			fmt.Sprintf("%d traced commands were recorded within a 10 minute window.", recentWindowCount),
		)
	}

	return flags
}

func buildCLISessionTimeline(session cliSessionRecord, traces []CLITraceSummary) []map[string]any {
	items := make([]map[string]any, 0, len(traces)+4)
	add := func(at time.Time, kind, title, detail, status string, attrs map[string]any) {
		if at.IsZero() {
			return
		}
		entry := map[string]any{
			"at":     at,
			"kind":   kind,
			"title":  title,
			"detail": detail,
			"status": status,
		}
		if len(attrs) > 0 {
			entry["attributes"] = attrs
		}
		items = append(items, entry)
	}

	add(session.CreatedAt, "session_created", "Session created", strings.TrimSpace(session.ClientName), "ok", map[string]any{
		"client_host": session.ClientHost,
	})
	add(session.ApprovedAt, "session_approved", "Session approved", strings.TrimSpace(session.UserLabel), "ok", map[string]any{
		"role":  session.Role,
		"email": session.Email,
	})
	add(session.LastUsedAt, "session_used", "Last activity recorded", strings.TrimSpace(session.LastCommand), "info", map[string]any{
		"repository": session.LastRepository,
		"project_id": session.LastProjectID,
		"scan_id":    session.LastScanID,
		"ip":         session.LastIP,
	})
	add(session.RefreshExpiresAt, "session_refresh_expires", "Refresh token expires", "", "warning", nil)

	for _, trace := range traces {
		detailParts := make([]string, 0, 3)
		if value := strings.TrimSpace(trace.Repository); value != "" {
			detailParts = append(detailParts, value)
		}
		if value := strings.TrimSpace(trace.ProjectID); value != "" {
			detailParts = append(detailParts, value)
		}
		if value := strings.TrimSpace(trace.Message); value != "" {
			detailParts = append(detailParts, value)
		}
		add(trace.StartedAt, "trace", "CLI command: "+strings.TrimSpace(trace.Command), strings.Join(detailParts, " | "), strings.TrimSpace(trace.Status), map[string]any{
			"trace_id":     trace.TraceID,
			"scan_id":      trace.ScanID,
			"event_count":  trace.EventCount,
			"duration_ms":  trace.DurationMS,
			"session_id":   trace.SessionID,
			"command":      trace.Command,
			"repository":   trace.Repository,
			"project_id":   trace.ProjectID,
			"trace_status": trace.Status,
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		left, _ := items[i]["at"].(time.Time)
		right, _ := items[j]["at"].(time.Time)
		return left.After(right)
	})
	return items
}

func (s *Server) handleCLISessionsByOwnerKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}
	ownerKey := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/cli/session/owner/"))
	if ownerKey == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "owner key is required")
		return
	}
	revokedCount, err := s.store.RevokeCLISessionsByOwnerKey(ownerKey, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to revoke cli sessions")
		return
	}
	if revokedCount == 0 {
		writeError(w, http.StatusNotFound, "not_found", "no active cli sessions found for this user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":       true,
		"owner_key":     ownerKey,
		"revoked_count": revokedCount,
	})
}

func (s *Server) cliVerificationURL(r *http.Request) string {
	scheme := "http"
	if s.isRequestSecure(r) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/dashboard", scheme, r.Host)
}

func randomCLIUserCode() string {
	raw := strings.ToUpper(strings.ReplaceAll(randomToken(6), "-", ""))
	raw = strings.ReplaceAll(raw, "_", "")
	raw = strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '2' && r <= '9':
			return r
		default:
			return -1
		}
	}, raw)
	if len(raw) < 8 {
		raw += "ABCDEFGH"
	}
	raw = raw[:8]
	return raw[:4] + "-" + raw[4:]
}

func fallbackCLIUserLabel(record cliAuthRequestRecord) string {
	if v := strings.TrimSpace(record.ApprovedUserLabel); v != "" {
		return v
	}
	if v := strings.TrimSpace(record.ApprovedEmail); v != "" {
		return v
	}
	return "cli_user"
}

func trimMax(value string, max int) string {
	out := strings.TrimSpace(value)
	if max > 0 && len(out) > max {
		return out[:max]
	}
	return out
}
