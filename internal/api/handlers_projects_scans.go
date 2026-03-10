package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/projects"))
	pathSuffix = strings.Trim(pathSuffix, "/")
	segments := []string{}
	if pathSuffix != "" {
		segments = strings.Split(pathSuffix, "/")
	}
	projectID := ""
	projectAction := ""
	if len(segments) > 0 {
		projectID = strings.TrimSpace(segments[0])
	}
	if len(segments) > 1 {
		projectAction = strings.TrimSpace(strings.ToLower(segments[1]))
	}
	if len(segments) > 2 {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if projectAction != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		principal, err := s.requestPrincipal(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		s.dataMu.RLock()
		projects := append([]Project(nil), s.projects...)
		s.dataMu.RUnlock()

		if projectID != "" {
			for _, project := range projects {
				if project.ID == projectID && principal.canAccessOwner(project.OwnerID) {
					writeJSON(w, http.StatusOK, project)
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found", "project not found")
			return
		}

		if principal.enforceOwnership() {
			filtered := make([]Project, 0, len(projects))
			for _, project := range projects {
				if principal.canAccessOwner(project.OwnerID) {
					filtered = append(filtered, project)
				}
			}
			projects = filtered
		}

		writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		principal, err := s.requestPrincipal(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		if projectAction == "claim" {
			s.handleProjectClaim(w, r, principal, projectID)
			return
		}
		if projectID != "" || projectAction != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if principal.Role == RoleViewer {
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
		if strings.TrimSpace(principal.OwnerID) != "" {
			project.OwnerID = principal.OwnerID
		}
		if s.store != nil {
			if err := s.store.UpsertProject(project, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "system_error", "unable to persist project")
				return
			}
		}
		s.dataMu.Lock()
		s.projects = append(s.projects, project)
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "project_registered", project.ID, ""))
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, project)
	case http.MethodPut:
		if projectAction != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		principal, err := s.requestPrincipal(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if projectID == "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		if principal.Role == RoleViewer {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		var req struct {
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

		s.dataMu.Lock()
		defer s.dataMu.Unlock()

		index := -1
		for i := range s.projects {
			if s.projects[i].ID == projectID {
				index = i
				break
			}
		}
		if index < 0 {
			writeError(w, http.StatusNotFound, "not_found", "project not found")
			return
		}
		if principal.enforceOwnership() && !principal.canAccessOwner(s.projects[index].OwnerID) {
			writeError(w, http.StatusForbidden, "forbidden", "project access denied")
			return
		}

		updated := s.projects[index]
		updated.Name = strings.TrimSpace(req.Name)
		updated.RepositoryURL = strings.TrimSpace(req.RepositoryURL)
		updated.DefaultBranch = strings.TrimSpace(req.DefaultBranch)
		updated.PolicySet = strings.TrimSpace(req.PolicySet)
		if updated.DefaultBranch == "" {
			updated.DefaultBranch = "main"
		}
		if updated.PolicySet == "" {
			updated.PolicySet = "baseline:prod"
		}
		if s.store != nil {
			if err := s.store.UpsertProject(updated, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "system_error", "unable to persist project")
				return
			}
		}
		s.projects[index] = updated
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "project_updated", updated.ID, ""))
		writeJSON(w, http.StatusOK, updated)
	case http.MethodPatch:
		principal, err := s.requestPrincipal(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		if projectAction != "owner" || projectID == "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		s.handleProjectOwnerAssignment(w, r, principal, projectID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleProjectClaim(w http.ResponseWriter, r *http.Request, principal authPrincipal, projectID string) {
	if strings.TrimSpace(projectID) == "" {
		writeError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	if principal.AuthSource != "session" {
		writeError(w, http.StatusForbidden, "forbidden", "project claim requires a signed-in user session")
		return
	}
	if strings.TrimSpace(principal.OwnerID) == "" {
		writeError(w, http.StatusForbidden, "forbidden", "current session cannot own projects")
		return
	}

	s.dataMu.Lock()
	defer s.dataMu.Unlock()

	index := -1
	for i := range s.projects {
		if s.projects[i].ID == projectID {
			index = i
			break
		}
	}
	if index < 0 {
		writeError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	current := s.projects[index]
	currentOwner := strings.TrimSpace(current.OwnerID)
	if principal.Role != RoleAdmin && currentOwner != "" && currentOwner != strings.TrimSpace(principal.OwnerID) {
		writeError(w, http.StatusForbidden, "forbidden", "project claim is not allowed for this owner")
		return
	}

	current.OwnerID = strings.TrimSpace(principal.OwnerID)
	if s.store != nil {
		updated, err := s.store.UpdateProjectOwner(projectID, current.OwnerID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to persist project owner")
			return
		}
		current = updated
	}
	s.projects[index] = current
	s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "project_owner_claimed", current.ID, ""))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleProjectOwnerAssignment(w http.ResponseWriter, r *http.Request, principal authPrincipal, projectID string) {
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role is required")
		return
	}

	var req struct {
		OwnerID string `json:"owner_id"`
		UserID  string `json:"user_id"`
		Subject string `json:"subject"`
		Email   string `json:"email"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	ownerID := normalizeProjectOwnerID(req.OwnerID, req.UserID, req.Subject, req.Email)
	if ownerID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "owner_id, user_id, subject, or email is required")
		return
	}

	s.dataMu.Lock()
	defer s.dataMu.Unlock()

	index := -1
	for i := range s.projects {
		if s.projects[i].ID == projectID {
			index = i
			break
		}
	}
	if index < 0 {
		writeError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}

	updatedProject := s.projects[index]
	updatedProject.OwnerID = ownerID
	if s.store != nil {
		persisted, err := s.store.UpdateProjectOwner(projectID, ownerID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to persist project owner")
			return
		}
		updatedProject = persisted
	}
	s.projects[index] = updatedProject
	s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "project_owner_assigned", updatedProject.ID, ownerID))
	writeJSON(w, http.StatusOK, updatedProject)
}

func normalizeProjectOwnerID(ownerID, userID, subject, email string) string {
	if v := strings.TrimSpace(ownerID); v != "" {
		return strings.ToLower(v)
	}
	if v := strings.TrimSpace(userID); v != "" {
		return "user:" + strings.ToLower(v)
	}
	if v := strings.TrimSpace(subject); v != "" {
		return "sub:" + strings.ToLower(v)
	}
	if v := strings.TrimSpace(strings.ToLower(email)); v != "" {
		return "email:" + v
	}
	return ""
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/scans")
	pathSuffix = strings.Trim(pathSuffix, "/")

	switch r.Method {
	case http.MethodGet:
		principal, err := s.requestPrincipal(r)
		if err != nil {
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
			s.handleScanReport(w, r, scanID, principal)
			return
		}

		s.dataMu.RLock()
		scans := append([]ScanSummary(nil), s.scans...)
		s.dataMu.RUnlock()

		if strings.TrimSpace(pathSuffix) != "" {
			for _, scan := range scans {
				if scan.ID == pathSuffix && principal.canAccessOwner(scan.OwnerID) {
					writeJSON(w, http.StatusOK, scan)
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}

		if principal.enforceOwnership() {
			filtered := make([]ScanSummary, 0, len(scans))
			for _, scan := range scans {
				if principal.canAccessOwner(scan.OwnerID) {
					filtered = append(filtered, scan)
				}
			}
			scans = filtered
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
		principal, err := s.requestPrincipal(r)
		if err != nil {
			writeUnauthorized(w, err.Error())
			return
		}
		if strings.TrimSpace(pathSuffix) != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		if principal.Role == RoleViewer {
			writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		var req CreateScanRequest
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		normalized, ok := validateCreateScanRequest(req)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_payload", "invalid scan payload")
			return
		}

		idempotencyKey, hasIdempotency, idempotencyKeyValid := parseIdempotencyKey(r.Header.Get("Idempotency-Key"))
		if !idempotencyKeyValid {
			writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "invalid Idempotency-Key header")
			return
		}
		idempotencyScope := ""
		requestHash := ""
		if hasIdempotency {
			idempotencyScope = buildScanIdempotencyScope(r, principal.AuthSource)
			requestHash = hashCreateScanRequest(normalized)
		}

		projectExists := false
		projectAccessible := false
		projectOwnerID := ""
		s.dataMu.RLock()
		for _, project := range s.projects {
			if project.ID == normalized.ProjectID {
				projectExists = true
				projectOwnerID = strings.TrimSpace(project.OwnerID)
				if principal.canAccessOwner(project.OwnerID) {
					projectAccessible = true
				}
				break
			}
		}
		s.dataMu.RUnlock()
		if !projectExists {
			writeError(w, http.StatusBadRequest, "bad_request", "project_id does not exist")
			return
		}
		if principal.enforceOwnership() && !projectAccessible {
			writeError(w, http.StatusForbidden, "forbidden", "project access denied")
			return
		}

		scan := ScanSummary{
			ID:         normalized.ID,
			ProjectID:  normalized.ProjectID,
			CommitSHA:  normalized.CommitSHA,
			Status:     normalized.Status,
			Violations: normalized.Violations,
			CreatedAt:  time.Now().UTC(),
			OwnerID:    projectOwnerID,
		}
		if scan.ID == "" {
			scan.ID = randomToken(8)
		}

		s.dataMu.Lock()
		if hasIdempotency {
			s.pruneScanIdempotencyLocked(scan.CreatedAt)
			mapKey := scanIdempotencyMapKey(idempotencyScope, idempotencyKey)
			if entry, exists := s.scanIdempotency[mapKey]; exists {
				if entry.RequestHash != requestHash {
					s.dataMu.Unlock()
					writeError(w, http.StatusConflict, "idempotency_conflict", "Idempotency-Key already used for a different scan payload")
					return
				}
				replayed := entry.Scan
				s.dataMu.Unlock()
				w.Header().Set("X-Idempotency-Replayed", "true")
				writeJSON(w, http.StatusCreated, replayed)
				return
			}
		}
		if s.store != nil {
			if err := s.store.UpsertScan(scan); err != nil {
				s.dataMu.Unlock()
				writeError(w, http.StatusInternalServerError, "system_error", "unable to persist scan")
				return
			}
		}
		s.scans = append([]ScanSummary{scan}, s.scans...)
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "scan_uploaded", scan.ProjectID, scan.ID))
		if strings.EqualFold(scan.Status, "fail") {
			s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "enforcement_failed", scan.ProjectID, scan.ID))
		}
		if hasIdempotency {
			if s.scanIdempotency == nil {
				s.scanIdempotency = map[string]scanIdempotencyEntry{}
			}
			s.scanIdempotency[scanIdempotencyMapKey(idempotencyScope, idempotencyKey)] = scanIdempotencyEntry{
				RequestHash: requestHash,
				Scan:        scan,
				CreatedAt:   scan.CreatedAt,
			}
		}
		s.dataMu.Unlock()

		writeJSON(w, http.StatusCreated, scan)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

type scanIdempotencyEntry struct {
	RequestHash string
	Scan        ScanSummary
	CreatedAt   time.Time
}

func validateCreateScanRequest(req CreateScanRequest) (CreateScanRequest, bool) {
	normalized := CreateScanRequest{
		ID:         strings.TrimSpace(req.ID),
		ProjectID:  strings.TrimSpace(req.ProjectID),
		CommitSHA:  strings.TrimSpace(req.CommitSHA),
		Status:     strings.ToLower(strings.TrimSpace(req.Status)),
		Violations: make([]ScanViolation, 0, len(req.Violations)),
	}
	if normalized.ProjectID == "" || len(normalized.ProjectID) > 128 {
		return CreateScanRequest{}, false
	}
	if len(normalized.ID) > 128 || strings.ContainsAny(normalized.ID, " \t\r\n") {
		return CreateScanRequest{}, false
	}
	if len(normalized.CommitSHA) > 128 || strings.ContainsAny(normalized.CommitSHA, " \t\r\n") {
		return CreateScanRequest{}, false
	}
	if normalized.Status == "" {
		normalized.Status = "pass"
	}
	if normalized.Status != "pass" && normalized.Status != "fail" && normalized.Status != "warn" {
		return CreateScanRequest{}, false
	}
	if len(req.Violations) > 500 {
		return CreateScanRequest{}, false
	}
	for _, item := range req.Violations {
		policyID := strings.TrimSpace(item.PolicyID)
		if policyID == "" || len(policyID) > 128 {
			return CreateScanRequest{}, false
		}
		severity := strings.ToLower(strings.TrimSpace(item.Severity))
		if severity == "" {
			severity = "block"
		}
		if severity != "block" && severity != "warn" && severity != "info" {
			return CreateScanRequest{}, false
		}
		message := strings.TrimSpace(item.Message)
		if message == "" || len(message) > 2048 {
			return CreateScanRequest{}, false
		}
		normalized.Violations = append(normalized.Violations, ScanViolation{
			PolicyID: policyID,
			Severity: severity,
			Message:  message,
		})
	}
	return normalized, true
}

func parseIdempotencyKey(raw string) (string, bool, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, true
	}
	if len(trimmed) > 128 {
		return "", false, false
	}
	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_' || ch == '.' || ch == ':':
		default:
			return "", false, false
		}
	}
	return trimmed, true, true
}

func buildScanIdempotencyScope(r *http.Request, authSource string) string {
	switch strings.TrimSpace(authSource) {
	case "api_key":
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if token := strings.TrimSpace(parts[1]); token != "" {
				return "api_key:" + legacyAPIKeyHash(token)
			}
		}
	case "session":
		if cookie, err := r.Cookie(dashboardSessionCookieName); err == nil && cookie != nil {
			if token := strings.TrimSpace(cookie.Value); token != "" {
				return "session:" + legacyAPIKeyHash(token)
			}
		}
	}
	return "remote:" + strings.TrimSpace(r.RemoteAddr)
}

func hashCreateScanRequest(req CreateScanRequest) string {
	payload, _ := json.Marshal(req)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func scanIdempotencyMapKey(scope, key string) string {
	return strings.TrimSpace(scope) + "|" + strings.TrimSpace(key)
}

func (s *Server) pruneScanIdempotencyLocked(now time.Time) {
	if s == nil {
		return
	}
	if now.Sub(s.scanIdempotencySweep) < 1*time.Minute {
		return
	}
	ttl := s.scanIdempotencyTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	for key, entry := range s.scanIdempotency {
		if entry.CreatedAt.IsZero() || now.Sub(entry.CreatedAt) > ttl {
			delete(s.scanIdempotency, key)
		}
	}
	s.scanIdempotencySweep = now
}

func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request, scanID string, principal authPrincipal) {
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
	if !principal.canAccessOwner(scan.OwnerID) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	fileBase := reportFileBase(scan.ID)

	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileBase+`.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileBase+`.txt"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(renderScanTextReport(*scan)))
	case "sarif":
		w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileBase+`.sarif"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(renderScanSARIF(*scan))
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "unsupported report format; use json|text|sarif")
	}
}

func reportFileBase(scanID string) string {
	trimmed := strings.TrimSpace(scanID)
	if trimmed == "" {
		return "baseline-scan"
	}
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		default:
			return '-'
		}
	}, trimmed)
	return "baseline-scan-" + sanitized
}
