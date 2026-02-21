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
			idempotencyScope = buildScanIdempotencyScope(r, authSource)
			requestHash = hashCreateScanRequest(normalized)
		}

		projectExists := false
		s.dataMu.RLock()
		for _, project := range s.projects {
			if project.ID == normalized.ProjectID {
				projectExists = true
				break
			}
		}
		s.dataMu.RUnlock()
		if !projectExists {
			writeError(w, http.StatusBadRequest, "bad_request", "project_id does not exist")
			return
		}

		scan := ScanSummary{
			ID:         normalized.ID,
			ProjectID:  normalized.ProjectID,
			CommitSHA:  normalized.CommitSHA,
			Status:     normalized.Status,
			Violations: normalized.Violations,
			CreatedAt:  time.Now().UTC(),
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
