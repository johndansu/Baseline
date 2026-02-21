package api

import (
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
