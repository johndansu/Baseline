package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const cliTelemetryRetention = 180 * 24 * time.Hour

type createCLIEventRequest struct {
	EventType      string `json:"event_type"`
	Command        string `json:"command"`
	Repository     string `json:"repository,omitempty"`
	Message        string `json:"message,omitempty"`
	Status         string `json:"status,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	ScanID         string `json:"scan_id,omitempty"`
	Version        string `json:"version,omitempty"`
	FilesScanned   int    `json:"files_scanned,omitempty"`
	SecurityIssues int    `json:"security_issues,omitempty"`
	ViolationCount int    `json:"violation_count,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
	TraceID        string `json:"trace_id,omitempty"`
	SpanID         string `json:"span_id,omitempty"`
	ParentSpanID   string `json:"parent_span_id,omitempty"`
	Component      string `json:"component,omitempty"`
	Function       string `json:"function,omitempty"`
	Branch         string `json:"branch,omitempty"`
}

func (s *Server) handleCLIEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleCLIEventsList(w, r)
		return
	case http.MethodPost:
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
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

	var payload createCLIEventRequest
	if !s.decodeJSONBody(w, r, &payload) {
		return
	}

	payload.EventType = strings.ToLower(strings.TrimSpace(payload.EventType))
	if !isAllowedCLIEventType(payload.EventType) {
		writeError(w, http.StatusBadRequest, "bad_request", "event_type must start with cli_")
		return
	}
	payload.Command = strings.TrimSpace(payload.Command)
	if payload.Command == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "command is required")
		return
	}
	payload.ProjectID = strings.TrimSpace(payload.ProjectID)
	payload.ScanID = strings.TrimSpace(payload.ScanID)
	payload.Repository = strings.TrimSpace(payload.Repository)
	payload.Message = strings.TrimSpace(payload.Message)
	payload.Status = strings.TrimSpace(payload.Status)
	payload.Version = strings.TrimSpace(payload.Version)
	payload.TraceID = strings.TrimSpace(payload.TraceID)
	payload.SpanID = strings.TrimSpace(payload.SpanID)
	payload.ParentSpanID = strings.TrimSpace(payload.ParentSpanID)
	payload.Component = strings.TrimSpace(payload.Component)
	payload.Function = strings.TrimSpace(payload.Function)
	payload.Branch = strings.TrimSpace(payload.Branch)
	if payload.FilesScanned < 0 || payload.SecurityIssues < 0 || payload.ViolationCount < 0 || payload.DurationMS < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "numeric fields must be zero or greater")
		return
	}
	if payload.ProjectID != "" && !s.principalCanAttachCLIEvent(principal, payload.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden", "cannot attach CLI event to this project")
		return
	}

	event := s.newRequestAuditEvent(r, principal.AuthSource, payload.EventType, payload.ProjectID, payload.ScanID)
	event.Details = formatCLIEventDetails(payload)

	s.dataMu.Lock()
	s.appendEventLocked(event)
	s.pruneCLITelemetryLocked(time.Now().UTC().Add(-cliTelemetryRetention))
	s.dataMu.Unlock()

	writeJSON(w, http.StatusCreated, event)
}

func (s *Server) pruneCLITelemetryLocked(before time.Time) {
	filtered := make([]AuditEvent, 0, len(s.events))
	for _, event := range s.events {
		eventType := strings.ToLower(strings.TrimSpace(event.EventType))
		if strings.HasPrefix(eventType, "cli_") && event.CreatedAt.Before(before) {
			continue
		}
		filtered = append(filtered, event)
	}
	s.events = filtered
	if s.store != nil {
		_ = s.store.DeleteAuditEventsByPrefixBefore("cli_", before)
	}
}

func (s *Server) handleCLIEventsList(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}

	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, 500)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive integer up to 500")
			return
		}
		limit = parsed
	}
	commandFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("command")))
	typeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("event_type")))
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project_id"))

	s.dataMu.RLock()
	allEvents := append([]AuditEvent(nil), s.events...)
	s.dataMu.RUnlock()

	events := make([]AuditEvent, 0, len(allEvents))
	summary := map[string]any{
		"total":      0,
		"by_type":    map[string]int{},
		"by_command": map[string]int{},
	}
	for _, event := range allEvents {
		eventType := strings.ToLower(strings.TrimSpace(event.EventType))
		if !strings.HasPrefix(eventType, "cli_") {
			continue
		}
		command := cliEventField(event.Details, "command")
		status := cliEventField(event.Details, "status")
		if typeFilter != "" && eventType != typeFilter {
			continue
		}
		if commandFilter != "" && command != commandFilter {
			continue
		}
		if statusFilter != "" && status != statusFilter {
			continue
		}
		if projectFilter != "" && strings.TrimSpace(event.ProjectID) != projectFilter {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	for _, event := range events {
		eventType := strings.ToLower(strings.TrimSpace(event.EventType))
		command := cliEventField(event.Details, "command")
		summary["total"] = summary["total"].(int) + 1
		summary["by_type"].(map[string]int)[eventType]++
		if command != "" {
			summary["by_command"].(map[string]int)[command]++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"events":  events,
	})
}

func isAllowedCLIEventType(eventType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(eventType))
	return strings.HasPrefix(normalized, "cli_") && len(normalized) <= 64
}

func cliEventField(details, key string) string {
	prefix := strings.ToLower(strings.TrimSpace(key)) + " "
	for _, part := range strings.Split(strings.TrimSpace(details), "|") {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

func parsePositiveInt(raw string, max int) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, fmt.Errorf("empty")
	}
	var parsed int
	_, err := fmt.Sscanf(value, "%d", &parsed)
	if err != nil || parsed <= 0 || parsed > max {
		return 0, fmt.Errorf("invalid")
	}
	return parsed, nil
}

func (s *Server) principalCanAttachCLIEvent(principal authPrincipal, projectID string) bool {
	if strings.TrimSpace(projectID) == "" {
		return true
	}
	if !principal.enforceOwnership() {
		return true
	}

	s.dataMu.RLock()
	defer s.dataMu.RUnlock()
	for _, project := range s.projects {
		if strings.TrimSpace(project.ID) == strings.TrimSpace(projectID) {
			return principal.canAccessOwner(project.OwnerID)
		}
	}
	return false
}

func formatCLIEventDetails(payload createCLIEventRequest) string {
	parts := []string{fmt.Sprintf("command %s", payload.Command)}
	if payload.Repository != "" {
		parts = append(parts, fmt.Sprintf("repository %s", payload.Repository))
	}
	if payload.Status != "" {
		parts = append(parts, fmt.Sprintf("status %s", payload.Status))
	}
	if payload.TraceID != "" {
		parts = append(parts, fmt.Sprintf("trace %s", payload.TraceID))
	}
	if payload.Component != "" {
		parts = append(parts, fmt.Sprintf("component %s", payload.Component))
	}
	if payload.Function != "" {
		parts = append(parts, fmt.Sprintf("function %s", payload.Function))
	}
	if payload.Branch != "" {
		parts = append(parts, fmt.Sprintf("branch %s", payload.Branch))
	}
	if payload.Message != "" {
		parts = append(parts, payload.Message)
	}
	if payload.FilesScanned > 0 {
		parts = append(parts, fmt.Sprintf("files %d", payload.FilesScanned))
	}
	if payload.SecurityIssues > 0 || payload.EventType == "cli_health" || payload.EventType == "cli_warning" || payload.EventType == "cli_error" {
		parts = append(parts, fmt.Sprintf("security issues %d", payload.SecurityIssues))
	}
	if payload.ViolationCount > 0 || payload.EventType == "cli_health" || payload.EventType == "cli_warning" || payload.EventType == "cli_error" {
		parts = append(parts, fmt.Sprintf("violations %d", payload.ViolationCount))
	}
	if payload.DurationMS > 0 {
		parts = append(parts, fmt.Sprintf("duration %dms", payload.DurationMS))
	}
	if payload.Version != "" {
		parts = append(parts, fmt.Sprintf("version %s", payload.Version))
	}
	return strings.Join(parts, " | ")
}
