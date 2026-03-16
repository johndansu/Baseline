package api

import (
	"net/http"
	"strings"
	"time"
)

type createCLITraceRequest struct {
	TraceID        string                   `json:"trace_id"`
	Command        string                   `json:"command"`
	Repository     string                   `json:"repository,omitempty"`
	ProjectID      string                   `json:"project_id,omitempty"`
	ScanID         string                   `json:"scan_id,omitempty"`
	Status         string                   `json:"status,omitempty"`
	Message        string                   `json:"message,omitempty"`
	Version        string                   `json:"version,omitempty"`
	StartedAt      time.Time                `json:"started_at"`
	FinishedAt     time.Time                `json:"finished_at"`
	DurationMS     int64                    `json:"duration_ms"`
	EventCount     int                      `json:"event_count"`
	FilesScanned   int                      `json:"files_scanned,omitempty"`
	SecurityIssues int                      `json:"security_issues,omitempty"`
	ViolationCount int                      `json:"violation_count,omitempty"`
	Attributes     map[string]string        `json:"attributes,omitempty"`
	Events         []createCLITraceEventReq `json:"events"`
}

type createCLITraceEventReq struct {
	TraceID      string            `json:"trace_id,omitempty"`
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Type         string            `json:"type"`
	Component    string            `json:"component,omitempty"`
	Function     string            `json:"function,omitempty"`
	Branch       string            `json:"branch,omitempty"`
	Status       string            `json:"status,omitempty"`
	Message      string            `json:"message,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

func (s *Server) handleCLITraces(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "trace storage unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleCLITracesListOrDetail(w, r)
	case http.MethodPost:
		s.handleCLITraceCreate(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleCLITraceCreate(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}

	var req createCLITraceRequest
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	req.TraceID = strings.TrimSpace(req.TraceID)
	req.Command = strings.TrimSpace(req.Command)
	req.Repository = strings.TrimSpace(req.Repository)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.Status = strings.TrimSpace(req.Status)
	req.Message = strings.TrimSpace(req.Message)
	req.Version = strings.TrimSpace(req.Version)
	if req.TraceID == "" || req.Command == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "trace_id and command are required")
		return
	}
	if req.ProjectID != "" && !s.principalCanAttachCLIEvent(principal, req.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden", "cannot attach CLI trace to this project")
		return
	}
	if req.StartedAt.IsZero() {
		req.StartedAt = time.Now().UTC()
	}
	if req.FinishedAt.IsZero() {
		req.FinishedAt = req.StartedAt
	}
	if req.EventCount < 0 || req.DurationMS < 0 || req.FilesScanned < 0 || req.SecurityIssues < 0 || req.ViolationCount < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "numeric fields must be zero or greater")
		return
	}

	trace := CLITraceDetail{
		Summary: CLITraceSummary{
			TraceID:        req.TraceID,
			Command:        req.Command,
			Repository:     req.Repository,
			ProjectID:      req.ProjectID,
			ScanID:         req.ScanID,
			Status:         req.Status,
			Message:        req.Message,
			Version:        req.Version,
			StartedAt:      req.StartedAt.UTC(),
			FinishedAt:     req.FinishedAt.UTC(),
			DurationMS:     req.DurationMS,
			EventCount:     req.EventCount,
			FilesScanned:   req.FilesScanned,
			SecurityIssues: req.SecurityIssues,
			ViolationCount: req.ViolationCount,
			Attributes:     req.Attributes,
		},
		Events: make([]CLITraceEvent, 0, len(req.Events)),
	}
	for _, raw := range req.Events {
		eventTraceID := strings.TrimSpace(raw.TraceID)
		if eventTraceID == "" {
			eventTraceID = req.TraceID
		}
		if eventTraceID != req.TraceID {
			writeError(w, http.StatusBadRequest, "bad_request", "event trace_id must match trace_id")
			return
		}
		if strings.TrimSpace(raw.SpanID) == "" || strings.TrimSpace(raw.Type) == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "each event requires span_id and type")
			return
		}
		createdAt := raw.CreatedAt
		if createdAt.IsZero() {
			createdAt = req.StartedAt
		}
		trace.Events = append(trace.Events, CLITraceEvent{
			TraceID:      eventTraceID,
			SpanID:       strings.TrimSpace(raw.SpanID),
			ParentSpanID: strings.TrimSpace(raw.ParentSpanID),
			Type:         strings.TrimSpace(raw.Type),
			Component:    strings.TrimSpace(raw.Component),
			Function:     strings.TrimSpace(raw.Function),
			Branch:       strings.TrimSpace(raw.Branch),
			Status:       strings.TrimSpace(raw.Status),
			Message:      strings.TrimSpace(raw.Message),
			Attributes:   raw.Attributes,
			CreatedAt:    createdAt.UTC(),
		})
	}
	if trace.Summary.EventCount == 0 {
		trace.Summary.EventCount = len(trace.Events)
	}
	if err := s.store.CreateCLITrace(trace); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, trace.Summary)
}

func (s *Server) handleCLITracesListOrDetail(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/cli/traces")
	pathSuffix = strings.Trim(pathSuffix, "/")
	if pathSuffix != "" {
		trace, err := s.store.GetCLITrace(pathSuffix)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no rows") {
				writeError(w, http.StatusNotFound, "not_found", "trace not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, trace)
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
	traces, err := s.store.ListCLITraces(
		limit,
		strings.TrimSpace(r.URL.Query().Get("command")),
		strings.TrimSpace(r.URL.Query().Get("status")),
		strings.TrimSpace(r.URL.Query().Get("project_id")),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"traces": traces,
	})
}
