package api

import (
	"net/http"
	"strconv"
	"strings"
)

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
