package api

import (
	"net/http"
	"strconv"
	"strings"
)

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
