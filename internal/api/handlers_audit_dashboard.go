package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	s.dataMu.RLock()
	projects := append([]Project(nil), s.projects...)
	scans := append([]ScanSummary(nil), s.scans...)
	events := append([]AuditEvent(nil), s.events...)
	s.dataMu.RUnlock()

	if principal.enforceOwnership() {
		allowedProjects := map[string]struct{}{}
		filteredProjects := make([]Project, 0, len(projects))
		for _, project := range projects {
			if principal.canAccessOwner(project.OwnerID) {
				filteredProjects = append(filteredProjects, project)
				allowedProjects[project.ID] = struct{}{}
			}
		}
		projects = filteredProjects

		filteredScans := make([]ScanSummary, 0, len(scans))
		for _, scan := range scans {
			if principal.canAccessOwner(scan.OwnerID) {
				filteredScans = append(filteredScans, scan)
			}
		}
		scans = filteredScans

		if principal.AuthSource == "session" {
			filteredEvents := make([]AuditEvent, 0, len(events))
			for _, event := range events {
				if strings.TrimSpace(event.ProjectID) == "" {
					filteredEvents = append(filteredEvents, event)
					continue
				}
				if _, ok := allowedProjects[event.ProjectID]; ok {
					filteredEvents = append(filteredEvents, event)
				}
			}
			events = filteredEvents
		}
	}

	metrics := DashboardMetrics{
		Projects: len(projects),
		Scans:    len(scans),
	}

	violationCounts := map[string]int{}
	for _, scan := range scans {
		if strings.EqualFold(strings.TrimSpace(scan.Status), "fail") {
			metrics.FailingScans++
		}
		for _, violation := range scan.Violations {
			if strings.EqualFold(strings.TrimSpace(violation.Severity), "block") {
				metrics.BlockingViolations++
			}
			policyID := strings.TrimSpace(violation.PolicyID)
			if policyID != "" {
				violationCounts[policyID]++
			}
		}
	}

	sort.Slice(scans, func(i, j int) bool {
		return scans[i].CreatedAt.After(scans[j].CreatedAt)
	})
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})

	topViolations := make([]DashboardViolationCount, 0, len(violationCounts))
	for policyID, count := range violationCounts {
		topViolations = append(topViolations, DashboardViolationCount{
			PolicyID: policyID,
			Count:    count,
		})
	}
	sort.Slice(topViolations, func(i, j int) bool {
		if topViolations[i].Count == topViolations[j].Count {
			return topViolations[i].PolicyID < topViolations[j].PolicyID
		}
		return topViolations[i].Count > topViolations[j].Count
	})

	const recentScansLimit = 12
	const topViolationsLimit = 8
	const recentEventsLimit = 20
	if len(scans) > recentScansLimit {
		scans = scans[:recentScansLimit]
	}
	if len(topViolations) > topViolationsLimit {
		topViolations = topViolations[:topViolationsLimit]
	}
	if len(events) > recentEventsLimit {
		events = events[:recentEventsLimit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"metrics":        metrics,
		"recent_scans":   scans,
		"top_violations": topViolations,
		"recent_events":  events,
	})
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	limitRaw := strings.TrimSpace(r.URL.Query().Get("limit"))

	s.dataMu.RLock()
	events := append([]AuditEvent(nil), s.events...)
	projects := append([]Project(nil), s.projects...)
	s.dataMu.RUnlock()

	if principal.enforceOwnership() {
		allowedProjects := map[string]struct{}{}
		for _, project := range projects {
			if principal.canAccessOwner(project.OwnerID) {
				allowedProjects[project.ID] = struct{}{}
			}
		}
		if principal.AuthSource == "session" {
			filtered := make([]AuditEvent, 0, len(events))
			for _, event := range events {
				if strings.TrimSpace(event.ProjectID) == "" {
					filtered = append(filtered, event)
					continue
				}
				if _, ok := allowedProjects[event.ProjectID]; ok {
					filtered = append(filtered, event)
				}
			}
			events = filtered
		}
	}

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
