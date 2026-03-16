package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type dashboardActivityRange string

const (
	dashboardActivityRangeLastWeek  dashboardActivityRange = "last_week"
	dashboardActivityRangeToday     dashboardActivityRange = "today"
	dashboardActivityRangeLastMonth dashboardActivityRange = "last_month"
	dashboardActivityRangeLastYear  dashboardActivityRange = "last_year"
)

func (s *Server) handleDashboardStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if _, err := s.requestPrincipal(r); err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "system_error", "streaming not supported")
		return
	}
	if controller := http.NewResponseController(w); controller != nil {
		_ = controller.SetWriteDeadline(time.Time{})
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	stream := s.subscribeDashboardStream()
	defer s.unsubscribeDashboardStream(stream)

	fmt.Fprint(w, "event: ready\ndata: connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-stream:
			fmt.Fprint(w, "event: refresh\ndata: update\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleDashboardCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"role":         principal.Role,
		"source":       principal.AuthSource,
		"capabilities": dashboardCapabilitiesForRole(principal.Role),
	})
}

func dashboardCapabilitiesForRole(role Role) map[string]bool {
	capabilities := map[string]bool{
		"dashboard.view": true,
		"projects.read":  true,
		"projects.write": false,
		"scans.read":     true,
		"scans.run":      false,
		"api_keys.read":  true,
		// Self-service API key lifecycle is available for authenticated users.
		"api_keys.write":             true,
		"audit.read":                 true,
		"integrations.read":          false,
		"integrations.write":         false,
		"integrations.secrets.write": false,
	}

	switch role {
	case RoleOperator:
		capabilities["projects.write"] = true
		capabilities["scans.run"] = true
		capabilities["integrations.read"] = true
		capabilities["integrations.write"] = true
	case RoleAdmin:
		capabilities["projects.write"] = true
		capabilities["scans.run"] = true
		capabilities["integrations.read"] = true
		capabilities["integrations.write"] = true
		capabilities["integrations.secrets.write"] = true
	}

	return capabilities
}

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

	activityRange := parseDashboardActivityRange(r.URL.Query().Get("activity_range"))
	activityWindow, activityIndex := buildDashboardActivityWindow(time.Now().UTC(), activityRange)

	violationCounts := map[string]int{}
	for _, scan := range scans {
		if strings.EqualFold(strings.TrimSpace(scan.Status), "fail") {
			metrics.FailingScans++
		}
		activityKey := dashboardActivityBucketKey(scan.CreatedAt.UTC(), activityRange)
		if idx, ok := activityIndex[activityKey]; ok {
			activityWindow[idx].Scans++
			if strings.EqualFold(strings.TrimSpace(scan.Status), "fail") {
				activityWindow[idx].FailingScans++
			}
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
		"activity_range": activityRange,
		"scan_activity":  activityWindow,
		"recent_scans":   scans,
		"top_violations": topViolations,
		"recent_events":  events,
	})
}

func parseDashboardActivityRange(raw string) dashboardActivityRange {
	switch dashboardActivityRange(strings.TrimSpace(strings.ToLower(raw))) {
	case dashboardActivityRangeToday:
		return dashboardActivityRangeToday
	case dashboardActivityRangeLastMonth:
		return dashboardActivityRangeLastMonth
	case dashboardActivityRangeLastYear:
		return dashboardActivityRangeLastYear
	default:
		return dashboardActivityRangeLastWeek
	}
}

func buildDashboardActivityWindow(now time.Time, activityRange dashboardActivityRange) ([]DashboardScanActivityPoint, map[string]int) {
	now = now.UTC()
	switch activityRange {
	case dashboardActivityRangeToday:
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		points := make([]DashboardScanActivityPoint, 0, 24)
		index := make(map[string]int, 24)
		for i := 0; i < 24; i++ {
			hour := start.Add(time.Duration(i) * time.Hour)
			key := hour.Format("2006-01-02T15")
			index[key] = len(points)
			points = append(points, DashboardScanActivityPoint{
				Date:  key,
				Label: hour.Format("15:00"),
			})
		}
		return points, index
	case dashboardActivityRangeLastMonth:
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		points := make([]DashboardScanActivityPoint, 0, 30)
		index := make(map[string]int, 30)
		for i := 29; i >= 0; i-- {
			day := today.AddDate(0, 0, -i)
			key := day.Format("2006-01-02")
			index[key] = len(points)
			points = append(points, DashboardScanActivityPoint{
				Date:  key,
				Label: day.Format("2 Jan"),
			})
		}
		return points, index
	case dashboardActivityRangeLastYear:
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		points := make([]DashboardScanActivityPoint, 0, 12)
		index := make(map[string]int, 12)
		for i := 11; i >= 0; i-- {
			month := monthStart.AddDate(0, -i, 0)
			key := month.Format("2006-01")
			index[key] = len(points)
			points = append(points, DashboardScanActivityPoint{
				Date:  key,
				Label: month.Format("Jan"),
			})
		}
		return points, index
	default:
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		points := make([]DashboardScanActivityPoint, 0, 7)
		index := make(map[string]int, 7)
		for i := 6; i >= 0; i-- {
			day := today.AddDate(0, 0, -i)
			key := day.Format("2006-01-02")
			index[key] = len(points)
			points = append(points, DashboardScanActivityPoint{
				Date:  key,
				Label: day.Format("Mon"),
			})
		}
		return points, index
	}
}

func dashboardActivityBucketKey(ts time.Time, activityRange dashboardActivityRange) string {
	switch activityRange {
	case dashboardActivityRangeToday:
		return ts.UTC().Format("2006-01-02T15")
	case dashboardActivityRangeLastYear:
		return ts.UTC().Format("2006-01")
	default:
		return ts.UTC().Format("2006-01-02")
	}
}

func (s *Server) handleDashboardActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	limit := 20
	limitRaw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if limitRaw != "" {
		parsed, parseErr := strconv.Atoi(limitRaw)
		if parseErr != nil || parsed <= 0 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be an integer between 1 and 100")
			return
		}
		limit = parsed
	}

	activityType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if activityType != "" && activityType != "scan" && activityType != "audit" && activityType != "integration" {
		writeError(w, http.StatusBadRequest, "bad_request", "type must be one of scan|audit|integration")
		return
	}
	actor := strings.TrimSpace(r.URL.Query().Get("actor"))

	var from *time.Time
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	if fromRaw != "" {
		parsed, parseErr := time.Parse(time.RFC3339, fromRaw)
		if parseErr != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "from must be RFC3339")
			return
		}
		t := parsed.UTC()
		from = &t
	}
	var to *time.Time
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if toRaw != "" {
		parsed, parseErr := time.Parse(time.RFC3339, toRaw)
		if parseErr != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "to must be RFC3339")
			return
		}
		t := parsed.UTC()
		to = &t
	}
	if from != nil && to != nil && from.After(*to) {
		writeError(w, http.StatusBadRequest, "bad_request", "from must be before or equal to to")
		return
	}

	cursor, cursorProvided, cursorErr := parseDashboardActivityCursor(strings.TrimSpace(r.URL.Query().Get("cursor")))
	if cursorErr != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid cursor")
		return
	}

	s.dataMu.RLock()
	projects := append([]Project(nil), s.projects...)
	scans := append([]ScanSummary(nil), s.scans...)
	events := append([]AuditEvent(nil), s.events...)
	s.dataMu.RUnlock()

	allowedProjects := map[string]struct{}{}
	if principal.enforceOwnership() {
		for _, project := range projects {
			if principal.canAccessOwner(project.OwnerID) {
				allowedProjects[project.ID] = struct{}{}
			}
		}
	}

	items := make([]DashboardActivityItem, 0, len(scans)+len(events))

	for _, scan := range scans {
		if principal.enforceOwnership() && !principal.canAccessOwner(scan.OwnerID) {
			continue
		}
		items = append(items, DashboardActivityItem{
			ID:        "scan:" + scan.ID,
			Type:      "scan",
			Action:    "scan_" + strings.ToLower(strings.TrimSpace(scan.Status)),
			Status:    strings.ToLower(strings.TrimSpace(scan.Status)),
			ProjectID: scan.ProjectID,
			ScanID:    scan.ID,
			Actor:     strings.TrimSpace(scan.OwnerID),
			CreatedAt: scan.CreatedAt.UTC(),
		})
	}

	for i, event := range events {
		eventType := strings.TrimSpace(event.EventType)
		itemType := "audit"
		if strings.HasPrefix(strings.ToLower(eventType), "integration_") {
			itemType = "integration"
		}
		if principal.enforceOwnership() && strings.TrimSpace(event.ProjectID) != "" {
			if _, ok := allowedProjects[event.ProjectID]; !ok {
				continue
			}
		}
		items = append(items, DashboardActivityItem{
			ID:        fmt.Sprintf("audit:%d:%d", event.CreatedAt.UTC().UnixNano(), i),
			Type:      itemType,
			Action:    eventType,
			ProjectID: strings.TrimSpace(event.ProjectID),
			ScanID:    strings.TrimSpace(event.ScanID),
			Actor:     strings.TrimSpace(event.Actor),
			Details:   strings.TrimSpace(event.Details),
			RequestID: strings.TrimSpace(event.RequestID),
			CreatedAt: event.CreatedAt.UTC(),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	filtered := make([]DashboardActivityItem, 0, len(items))
	for _, item := range items {
		if activityType != "" && item.Type != activityType {
			continue
		}
		if actor != "" && !strings.EqualFold(strings.TrimSpace(item.Actor), actor) {
			continue
		}
		if from != nil && item.CreatedAt.Before(*from) {
			continue
		}
		if to != nil && item.CreatedAt.After(*to) {
			continue
		}
		if cursorProvided && !itemAfterDashboardActivityCursor(item, cursor) {
			continue
		}
		filtered = append(filtered, item)
	}

	nextCursor := ""
	if len(filtered) > limit {
		last := filtered[limit-1]
		nextCursor = encodeDashboardActivityCursor(last.CreatedAt, last.ID)
		filtered = filtered[:limit]
	}

	writeJSON(w, http.StatusOK, DashboardActivityResponse{
		Items:      filtered,
		NextCursor: nextCursor,
	})
}

type dashboardActivityCursor struct {
	CreatedAt time.Time
	ID        string
}

func parseDashboardActivityCursor(raw string) (dashboardActivityCursor, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return dashboardActivityCursor{}, false, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return dashboardActivityCursor{}, false, err
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return dashboardActivityCursor{}, false, fmt.Errorf("malformed cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(parts[0]))
	if err != nil {
		return dashboardActivityCursor{}, false, err
	}
	id := strings.TrimSpace(parts[1])
	if id == "" {
		return dashboardActivityCursor{}, false, fmt.Errorf("missing cursor id")
	}
	return dashboardActivityCursor{CreatedAt: createdAt.UTC(), ID: id}, true, nil
}

func encodeDashboardActivityCursor(createdAt time.Time, id string) string {
	payload := createdAt.UTC().Format(time.RFC3339Nano) + "|" + strings.TrimSpace(id)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func itemAfterDashboardActivityCursor(item DashboardActivityItem, cursor dashboardActivityCursor) bool {
	if item.CreatedAt.Before(cursor.CreatedAt) {
		return true
	}
	if item.CreatedAt.After(cursor.CreatedAt) {
		return false
	}
	return item.ID < cursor.ID
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
