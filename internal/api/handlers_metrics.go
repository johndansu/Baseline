package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type dashboardEndpointMetrics struct {
	RequestTotal      int64
	ErrorTotal        int64
	AuthFailuresTotal int64
	DurationSeconds   float64
	DurationCount     int64
	StatusClassTotals map[string]int64
}

type dashboardMetricsSample struct {
	Endpoint          string
	RequestTotal      int64
	ErrorTotal        int64
	AuthFailuresTotal int64
	DurationSeconds   float64
	DurationCount     int64
	StatusClassTotals map[string]int64
}

type metricsSnapshot struct {
	projects           int
	scans              int
	failingScans       int
	blockingViolations int
	auditEvents        int
	activeAPIKeys      int
	revokedAPIKeys     int
	activeSessions     int
	dashboardEndpoints []dashboardMetricsSample
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	snapshot := s.captureMetricsSnapshot()

	var builder strings.Builder
	builder.WriteString("# HELP baseline_projects_total Total number of projects currently loaded.\n")
	builder.WriteString("# TYPE baseline_projects_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_projects_total %d\n", snapshot.projects))

	builder.WriteString("# HELP baseline_scans_total Total number of scans currently loaded.\n")
	builder.WriteString("# TYPE baseline_scans_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_scans_total %d\n", snapshot.scans))

	builder.WriteString("# HELP baseline_failing_scans_total Total number of failing scans currently loaded.\n")
	builder.WriteString("# TYPE baseline_failing_scans_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_failing_scans_total %d\n", snapshot.failingScans))

	builder.WriteString("# HELP baseline_blocking_violations_total Total number of blocking violations across loaded scans.\n")
	builder.WriteString("# TYPE baseline_blocking_violations_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_blocking_violations_total %d\n", snapshot.blockingViolations))

	builder.WriteString("# HELP baseline_audit_events_total Total number of retained audit events.\n")
	builder.WriteString("# TYPE baseline_audit_events_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_audit_events_total %d\n", snapshot.auditEvents))

	builder.WriteString("# HELP baseline_api_keys_active_total Total number of active API keys.\n")
	builder.WriteString("# TYPE baseline_api_keys_active_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_api_keys_active_total %d\n", snapshot.activeAPIKeys))

	builder.WriteString("# HELP baseline_api_keys_revoked_total Total number of revoked API keys.\n")
	builder.WriteString("# TYPE baseline_api_keys_revoked_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_api_keys_revoked_total %d\n", snapshot.revokedAPIKeys))

	builder.WriteString("# HELP baseline_dashboard_sessions_active_total Total number of active dashboard sessions.\n")
	builder.WriteString("# TYPE baseline_dashboard_sessions_active_total gauge\n")
	builder.WriteString(fmt.Sprintf("baseline_dashboard_sessions_active_total %d\n", snapshot.activeSessions))

	builder.WriteString("# HELP baseline_dashboard_requests_total Total number of dashboard API requests by endpoint and status class.\n")
	builder.WriteString("# TYPE baseline_dashboard_requests_total counter\n")
	for _, endpoint := range snapshot.dashboardEndpoints {
		statusClasses := sortedDashboardMetricClassKeys(endpoint.StatusClassTotals)
		for _, classLabel := range statusClasses {
			total := endpoint.StatusClassTotals[classLabel]
			builder.WriteString(fmt.Sprintf("baseline_dashboard_requests_total{endpoint=\"%s\",status_class=\"%s\"} %d\n",
				prometheusLabelEscape(endpoint.Endpoint), prometheusLabelEscape(classLabel), total))
		}
	}

	builder.WriteString("# HELP baseline_dashboard_request_duration_seconds_sum Cumulative dashboard API request duration in seconds by endpoint.\n")
	builder.WriteString("# TYPE baseline_dashboard_request_duration_seconds_sum counter\n")
	for _, endpoint := range snapshot.dashboardEndpoints {
		builder.WriteString(fmt.Sprintf("baseline_dashboard_request_duration_seconds_sum{endpoint=\"%s\"} %.6f\n",
			prometheusLabelEscape(endpoint.Endpoint), endpoint.DurationSeconds))
	}

	builder.WriteString("# HELP baseline_dashboard_request_duration_seconds_count Total number of observed dashboard API request durations by endpoint.\n")
	builder.WriteString("# TYPE baseline_dashboard_request_duration_seconds_count counter\n")
	for _, endpoint := range snapshot.dashboardEndpoints {
		builder.WriteString(fmt.Sprintf("baseline_dashboard_request_duration_seconds_count{endpoint=\"%s\"} %d\n",
			prometheusLabelEscape(endpoint.Endpoint), endpoint.DurationCount))
	}

	builder.WriteString("# HELP baseline_dashboard_request_errors_total Total number of dashboard API requests with HTTP status >= 400 by endpoint.\n")
	builder.WriteString("# TYPE baseline_dashboard_request_errors_total counter\n")
	for _, endpoint := range snapshot.dashboardEndpoints {
		builder.WriteString(fmt.Sprintf("baseline_dashboard_request_errors_total{endpoint=\"%s\"} %d\n",
			prometheusLabelEscape(endpoint.Endpoint), endpoint.ErrorTotal))
	}

	builder.WriteString("# HELP baseline_dashboard_auth_failures_total Total number of dashboard API requests with HTTP 401 responses by endpoint.\n")
	builder.WriteString("# TYPE baseline_dashboard_auth_failures_total counter\n")
	for _, endpoint := range snapshot.dashboardEndpoints {
		builder.WriteString(fmt.Sprintf("baseline_dashboard_auth_failures_total{endpoint=\"%s\"} %d\n",
			prometheusLabelEscape(endpoint.Endpoint), endpoint.AuthFailuresTotal))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(builder.String()))
}

func (s *Server) captureMetricsSnapshot() metricsSnapshot {
	snapshot := metricsSnapshot{}

	s.dataMu.RLock()
	snapshot.projects = len(s.projects)
	snapshot.scans = len(s.scans)
	snapshot.auditEvents = len(s.events)
	for _, scan := range s.scans {
		if strings.EqualFold(strings.TrimSpace(scan.Status), "fail") {
			snapshot.failingScans++
		}
		for _, violation := range scan.Violations {
			if strings.EqualFold(strings.TrimSpace(violation.Severity), "block") {
				snapshot.blockingViolations++
			}
		}
	}
	s.dataMu.RUnlock()

	s.authMu.RLock()
	for _, metadata := range s.keysByID {
		if metadata.Revoked {
			snapshot.revokedAPIKeys++
			continue
		}
		snapshot.activeAPIKeys++
	}
	s.authMu.RUnlock()

	now := time.Now().UTC()
	if s.store != nil {
		if count, err := s.store.CountActiveAuthSessions(now); err == nil {
			snapshot.activeSessions = count
			return snapshot
		}
	}

	s.sessionMu.RLock()
	for _, session := range s.sessions {
		if now.Before(session.ExpiresAt) {
			snapshot.activeSessions++
		}
	}
	s.sessionMu.RUnlock()
	snapshot.dashboardEndpoints = s.captureDashboardMetricsSamples()

	return snapshot
}

func (s *Server) captureDashboardMetricsSamples() []dashboardMetricsSample {
	s.dashboardMetricsMu.Lock()
	defer s.dashboardMetricsMu.Unlock()

	samples := make([]dashboardMetricsSample, 0, len(s.dashboardMetrics))
	for endpoint, item := range s.dashboardMetrics {
		copiedStatusClasses := make(map[string]int64, len(item.StatusClassTotals))
		for classLabel, total := range item.StatusClassTotals {
			copiedStatusClasses[classLabel] = total
		}
		samples = append(samples, dashboardMetricsSample{
			Endpoint:          endpoint,
			RequestTotal:      item.RequestTotal,
			ErrorTotal:        item.ErrorTotal,
			AuthFailuresTotal: item.AuthFailuresTotal,
			DurationSeconds:   item.DurationSeconds,
			DurationCount:     item.DurationCount,
			StatusClassTotals: copiedStatusClasses,
		})
	}

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Endpoint < samples[j].Endpoint
	})
	return samples
}

func (s *Server) recordDashboardRequestMetrics(path string, statusCode int, duration time.Duration) {
	if !strings.HasPrefix(path, "/v1/dashboard") {
		return
	}
	endpoint := normalizeDashboardMetricsEndpoint(path)
	if endpoint == "" {
		return
	}
	classLabel := dashboardStatusClassLabel(statusCode)

	s.dashboardMetricsMu.Lock()
	defer s.dashboardMetricsMu.Unlock()

	entry := s.dashboardMetrics[endpoint]
	if entry == nil {
		entry = &dashboardEndpointMetrics{
			StatusClassTotals: map[string]int64{},
		}
		s.dashboardMetrics[endpoint] = entry
	}
	entry.RequestTotal++
	entry.DurationSeconds += duration.Seconds()
	entry.DurationCount++
	entry.StatusClassTotals[classLabel]++
	if statusCode >= http.StatusBadRequest {
		entry.ErrorTotal++
	}
	if statusCode == http.StatusUnauthorized {
		entry.AuthFailuresTotal++
	}
}

func normalizeDashboardMetricsEndpoint(path string) string {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return ""
	}
	if normalized == "/v1/dashboard/" {
		return "/v1/dashboard"
	}
	return normalized
}

func dashboardStatusClassLabel(statusCode int) string {
	switch {
	case statusCode >= 500:
		return "5xx"
	case statusCode >= 400:
		return "4xx"
	case statusCode >= 300:
		return "3xx"
	case statusCode >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func sortedDashboardMetricClassKeys(values map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func prometheusLabelEscape(raw string) string {
	safe := strings.ReplaceAll(raw, "\\", "\\\\")
	return strings.ReplaceAll(safe, "\"", "\\\"")
}
