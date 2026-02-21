package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type metricsSnapshot struct {
	projects           int
	scans              int
	failingScans       int
	blockingViolations int
	auditEvents        int
	activeAPIKeys      int
	revokedAPIKeys     int
	activeSessions     int
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
	s.sessionMu.RLock()
	for _, session := range s.sessions {
		if now.Before(session.ExpiresAt) {
			snapshot.activeSessions++
		}
	}
	s.sessionMu.RUnlock()

	return snapshot
}
