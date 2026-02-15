// Package api provides the Baseline HTTP API used by the CLI dashboard.
package api

import "time"

// Role controls access levels for API keys and dashboard sessions.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

func isValidRole(role Role) bool {
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// Project is a compact dashboard project model.
type Project struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	PolicySet     string `json:"policy_set"`
}

// ScanSummary is a compact dashboard scan model.
type ScanSummary struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	Violations []string  `json:"violations"`
	CreatedAt  time.Time `json:"created_at"`
}

// DashboardMetrics contains top-level dashboard counters.
type DashboardMetrics struct {
	Projects           int `json:"projects"`
	Scans              int `json:"scans"`
	FailingScans       int `json:"failing_scans"`
	BlockingViolations int `json:"blocking_violations"`
}

// DashboardViolationCount contains aggregate policy occurrences.
type DashboardViolationCount struct {
	PolicyID string `json:"policy_id"`
	Count    int    `json:"count"`
}

// AuditEvent is a compact audit event view.
type AuditEvent struct {
	EventType string    `json:"event_type"`
	CreatedAt time.Time `json:"created_at"`
}
