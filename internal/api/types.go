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
	RepositoryURL string `json:"repository_url,omitempty"`
	DefaultBranch string `json:"default_branch"`
	PolicySet     string `json:"policy_set"`
}

// ScanViolation captures one policy violation in a scan report.
type ScanViolation struct {
	PolicyID string `json:"policy_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ScanSummary is the API scan model.
type ScanSummary struct {
	ID         string          `json:"id"`
	ProjectID  string          `json:"project_id,omitempty"`
	CommitSHA  string          `json:"commit_sha,omitempty"`
	Status     string          `json:"status"`
	Violations []ScanViolation `json:"violations"`
	CreatedAt  time.Time       `json:"created_at"`
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

// PolicyVersion is an immutable policy version payload.
type PolicyVersion struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description,omitempty"`
	Content     map[string]any         `json:"content,omitempty"`
	PublishedAt time.Time              `json:"published_at"`
	PublishedBy string                 `json:"published_by,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicySummary is a compact policy listing model.
type PolicySummary struct {
	Name          string    `json:"name"`
	LatestVersion string    `json:"latest_version"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// RulesetVersion is an immutable ruleset version payload.
type RulesetVersion struct {
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	PolicyNames []string  `json:"policy_names,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

// AuditEvent is a compact audit event view.
type AuditEvent struct {
	EventType string    `json:"event_type"`
	ProjectID string    `json:"project_id,omitempty"`
	ScanID    string    `json:"scan_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKeyMetadata is a non-secret view of one API key.
type APIKeyMetadata struct {
	ID        string     `json:"id"`
	Name      string     `json:"name,omitempty"`
	Role      Role       `json:"role"`
	Prefix    string     `json:"prefix"`
	Source    string     `json:"source,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by,omitempty"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

const (
	IntegrationJobPending   = "pending"
	IntegrationJobRunning   = "running"
	IntegrationJobSucceeded = "succeeded"
	IntegrationJobFailed    = "failed"
)

// IntegrationJob is a persisted asynchronous integration task.
type IntegrationJob struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`
	JobType       string    `json:"job_type"`
	ProjectRef    string    `json:"project_ref,omitempty"`
	ExternalRef   string    `json:"external_ref,omitempty"`
	Payload       string    `json:"payload,omitempty"`
	Status        string    `json:"status"`
	AttemptCount  int       `json:"attempt_count"`
	MaxAttempts   int       `json:"max_attempts"`
	LastError     string    `json:"last_error,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
