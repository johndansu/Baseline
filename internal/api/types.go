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

// UserStatus represents the lifecycle state of an authenticated user.
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
)

func isValidUserStatus(status UserStatus) bool {
	switch status {
	case UserStatusActive, UserStatusSuspended:
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
	OwnerID       string `json:"owner_id,omitempty"`
}

// ScanViolation captures one policy violation in a scan report.
type ScanViolation struct {
	PolicyID string `json:"policy_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ScanSummary is the API scan model.
type ScanSummary struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"project_id,omitempty"`
	CommitSHA    string          `json:"commit_sha,omitempty"`
	FilesScanned int             `json:"files_scanned"`
	Status       string          `json:"status"`
	Violations   []ScanViolation `json:"violations"`
	CreatedAt    time.Time       `json:"created_at"`
	OwnerID      string          `json:"owner_id,omitempty"`
}

// CreateScanRequest is the accepted payload for POST /v1/scans.
type CreateScanRequest struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"project_id"`
	CommitSHA    string          `json:"commit_sha"`
	FilesScanned int             `json:"files_scanned"`
	Status       string          `json:"status"`
	Violations   []ScanViolation `json:"violations"`
}

// CreatePolicyVersionRequest is the accepted payload for POST /v1/policies/{name}/versions.
type CreatePolicyVersionRequest struct {
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Content     map[string]any         `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CreateRulesetRequest is the accepted payload for POST /v1/rulesets.
type CreateRulesetRequest struct {
	Version     string   `json:"version"`
	Description string   `json:"description"`
	PolicyNames []string `json:"policy_names"`
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

// DashboardScanActivityPoint contains one day of scan activity for trend charts.
type DashboardScanActivityPoint struct {
	Date         string `json:"date"`
	Label        string `json:"label"`
	Scans        int    `json:"scans"`
	FailingScans int    `json:"failing_scans"`
}

// DashboardCapabilitiesResponse provides frontend-safe feature flags
// and role/source context for the currently authenticated principal.
type DashboardCapabilitiesResponse struct {
	Role         Role            `json:"role"`
	Source       string          `json:"source"`
	Capabilities map[string]bool `json:"capabilities"`
}

// DashboardActivityItem represents one normalized dashboard feed event.
type DashboardActivityItem struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Action    string    `json:"action"`
	Status    string    `json:"status,omitempty"`
	ProjectID string    `json:"project_id,omitempty"`
	ScanID    string    `json:"scan_id,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	RequestID string    `json:"request_id,omitempty"`
}

// DashboardActivityResponse is the paginated activity feed payload.
type DashboardActivityResponse struct {
	Items      []DashboardActivityItem `json:"items"`
	NextCursor string                  `json:"next_cursor,omitempty"`
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
	Actor     string    `json:"actor,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKeyMetadata is a non-secret view of one API key.
type APIKeyMetadata struct {
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	Role             Role       `json:"role"`
	Prefix           string     `json:"prefix"`
	Source           string     `json:"source,omitempty"`
	OwnerUserID      string     `json:"owner_user_id,omitempty"`
	OwnerSubject     string     `json:"owner_subject,omitempty"`
	OwnerEmail       string     `json:"owner_email,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        string     `json:"created_by,omitempty"`
	CreatedByUserID  string     `json:"created_by_user_id,omitempty"`
	Revoked          bool       `json:"revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedByUserID  string     `json:"revoked_by_user_id,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

// UserRecord is the persisted non-secret user model for admin operations.
type UserRecord struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	Role        Role       `json:"role"`
	Status      UserStatus `json:"status"`
	LastLoginAt time.Time  `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
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

// IntegrationJobSummary is a frontend-safe view of one integration job.
type IntegrationJobSummary struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`
	JobType       string    `json:"job_type"`
	ProjectRef    string    `json:"project_ref,omitempty"`
	ExternalRef   string    `json:"external_ref,omitempty"`
	Status        string    `json:"status"`
	AttemptCount  int       `json:"attempt_count"`
	MaxAttempts   int       `json:"max_attempts"`
	LastError     string    `json:"last_error,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// IntegrationJobsResponse is the integrations jobs list payload.
type IntegrationJobsResponse struct {
	Jobs []IntegrationJobSummary `json:"jobs"`
}
