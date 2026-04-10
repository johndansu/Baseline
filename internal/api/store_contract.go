package api

import (
	"context"
	"time"
)

// PersistentStore defines the storage operations the API server depends on.
// It keeps handler and server logic decoupled from a specific database engine.
type PersistentStore interface {
	SetAPIKeyHashSecret(secret string)
	Close() error
	Ping(ctx context.Context) error

	UpsertProject(project Project, now time.Time) error
	LoadProjects() ([]Project, error)
	UpdateProjectOwner(projectID, ownerID string) (Project, error)

	UpsertScan(scan ScanSummary) error
	LoadScans(limit int) ([]ScanSummary, error)

	UpsertAPIKey(rawKey string, metadata APIKeyMetadata) error
	EnsureBootstrapAPIKey(rawKey string, metadata APIKeyMetadata) error
	LoadAPIKeys() ([]persistedAPIKey, error)
	RevokeAPIKey(id string, revokedAt time.Time) error
	RevokeAPIKeyWithContext(id string, revokedAt time.Time, revokedByUserID, reason string) error
	ListAPIKeysByOwnerUserID(ownerUserID string, includeRevoked bool, limit int) ([]APIKeyMetadata, error)

	AppendAuditEvent(event AuditEvent) error
	LoadAuditEvents(limit int) ([]AuditEvent, error)
	ListAuditEventsByActors(actors []string, limit, offset int, eventType string, from, to *time.Time) (UserListResult, []AuditEvent, error)
	DeleteAuditEventsByPrefixBefore(prefix string, before time.Time) error

	CreateCLITrace(trace CLITraceDetail) error
	ListCLITraces(limit int, command, status, projectID string) ([]CLITraceSummary, error)
	ListCLITracesBySessionID(sessionID string, limit int) ([]CLITraceSummary, error)
	GetCLITrace(traceID string) (CLITraceDetail, error)

	UpsertOIDCUser(provider, subject, email, displayName string, now time.Time) (string, error)
	CreateUser(email, displayName string, role Role, status UserStatus, now time.Time) (UserRecord, error)
	ListUsersPage(filter UserListFilter) (UserListResult, error)
	GetUserByID(userID string) (UserRecord, bool, error)
	GetUserByEmail(email string) (UserRecord, bool, error)
	UpdateUserRoleAndStatus(userID string, role Role, status UserStatus, updatedAt time.Time) (UserRecord, error)
	UpdateUserProfile(userID, displayName string, updatedAt time.Time) (UserRecord, error)

	UpsertAuthSession(rawToken string, session dashboardSession, now time.Time) error
	LoadAuthSession(rawToken string, now time.Time) (dashboardSession, bool, error)
	RevokeAuthSession(rawToken string, revokedAt time.Time) error
	CountActiveAuthSessions(now time.Time) (int, error)

	EnqueueIntegrationJob(job IntegrationJob) (IntegrationJob, error)
	ClaimDueIntegrationJob(now time.Time) (*IntegrationJob, error)
	MarkIntegrationJobSucceededWithAuditEvent(id string, now time.Time, event AuditEvent) error
	MarkIntegrationJobRetryWithAuditEvent(id, lastError string, nextAttemptAt, now time.Time, event AuditEvent) error
	MarkIntegrationJobFailedWithAuditEvent(id, lastError string, now time.Time, event AuditEvent) error
	ListIntegrationJobs(limit int) ([]IntegrationJob, error)

	CreateCLIAuthRequest(deviceCode, userCode, clientName, clientHost string, expiresAt, now time.Time) error
	GetCLIAuthRequest(deviceCode, userCode string, now time.Time) (cliAuthRequestRecord, bool, error)
	ApproveCLIAuthRequest(deviceCode, userCode string, session cliSessionRecord, now time.Time) (cliAuthRequestRecord, error)
	ConsumeCLIAuthRequest(deviceCode string, now time.Time) error
	CreateCLISession(accessToken, refreshToken string, session cliSessionRecord, now time.Time) error
	LoadCLISessionByAccessToken(accessToken string, now time.Time) (cliSessionRecord, bool, error)
	LoadCLISessionByRefreshToken(refreshToken string, now time.Time) (cliSessionRecord, bool, error)
	RotateCLISession(session cliSessionRecord, newAccessToken, newRefreshToken string, now time.Time) error
	RevokeCLISessionByAccessToken(accessToken string, revokedAt time.Time) error
	RevokeCLISessionByRefreshToken(refreshToken string, revokedAt time.Time) error
	ListCLISessions(limit int, now time.Time) ([]cliSessionRecord, error)
	UpdateCLISessionMetadata(sessionID, lastIP, cliVersion, repository, projectID, command, scanID string, now time.Time) error
	RevokeCLISessionByID(sessionID string, revokedAt time.Time) (bool, error)
	RevokeCLISessionsByOwnerKey(ownerKey string, revokedAt time.Time) (int64, error)
}

var _ PersistentStore = (*Store)(nil)
