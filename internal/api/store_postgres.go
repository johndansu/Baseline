package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const currentPostgresStoreSchemaVersion = 1

// PostgresStore is the first production-oriented shared-database backend.
// This initial slice focuses on connectivity, schema bootstrap, and the
// minimum store operations required for the API to start cleanly.
type PostgresStore struct {
	db               *sql.DB
	apiKeyHashSecret string
}

var _ PersistentStore = (*PostgresStore)(nil)

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	dsn := strings.TrimSpace(databaseURL)
	if dsn == "" {
		return nil, errors.New("postgres database URL is required")
	}
	if _, err := pgx.ParseConfig(dsn); err != nil {
		return nil, fmt.Errorf("invalid postgres database URL: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := bootstrapPostgresStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

func bootstrapPostgresStore(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS store_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			key_hash TEXT NOT NULL UNIQUE,
			name TEXT,
			role TEXT NOT NULL,
			prefix TEXT NOT NULL,
			source TEXT,
			owner_user_id TEXT,
			owner_subject TEXT,
			owner_email TEXT,
			created_at TEXT NOT NULL,
			created_by TEXT,
			created_by_user_id TEXT,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TEXT,
			revoked_by_user_id TEXT,
			revocation_reason TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_revoked_created_at ON api_keys(revoked, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_id_revoked ON api_keys(id, revoked);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_source_created_at ON api_keys(source, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_owner_user_revoked_created_at ON api_keys(owner_user_id, revoked, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id BIGSERIAL PRIMARY KEY,
			event_type TEXT NOT NULL,
			project_id TEXT,
			scan_id TEXT,
			actor TEXT,
			request_id TEXT,
			details TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_project_created_at ON audit_events(project_id, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS integration_jobs (
			id TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			job_type TEXT NOT NULL,
			project_ref TEXT,
			external_ref TEXT,
			payload TEXT,
			status TEXT NOT NULL,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 5,
			last_error TEXT,
			next_attempt_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_integration_jobs_due ON integration_jobs(status, next_attempt_at, created_at);`,
		`CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			repository_url TEXT,
			default_branch TEXT NOT NULL DEFAULT 'main',
			policy_set TEXT NOT NULL DEFAULT 'baseline:prod',
			owner_id TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_projects_owner_created_at ON projects(owner_id, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			commit_sha TEXT,
			status TEXT NOT NULL,
			violations_json TEXT,
			files_scanned INTEGER NOT NULL DEFAULT 0,
			owner_id TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_project_created_at ON scans(project_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_owner_created_at ON scans(owner_id, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			display_name TEXT,
			email TEXT,
			role TEXT NOT NULL DEFAULT 'viewer',
			status TEXT NOT NULL DEFAULT 'active',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role, status, updated_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE TABLE IF NOT EXISTS user_identities (
			provider TEXT NOT NULL,
			subject TEXT NOT NULL,
			user_id TEXT NOT NULL,
			email TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(provider, subject)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities(user_id);`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT,
			role TEXT NOT NULL,
			user_label TEXT NOT NULL,
			subject TEXT,
			email TEXT,
			auth_source TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth_sessions(revoked, expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);`,
		`CREATE TABLE IF NOT EXISTS cli_traces (
			trace_id TEXT PRIMARY KEY,
			session_id TEXT,
			command TEXT NOT NULL,
			repository TEXT,
			project_id TEXT,
			scan_id TEXT,
			status TEXT,
			message TEXT,
			version TEXT,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			event_count INTEGER NOT NULL DEFAULT 0,
			files_scanned INTEGER NOT NULL DEFAULT 0,
			security_issues INTEGER NOT NULL DEFAULT 0,
			violation_count INTEGER NOT NULL DEFAULT 0,
			attributes_json TEXT NOT NULL DEFAULT '{}'
		);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_traces_started_at ON cli_traces(started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_traces_command_started_at ON cli_traces(command, started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_traces_project_started_at ON cli_traces(project_id, started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_traces_session_started_at ON cli_traces(session_id, started_at DESC);`,
		`CREATE TABLE IF NOT EXISTS cli_trace_events (
			id BIGSERIAL PRIMARY KEY,
			trace_id TEXT NOT NULL,
			span_id TEXT,
			parent_span_id TEXT,
			event_type TEXT NOT NULL,
			component TEXT,
			function_name TEXT,
			branch TEXT,
			status TEXT,
			message TEXT,
			attributes_json TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_trace_events_trace_created_at ON cli_trace_events(trace_id, created_at ASC, id ASC);`,
		`CREATE TABLE IF NOT EXISTS cli_auth_requests (
			device_code_hash TEXT PRIMARY KEY,
			user_code_hash TEXT NOT NULL UNIQUE,
			user_code_display TEXT NOT NULL,
			client_name TEXT,
			client_host TEXT,
			status TEXT NOT NULL,
			requested_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			approved_at TEXT,
			approved_user_id TEXT,
			approved_role TEXT,
			approved_user_label TEXT,
			approved_subject TEXT,
			approved_email TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_auth_requests_status_expires_at ON cli_auth_requests(status, expires_at);`,
		`CREATE TABLE IF NOT EXISTS cli_sessions (
			session_id TEXT PRIMARY KEY,
			access_token_hash TEXT NOT NULL UNIQUE,
			refresh_token_hash TEXT NOT NULL UNIQUE,
			user_id TEXT,
			role TEXT NOT NULL,
			user_label TEXT NOT NULL,
			subject TEXT,
			email TEXT,
			client_name TEXT,
			client_host TEXT,
			last_ip TEXT,
			cli_version TEXT,
			last_repository TEXT,
			last_project_id TEXT,
			last_command TEXT,
			last_scan_id TEXT,
			created_at TEXT NOT NULL,
			approved_at TEXT NOT NULL,
			last_used_at TEXT NOT NULL,
			access_expires_at TEXT NOT NULL,
			refresh_expires_at TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_sessions_access_active ON cli_sessions(access_token_hash, revoked, access_expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_cli_sessions_refresh_active ON cli_sessions(refresh_token_hash, revoked, refresh_expires_at);`,
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range statements {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	if err := upsertPostgresStoreSchemaVersionTx(tx, currentPostgresStoreSchemaVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertPostgresStoreSchemaVersionTx(tx *sql.Tx, version int) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(
		`INSERT INTO store_meta (key, value, updated_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT(key) DO UPDATE SET
		   value = EXCLUDED.value,
		   updated_at = EXCLUDED.updated_at`,
		storeSchemaVersionKey,
		strconv.Itoa(version),
		now,
	)
	return err
}

func (s *PostgresStore) SetAPIKeyHashSecret(secret string) {
	if s == nil {
		return
	}
	s.apiKeyHashSecret = strings.TrimSpace(secret)
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("store is not initialized")
	}
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) UpsertProject(project Project, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	id := strings.TrimSpace(project.ID)
	if id == "" {
		return errors.New("project id is required")
	}
	name := strings.TrimSpace(project.Name)
	if name == "" {
		return errors.New("project name is required")
	}
	defaultBranch := strings.TrimSpace(project.DefaultBranch)
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	policySet := strings.TrimSpace(project.PolicySet)
	if policySet == "" {
		policySet = "baseline:prod"
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := s.db.Exec(
		`INSERT INTO projects (id, name, repository_url, default_branch, policy_set, owner_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT(id) DO UPDATE SET
		   name = EXCLUDED.name,
		   repository_url = EXCLUDED.repository_url,
		   default_branch = EXCLUDED.default_branch,
		   policy_set = EXCLUDED.policy_set,
		   owner_id = EXCLUDED.owner_id`,
		id,
		name,
		strings.TrimSpace(project.RepositoryURL),
		defaultBranch,
		policySet,
		strings.TrimSpace(project.OwnerID),
		now.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *PostgresStore) LoadProjects() ([]Project, error) {
	if s == nil || s.db == nil {
		return []Project{}, nil
	}
	rows, err := s.db.Query(
		`SELECT id, name, repository_url, default_branch, policy_set, owner_id, created_at
		 FROM projects
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Project{}
	for rows.Next() {
		var (
			project                Project
			repositoryURL, ownerID sql.NullString
			createdAtRaw           string
		)
		if err := rows.Scan(&project.ID, &project.Name, &repositoryURL, &project.DefaultBranch, &project.PolicySet, &ownerID, &createdAtRaw); err != nil {
			return nil, err
		}
		if _, err := parseStoredTime(createdAtRaw); err != nil {
			return nil, err
		}
		project.RepositoryURL = strings.TrimSpace(repositoryURL.String)
		project.OwnerID = strings.TrimSpace(ownerID.String)
		out = append(out, project)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateProjectOwner(projectID, ownerID string) (Project, error) {
	if s == nil || s.db == nil {
		return Project{}, nil
	}
	id := strings.TrimSpace(projectID)
	if id == "" {
		return Project{}, errors.New("project id is required")
	}
	result, err := s.db.Exec(
		`UPDATE projects
		 SET owner_id = $1
		 WHERE id = $2`,
		strings.TrimSpace(ownerID),
		id,
	)
	if err != nil {
		return Project{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Project{}, err
	}
	if affected == 0 {
		return Project{}, fmt.Errorf("project %s not found", id)
	}
	return s.getProjectByID(id)
}

func (s *PostgresStore) UpsertScan(scan ScanSummary) error {
	if s == nil || s.db == nil {
		return nil
	}
	id := strings.TrimSpace(scan.ID)
	if id == "" {
		return errors.New("scan id is required")
	}
	projectID := strings.TrimSpace(scan.ProjectID)
	if projectID == "" {
		return errors.New("scan project id is required")
	}
	violationsJSON, err := json.Marshal(scan.Violations)
	if err != nil {
		return err
	}
	createdAt := scan.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err = s.db.Exec(
		`INSERT INTO scans (id, project_id, commit_sha, files_scanned, status, violations_json, created_at, owner_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT(id) DO UPDATE SET
		   project_id = EXCLUDED.project_id,
		   commit_sha = EXCLUDED.commit_sha,
		   files_scanned = EXCLUDED.files_scanned,
		   status = EXCLUDED.status,
		   violations_json = EXCLUDED.violations_json,
		   owner_id = EXCLUDED.owner_id`,
		id,
		projectID,
		strings.TrimSpace(scan.CommitSHA),
		scan.FilesScanned,
		strings.TrimSpace(scan.Status),
		string(violationsJSON),
		createdAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(scan.OwnerID),
	)
	return err
}

func (s *PostgresStore) LoadScans(limit int) ([]ScanSummary, error) {
	if s == nil || s.db == nil {
		return []ScanSummary{}, nil
	}
	maxRows := limit
	if maxRows <= 0 {
		maxRows = 1000
	}
	rows, err := s.db.Query(
		`SELECT id, project_id, commit_sha, files_scanned, status, violations_json, created_at, owner_id
		 FROM scans
		 ORDER BY created_at DESC, id ASC
		 LIMIT $1`,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scans := []ScanSummary{}
	for rows.Next() {
		var (
			scan                     ScanSummary
			commitSHA, violationsRaw sql.NullString
			createdRaw               string
			ownerID                  sql.NullString
		)
		if err := rows.Scan(
			&scan.ID,
			&scan.ProjectID,
			&commitSHA,
			&scan.FilesScanned,
			&scan.Status,
			&violationsRaw,
			&createdRaw,
			&ownerID,
		); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return nil, err
		}
		scan.CommitSHA = strings.TrimSpace(commitSHA.String)
		scan.CreatedAt = createdAt
		scan.OwnerID = strings.TrimSpace(ownerID.String)
		if strings.TrimSpace(violationsRaw.String) != "" {
			if err := json.Unmarshal([]byte(violationsRaw.String), &scan.Violations); err != nil {
				return nil, err
			}
		}
		scans = append(scans, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scans, nil
}

func (s *PostgresStore) getProjectByID(projectID string) (Project, error) {
	if s == nil || s.db == nil {
		return Project{}, nil
	}
	id := strings.TrimSpace(projectID)
	if id == "" {
		return Project{}, errors.New("project id is required")
	}
	var (
		project       Project
		repositoryURL sql.NullString
		ownerID       sql.NullString
	)
	err := s.db.QueryRow(
		`SELECT id, name, repository_url, default_branch, policy_set, owner_id
		 FROM projects
		 WHERE id = $1`,
		id,
	).Scan(
		&project.ID,
		&project.Name,
		&repositoryURL,
		&project.DefaultBranch,
		&project.PolicySet,
		&ownerID,
	)
	if err != nil {
		return Project{}, err
	}
	project.RepositoryURL = strings.TrimSpace(repositoryURL.String)
	project.OwnerID = strings.TrimSpace(ownerID.String)
	return project, nil
}

func (s *PostgresStore) UpsertAPIKey(rawKey string, metadata APIKeyMetadata) error {
	return postgresNotImplemented("UpsertAPIKey")
}

func (s *PostgresStore) EnsureBootstrapAPIKey(rawKey string, metadata APIKeyMetadata) error {
	if s == nil || s.db == nil {
		return nil
	}
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return errors.New("empty API key")
	}
	keyHash := hashAPIKey(key, s.apiKeyHashSecret)
	if keyHash == "" {
		return errors.New("empty API key hash")
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return errors.New("missing API key id")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_keys (
			id, key_hash, name, role, prefix, source, owner_user_id, owner_subject, owner_email,
			created_at, created_by, created_by_user_id, revoked, revoked_at, revoked_by_user_id, revocation_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT(key_hash) DO NOTHING`,
		metadata.ID,
		keyHash,
		strings.TrimSpace(metadata.Name),
		string(metadata.Role),
		strings.TrimSpace(metadata.Prefix),
		"bootstrap",
		strings.TrimSpace(metadata.OwnerUserID),
		strings.TrimSpace(metadata.OwnerSubject),
		strings.ToLower(strings.TrimSpace(metadata.OwnerEmail)),
		metadata.CreatedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(metadata.CreatedBy),
		strings.TrimSpace(metadata.CreatedByUserID),
		boolToInt(metadata.Revoked),
		timePtrToString(metadata.RevokedAt),
		strings.TrimSpace(metadata.RevokedByUserID),
		strings.TrimSpace(metadata.RevocationReason),
	)
	return err
}

func (s *PostgresStore) LoadAPIKeys() ([]persistedAPIKey, error) {
	if s == nil || s.db == nil {
		return []persistedAPIKey{}, nil
	}
	rows, err := s.db.Query(
		`SELECT id, key_hash, name, role, prefix, source, owner_user_id, owner_subject, owner_email,
		        created_at, created_by, created_by_user_id, revoked, revoked_at, revoked_by_user_id, revocation_reason
		 FROM api_keys
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []persistedAPIKey{}
	for rows.Next() {
		var (
			id, keyHash, name, roleRaw, prefix, source, createdRaw, createdBy string
			ownerUserID, ownerSubject, ownerEmail                             sql.NullString
			createdByUserID, revokedByUserID, revocationReason                sql.NullString
			revoked                                                           int
			revokedRaw                                                        sql.NullString
		)
		if err := rows.Scan(
			&id,
			&keyHash,
			&name,
			&roleRaw,
			&prefix,
			&source,
			&ownerUserID,
			&ownerSubject,
			&ownerEmail,
			&createdRaw,
			&createdBy,
			&createdByUserID,
			&revoked,
			&revokedRaw,
			&revokedByUserID,
			&revocationReason,
		); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return nil, err
		}
		var revokedAt *time.Time
		if revokedRaw.Valid && strings.TrimSpace(revokedRaw.String) != "" {
			parsed, err := parseStoredTime(revokedRaw.String)
			if err != nil {
				return nil, err
			}
			revokedAt = &parsed
		}
		out = append(out, persistedAPIKey{
			KeyHash: normalizeStoredAPIKeyHash(keyHash),
			Metadata: APIKeyMetadata{
				ID:               strings.TrimSpace(id),
				Name:             strings.TrimSpace(name),
				Role:             Role(strings.ToLower(strings.TrimSpace(roleRaw))),
				Prefix:           strings.TrimSpace(prefix),
				Source:           strings.TrimSpace(source),
				OwnerUserID:      strings.TrimSpace(ownerUserID.String),
				OwnerSubject:     strings.TrimSpace(ownerSubject.String),
				OwnerEmail:       strings.ToLower(strings.TrimSpace(ownerEmail.String)),
				CreatedAt:        createdAt,
				CreatedBy:        strings.TrimSpace(createdBy),
				CreatedByUserID:  strings.TrimSpace(createdByUserID.String),
				Revoked:          revoked != 0,
				RevokedAt:        revokedAt,
				RevokedByUserID:  strings.TrimSpace(revokedByUserID.String),
				RevocationReason: strings.TrimSpace(revocationReason.String),
			},
		})
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeAPIKey(id string, revokedAt time.Time) error {
	return postgresNotImplemented("RevokeAPIKey")
}

func (s *PostgresStore) RevokeAPIKeyWithContext(id string, revokedAt time.Time, revokedByUserID, reason string) error {
	return postgresNotImplemented("RevokeAPIKeyWithContext")
}

func (s *PostgresStore) ListAPIKeysByOwnerUserID(ownerUserID string, includeRevoked bool, limit int) ([]APIKeyMetadata, error) {
	return nil, postgresNotImplemented("ListAPIKeysByOwnerUserID")
}

func (s *PostgresStore) AppendAuditEvent(event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_events (event_type, project_id, scan_id, actor, request_id, details, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.ProjectID),
		strings.TrimSpace(event.ScanID),
		strings.TrimSpace(event.Actor),
		strings.TrimSpace(event.RequestID),
		strings.TrimSpace(event.Details),
		event.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *PostgresStore) LoadAuditEvents(limit int) ([]AuditEvent, error) {
	if s == nil || s.db == nil {
		return []AuditEvent{}, nil
	}
	maxRows := limit
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 100
	}
	rows, err := s.db.Query(
		`SELECT event_type, project_id, scan_id, actor, request_id, details, created_at
		 FROM audit_events
		 ORDER BY created_at DESC
		 LIMIT $1`,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		var (
			event                 AuditEvent
			projectID, scanID     sql.NullString
			actor, requestID      sql.NullString
			details, createdAtRaw string
		)
		if err := rows.Scan(&event.EventType, &projectID, &scanID, &actor, &requestID, &details, &createdAtRaw); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdAtRaw)
		if err != nil {
			return nil, err
		}
		event.ProjectID = strings.TrimSpace(projectID.String)
		event.ScanID = strings.TrimSpace(scanID.String)
		event.Actor = strings.TrimSpace(actor.String)
		event.RequestID = strings.TrimSpace(requestID.String)
		event.Details = strings.TrimSpace(details)
		event.CreatedAt = createdAt
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListAuditEventsByActors(actors []string, limit, offset int, eventType string, from, to *time.Time) (UserListResult, []AuditEvent, error) {
	return UserListResult{}, nil, postgresNotImplemented("ListAuditEventsByActors")
}

func (s *PostgresStore) DeleteAuditEventsByPrefixBefore(prefix string, before time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	normalizedPrefix := strings.ToLower(strings.TrimSpace(prefix))
	if normalizedPrefix == "" {
		return nil
	}
	_, err := s.db.Exec(
		`DELETE FROM audit_events
		 WHERE lower(event_type) LIKE $1 AND created_at < $2`,
		normalizedPrefix+"%",
		before.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *PostgresStore) CreateCLITrace(trace CLITraceDetail) error {
	if s == nil || s.db == nil {
		return nil
	}
	traceID := strings.TrimSpace(trace.Summary.TraceID)
	command := strings.TrimSpace(trace.Summary.Command)
	if traceID == "" {
		return errors.New("trace id is required")
	}
	if command == "" {
		return errors.New("trace command is required")
	}
	startedAt := trace.Summary.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := trace.Summary.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = startedAt
	}
	attrsJSON, err := json.Marshal(trace.Summary.Attributes)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT INTO cli_traces (
			trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
			started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT(trace_id) DO UPDATE SET
			session_id = EXCLUDED.session_id,
			command = EXCLUDED.command,
			repository = EXCLUDED.repository,
			project_id = EXCLUDED.project_id,
			scan_id = EXCLUDED.scan_id,
			status = EXCLUDED.status,
			message = EXCLUDED.message,
			version = EXCLUDED.version,
			started_at = EXCLUDED.started_at,
			finished_at = EXCLUDED.finished_at,
			duration_ms = EXCLUDED.duration_ms,
			event_count = EXCLUDED.event_count,
			files_scanned = EXCLUDED.files_scanned,
			security_issues = EXCLUDED.security_issues,
			violation_count = EXCLUDED.violation_count,
			attributes_json = EXCLUDED.attributes_json`,
		traceID,
		strings.TrimSpace(trace.Summary.SessionID),
		command,
		strings.TrimSpace(trace.Summary.Repository),
		strings.TrimSpace(trace.Summary.ProjectID),
		strings.TrimSpace(trace.Summary.ScanID),
		strings.TrimSpace(trace.Summary.Status),
		strings.TrimSpace(trace.Summary.Message),
		strings.TrimSpace(trace.Summary.Version),
		startedAt.UTC().Format(time.RFC3339Nano),
		finishedAt.UTC().Format(time.RFC3339Nano),
		trace.Summary.DurationMS,
		trace.Summary.EventCount,
		trace.Summary.FilesScanned,
		trace.Summary.SecurityIssues,
		trace.Summary.ViolationCount,
		string(attrsJSON),
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM cli_trace_events WHERE trace_id = $1`, traceID); err != nil {
		return err
	}
	for _, event := range trace.Events {
		eventAttrsJSON, err := json.Marshal(event.Attributes)
		if err != nil {
			return err
		}
		createdAt := event.CreatedAt
		if createdAt.IsZero() {
			createdAt = startedAt
		}
		if _, err := tx.Exec(
			`INSERT INTO cli_trace_events (
				trace_id, span_id, parent_span_id, event_type, component, function_name, branch, status, message, attributes_json, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			traceID,
			strings.TrimSpace(event.SpanID),
			strings.TrimSpace(event.ParentSpanID),
			strings.TrimSpace(event.Type),
			strings.TrimSpace(event.Component),
			strings.TrimSpace(event.Function),
			strings.TrimSpace(event.Branch),
			strings.TrimSpace(event.Status),
			strings.TrimSpace(event.Message),
			string(eventAttrsJSON),
			createdAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListCLITraces(limit int, command, status, projectID string) ([]CLITraceSummary, error) {
	if s == nil || s.db == nil {
		return []CLITraceSummary{}, nil
	}
	maxRows := limit
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 100
	}
	where := []string{}
	args := []any{}
	placeholder := 1
	if trimmed := strings.TrimSpace(command); trimmed != "" {
		where = append(where, fmt.Sprintf("command = $%d", placeholder))
		args = append(args, trimmed)
		placeholder++
	}
	if trimmed := strings.TrimSpace(status); trimmed != "" {
		where = append(where, fmt.Sprintf("status = $%d", placeholder))
		args = append(args, trimmed)
		placeholder++
	}
	if trimmed := strings.TrimSpace(projectID); trimmed != "" {
		where = append(where, fmt.Sprintf("project_id = $%d", placeholder))
		args = append(args, trimmed)
		placeholder++
	}
	query := `SELECT trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
		started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		FROM cli_traces`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d", placeholder)
	args = append(args, maxRows)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CLITraceSummary{}
	for rows.Next() {
		summary, err := scanCLITraceSummaryRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) ListCLITracesBySessionID(sessionID string, limit int) ([]CLITraceSummary, error) {
	if s == nil || s.db == nil {
		return []CLITraceSummary{}, nil
	}
	normalizedID := strings.TrimSpace(sessionID)
	if normalizedID == "" {
		return []CLITraceSummary{}, errors.New("session id is required")
	}
	maxRows := limit
	if maxRows <= 0 || maxRows > 100 {
		maxRows = 10
	}
	rows, err := s.db.Query(
		`SELECT trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
		        started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		 FROM cli_traces
		 WHERE session_id = $1
		 ORDER BY started_at DESC
		 LIMIT $2`,
		normalizedID,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CLITraceSummary{}
	for rows.Next() {
		summary, err := scanCLITraceSummaryRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) GetCLITrace(traceID string) (CLITraceDetail, error) {
	if s == nil || s.db == nil {
		return CLITraceDetail{}, sql.ErrNoRows
	}
	id := strings.TrimSpace(traceID)
	if id == "" {
		return CLITraceDetail{}, errors.New("trace id is required")
	}
	row := s.db.QueryRow(
		`SELECT trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
			started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		 FROM cli_traces WHERE trace_id = $1`,
		id,
	)
	summary, err := scanCLITraceSummaryRow(row)
	if err != nil {
		return CLITraceDetail{}, err
	}
	rows, err := s.db.Query(
		`SELECT id, trace_id, span_id, parent_span_id, event_type, component, function_name, branch, status, message, attributes_json, created_at
		 FROM cli_trace_events
		 WHERE trace_id = $1
		 ORDER BY created_at ASC, id ASC`,
		id,
	)
	if err != nil {
		return CLITraceDetail{}, err
	}
	defer rows.Close()
	events := []CLITraceEvent{}
	for rows.Next() {
		var event CLITraceEvent
		var parentSpanID, component, functionName, branch, statusText, message, attrsRaw sql.NullString
		var createdRaw string
		if err := rows.Scan(&event.ID, &event.TraceID, &event.SpanID, &parentSpanID, &event.Type, &component, &functionName, &branch, &statusText, &message, &attrsRaw, &createdRaw); err != nil {
			return CLITraceDetail{}, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return CLITraceDetail{}, err
		}
		event.ParentSpanID = strings.TrimSpace(parentSpanID.String)
		event.Component = strings.TrimSpace(component.String)
		event.Function = strings.TrimSpace(functionName.String)
		event.Branch = strings.TrimSpace(branch.String)
		event.Status = strings.TrimSpace(statusText.String)
		event.Message = strings.TrimSpace(message.String)
		event.Attributes = map[string]string{}
		if strings.TrimSpace(attrsRaw.String) != "" {
			if err := json.Unmarshal([]byte(attrsRaw.String), &event.Attributes); err != nil {
				return CLITraceDetail{}, err
			}
		}
		event.CreatedAt = createdAt
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return CLITraceDetail{}, err
	}
	return CLITraceDetail{Summary: summary, Events: events}, nil
}

func (s *PostgresStore) UpsertOIDCUser(provider, subject, email, displayName string, now time.Time) (string, error) {
	if s == nil || s.db == nil {
		return "", nil
	}
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	subjectKey := strings.TrimSpace(subject)
	emailValue := strings.ToLower(strings.TrimSpace(email))
	nameValue := strings.TrimSpace(displayName)
	if providerKey == "" {
		return "", errors.New("identity provider is required")
	}
	if subjectKey == "" {
		return "", errors.New("identity subject is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowRaw := now.UTC().Format(time.RFC3339Nano)

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var userID string
	err = tx.QueryRow(
		`SELECT user_id
		 FROM user_identities
		 WHERE provider = $1 AND subject = $2`,
		providerKey,
		subjectKey,
	).Scan(&userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	if errors.Is(err, sql.ErrNoRows) {
		if emailValue != "" {
			existingUser, found, lookupErr := s.GetUserByEmail(emailValue)
			if lookupErr != nil {
				return "", lookupErr
			}
			if found && strings.TrimSpace(existingUser.ID) != "" {
				userID = strings.TrimSpace(existingUser.ID)
				if nameValue == "" {
					nameValue = strings.TrimSpace(existingUser.DisplayName)
				}
				_, err = tx.Exec(
					`UPDATE users
					 SET display_name = $1, email = $2, updated_at = $3, last_login_at = $4
					 WHERE id = $5`,
					nameValue,
					emailValue,
					nowRaw,
					nowRaw,
					userID,
				)
				if err != nil {
					return "", err
				}
				_, err = tx.Exec(
					`INSERT INTO user_identities (provider, subject, user_id, email, created_at, updated_at)
					 VALUES ($1, $2, $3, $4, $5, $6)`,
					providerKey,
					subjectKey,
					userID,
					emailValue,
					nowRaw,
					nowRaw,
				)
				if err != nil {
					return "", err
				}
				if err := tx.Commit(); err != nil {
					return "", err
				}
				return userID, nil
			}
		}

		userID = newUserID(now)
		_, err = tx.Exec(
			`INSERT INTO users (id, display_name, email, created_at, updated_at, last_login_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			userID,
			nameValue,
			emailValue,
			nowRaw,
			nowRaw,
			nowRaw,
		)
		if err != nil {
			return "", err
		}
		_, err = tx.Exec(
			`INSERT INTO user_identities (provider, subject, user_id, email, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			providerKey,
			subjectKey,
			userID,
			emailValue,
			nowRaw,
			nowRaw,
		)
		if err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return userID, nil
	}

	var currentName string
	var currentEmail string
	if scanErr := tx.QueryRow(`SELECT display_name, email FROM users WHERE id = $1`, userID).Scan(&currentName, &currentEmail); scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return "", scanErr
	}
	if nameValue == "" {
		nameValue = strings.TrimSpace(currentName)
	}
	if emailValue == "" {
		emailValue = strings.ToLower(strings.TrimSpace(currentEmail))
	}

	_, err = tx.Exec(
		`UPDATE users
		 SET display_name = $1, email = $2, updated_at = $3, last_login_at = $4
		 WHERE id = $5`,
		nameValue,
		emailValue,
		nowRaw,
		nowRaw,
		userID,
	)
	if err != nil {
		return "", err
	}

	_, err = tx.Exec(
		`INSERT INTO user_identities (provider, subject, user_id, email, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT(provider, subject) DO UPDATE SET
		   user_id = excluded.user_id,
		   email = excluded.email,
		   updated_at = excluded.updated_at`,
		providerKey,
		subjectKey,
		userID,
		emailValue,
		nowRaw,
		nowRaw,
	)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *PostgresStore) CreateUser(email, displayName string, role Role, status UserStatus, now time.Time) (UserRecord, error) {
	if s == nil || s.db == nil {
		return UserRecord{}, nil
	}
	emailValue := normalizeUserEmail(email)
	nameValue := strings.TrimSpace(displayName)
	if emailValue == "" {
		return UserRecord{}, errors.New("email is required")
	}
	if role == "" {
		role = RoleViewer
	}
	if status == "" {
		status = UserStatusActive
	}
	if !isValidRole(role) {
		return UserRecord{}, errors.New("invalid user role")
	}
	if !isValidUserStatus(status) {
		return UserRecord{}, errors.New("invalid user status")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if existing, found, err := s.GetUserByEmail(emailValue); err != nil {
		return UserRecord{}, err
	} else if found {
		return UserRecord{}, fmt.Errorf("%w: %s", errUserEmailAlreadyExists, existing.Email)
	}

	userID := newUserID(now)
	nowRaw := now.UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO users (id, display_name, email, role, status, created_at, updated_at, last_login_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID,
		nameValue,
		emailValue,
		string(role),
		string(status),
		nowRaw,
		nowRaw,
		nowRaw,
	)
	if err != nil {
		return UserRecord{}, err
	}
	user, found, err := s.GetUserByID(userID)
	if err != nil {
		return UserRecord{}, err
	}
	if !found {
		return UserRecord{}, fmt.Errorf("user %s not found", userID)
	}
	return user, nil
}

func (s *PostgresStore) ListUsersPage(filter UserListFilter) (UserListResult, error) {
	if s == nil || s.db == nil {
		return UserListResult{Users: []UserRecord{}}, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	roleRaw := strings.TrimSpace(string(filter.Role))
	statusRaw := strings.TrimSpace(string(filter.Status))
	queryRaw := strings.ToLower(strings.TrimSpace(filter.Query))
	sortBy := strings.TrimSpace(strings.ToLower(filter.SortBy))
	if sortBy == "" {
		sortBy = "updated_at"
	}
	sortDir := strings.TrimSpace(strings.ToLower(filter.SortDir))
	if sortDir == "" {
		sortDir = "desc"
	}

	orderColumn := "updated_at"
	switch sortBy {
	case "user":
		orderColumn = "lower(COALESCE(NULLIF(email, ''), NULLIF(display_name, ''), id))"
	case "role":
		orderColumn = "role"
	case "status":
		orderColumn = "status"
	case "last_login_at":
		orderColumn = "last_login_at"
	case "created_at":
		orderColumn = "created_at"
	case "updated_at":
		orderColumn = "updated_at"
	default:
		orderColumn = "updated_at"
	}

	orderDirection := "DESC"
	if sortDir == "asc" {
		orderDirection = "ASC"
	}

	var total int
	if err := s.db.QueryRow(
		`SELECT COUNT(1)
		 FROM users
		 WHERE ($1 = '' OR role = $2)
		   AND ($3 = '' OR status = $4)
		   AND ($5 = '' OR lower(display_name) LIKE '%' || $6 || '%' OR lower(email) LIKE '%' || $7 || '%')`,
		roleRaw,
		roleRaw,
		statusRaw,
		statusRaw,
		queryRaw,
		queryRaw,
		queryRaw,
	).Scan(&total); err != nil {
		return UserListResult{}, err
	}

	query := fmt.Sprintf(
		`SELECT id, display_name, email, role, status, last_login_at, created_at, updated_at
		 FROM users
		 WHERE ($1 = '' OR role = $2)
		   AND ($3 = '' OR status = $4)
		   AND ($5 = '' OR lower(display_name) LIKE '%%' || $6 || '%%' OR lower(email) LIKE '%%' || $7 || '%%')
		 ORDER BY %s %s, id ASC
		 LIMIT $8 OFFSET $9`,
		orderColumn,
		orderDirection,
	)
	rows, err := s.db.Query(
		query,
		roleRaw,
		roleRaw,
		statusRaw,
		statusRaw,
		queryRaw,
		queryRaw,
		queryRaw,
		limit,
		offset,
	)
	if err != nil {
		return UserListResult{}, err
	}
	defer rows.Close()

	out := []UserRecord{}
	for rows.Next() {
		user, err := scanUserRecord(rows)
		if err != nil {
			return UserListResult{}, err
		}
		out = append(out, user)
	}
	if err := rows.Err(); err != nil {
		return UserListResult{}, err
	}

	hasMore := false
	if total > 0 {
		hasMore = offset+len(out) < total
	}
	return UserListResult{
		Users:   out,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: hasMore,
	}, nil
}

func (s *PostgresStore) GetUserByID(userID string) (UserRecord, bool, error) {
	if s == nil || s.db == nil {
		return UserRecord{}, false, nil
	}
	id := strings.TrimSpace(userID)
	if id == "" {
		return UserRecord{}, false, errors.New("user id is required")
	}

	row := s.db.QueryRow(
		`SELECT id, display_name, email, role, status, last_login_at, created_at, updated_at
		 FROM users
		 WHERE id = $1`,
		id,
	)
	user, err := scanUserRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, false, nil
	}
	if err != nil {
		return UserRecord{}, false, err
	}
	return user, true, nil
}

func (s *PostgresStore) GetUserByEmail(email string) (UserRecord, bool, error) {
	if s == nil || s.db == nil {
		return UserRecord{}, false, nil
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedEmail == "" {
		return UserRecord{}, false, errors.New("email is required")
	}

	row := s.db.QueryRow(
		`SELECT id, display_name, email, role, status, last_login_at, created_at, updated_at
		 FROM users
		 WHERE lower(email) = $1`,
		normalizedEmail,
	)
	user, err := scanUserRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UserRecord{}, false, nil
	}
	if err != nil {
		return UserRecord{}, false, err
	}
	return user, true, nil
}

func (s *PostgresStore) UpdateUserRoleAndStatus(userID string, role Role, status UserStatus, updatedAt time.Time) (UserRecord, error) {
	if s == nil || s.db == nil {
		return UserRecord{}, nil
	}
	id := strings.TrimSpace(userID)
	if id == "" {
		return UserRecord{}, errors.New("user id is required")
	}
	if !isValidRole(role) {
		return UserRecord{}, errors.New("invalid user role")
	}
	if !isValidUserStatus(status) {
		return UserRecord{}, errors.New("invalid user status")
	}
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	updatedAtRaw := updatedAt.UTC().Format(time.RFC3339Nano)

	result, err := s.db.Exec(
		`UPDATE users
		 SET role = $1, status = $2, updated_at = $3
		 WHERE id = $4`,
		string(role),
		string(status),
		updatedAtRaw,
		id,
	)
	if err != nil {
		return UserRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return UserRecord{}, err
	}
	if affected == 0 {
		return UserRecord{}, fmt.Errorf("user %s not found", id)
	}

	user, found, err := s.GetUserByID(id)
	if err != nil {
		return UserRecord{}, err
	}
	if !found {
		return UserRecord{}, fmt.Errorf("user %s not found", id)
	}
	return user, nil
}

func (s *PostgresStore) UpdateUserProfile(userID, displayName string, updatedAt time.Time) (UserRecord, error) {
	if s == nil || s.db == nil {
		return UserRecord{}, nil
	}
	id := strings.TrimSpace(userID)
	if id == "" {
		return UserRecord{}, errors.New("user id is required")
	}
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	updatedAtRaw := updatedAt.UTC().Format(time.RFC3339Nano)
	nameValue := strings.TrimSpace(displayName)

	result, err := s.db.Exec(
		`UPDATE users
		 SET display_name = $1, updated_at = $2
		 WHERE id = $3`,
		nameValue,
		updatedAtRaw,
		id,
	)
	if err != nil {
		return UserRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return UserRecord{}, err
	}
	if affected == 0 {
		return UserRecord{}, fmt.Errorf("user %s not found", id)
	}

	user, found, err := s.GetUserByID(id)
	if err != nil {
		return UserRecord{}, err
	}
	if !found {
		return UserRecord{}, fmt.Errorf("user %s not found", id)
	}
	return user, nil
}

func (s *PostgresStore) UpsertAuthSession(rawToken string, session dashboardSession, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	tokenHash := hashAPIKey(rawToken, s.apiKeyHashSecret)
	if tokenHash == "" {
		return errors.New("empty auth session token")
	}
	if session.ExpiresAt.IsZero() {
		return errors.New("auth session expiry is required")
	}
	if !isValidRole(session.Role) {
		return errors.New("invalid auth session role")
	}
	if strings.TrimSpace(session.User) == "" {
		return errors.New("auth session user label is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowRaw := now.UTC().Format(time.RFC3339Nano)

	_, err := s.db.Exec(
		`INSERT INTO auth_sessions (
			token_hash, user_id, role, user_label, subject, email, auth_source,
			expires_at, created_at, last_seen_at, revoked, revoked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, '')
		ON CONFLICT(token_hash) DO UPDATE SET
			user_id = excluded.user_id,
			role = excluded.role,
			user_label = excluded.user_label,
			subject = excluded.subject,
			email = excluded.email,
			auth_source = excluded.auth_source,
			expires_at = excluded.expires_at,
			last_seen_at = excluded.last_seen_at,
			revoked = 0,
			revoked_at = ''`,
		tokenHash,
		strings.TrimSpace(session.UserID),
		string(session.Role),
		strings.TrimSpace(session.User),
		strings.TrimSpace(session.Subject),
		strings.ToLower(strings.TrimSpace(session.Email)),
		strings.TrimSpace(session.AuthSource),
		session.ExpiresAt.UTC().Format(time.RFC3339Nano),
		nowRaw,
		nowRaw,
	)
	return err
}

func (s *PostgresStore) LoadAuthSession(rawToken string, now time.Time) (dashboardSession, bool, error) {
	if s == nil || s.db == nil {
		return dashboardSession{}, false, nil
	}
	tokenHash := hashAPIKey(rawToken, s.apiKeyHashSecret)
	if tokenHash == "" {
		return dashboardSession{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowUTC := now.UTC()
	nowRaw := nowUTC.Format(time.RFC3339Nano)

	var (
		userID     string
		roleRaw    string
		userLabel  string
		subject    string
		email      string
		authSource string
		expiresRaw string
		revoked    int
	)
	err := s.db.QueryRow(
		`SELECT user_id, role, user_label, subject, email, auth_source, expires_at, revoked
		 FROM auth_sessions
		 WHERE token_hash = $1`,
		tokenHash,
	).Scan(
		&userID,
		&roleRaw,
		&userLabel,
		&subject,
		&email,
		&authSource,
		&expiresRaw,
		&revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return dashboardSession{}, false, nil
	}
	if err != nil {
		return dashboardSession{}, false, err
	}

	expiresAt, err := parseStoredTime(expiresRaw)
	if err != nil {
		return dashboardSession{}, false, err
	}
	if revoked != 0 || !nowUTC.Before(expiresAt) {
		_, _ = s.db.Exec(
			`UPDATE auth_sessions
			 SET revoked = 1, revoked_at = $1, last_seen_at = $2
			 WHERE token_hash = $3`,
			nowRaw,
			nowRaw,
			tokenHash,
		)
		return dashboardSession{}, false, nil
	}

	_, _ = s.db.Exec(
		`UPDATE auth_sessions
		 SET last_seen_at = $1
		 WHERE token_hash = $2`,
		nowRaw,
		tokenHash,
	)

	return dashboardSession{
		UserID:     strings.TrimSpace(userID),
		Role:       Role(strings.ToLower(strings.TrimSpace(roleRaw))),
		User:       strings.TrimSpace(userLabel),
		Subject:    strings.TrimSpace(subject),
		Email:      strings.ToLower(strings.TrimSpace(email)),
		AuthSource: strings.TrimSpace(authSource),
		ExpiresAt:  expiresAt,
	}, true, nil
}

func (s *PostgresStore) RevokeAuthSession(rawToken string, revokedAt time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	tokenHash := hashAPIKey(rawToken, s.apiKeyHashSecret)
	if tokenHash == "" {
		return errors.New("empty auth session token")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	revokedRaw := revokedAt.UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`UPDATE auth_sessions
		 SET revoked = 1, revoked_at = $1, last_seen_at = $2
		 WHERE token_hash = $3`,
		revokedRaw,
		revokedRaw,
		tokenHash,
	)
	return err
}

func (s *PostgresStore) CountActiveAuthSessions(now time.Time) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(1)
		 FROM auth_sessions
		 WHERE revoked = 0 AND expires_at > $1`,
		now.UTC().Format(time.RFC3339Nano),
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *PostgresStore) EnqueueIntegrationJob(job IntegrationJob) (IntegrationJob, error) {
	if s == nil || s.db == nil {
		return job, nil
	}

	now := time.Now().UTC()
	if strings.TrimSpace(job.ID) == "" {
		job.ID = "job_" + randomToken(6)
	}
	if strings.TrimSpace(job.Provider) == "" {
		return IntegrationJob{}, errors.New("integration job provider is required")
	}
	if strings.TrimSpace(job.JobType) == "" {
		return IntegrationJob{}, errors.New("integration job type is required")
	}
	if job.MaxAttempts <= 0 {
		job.MaxAttempts = 5
	}
	if strings.TrimSpace(job.Status) == "" {
		job.Status = IntegrationJobPending
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if job.UpdatedAt.IsZero() {
		job.UpdatedAt = now
	}
	if job.NextAttemptAt.IsZero() {
		job.NextAttemptAt = now
	}

	_, err := s.db.Exec(
		`INSERT INTO integration_jobs (
			id, provider, job_type, project_ref, external_ref, payload, status, attempt_count,
			max_attempts, last_error, next_attempt_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		strings.TrimSpace(job.ID),
		strings.TrimSpace(job.Provider),
		strings.TrimSpace(job.JobType),
		strings.TrimSpace(job.ProjectRef),
		strings.TrimSpace(job.ExternalRef),
		job.Payload,
		strings.TrimSpace(job.Status),
		job.AttemptCount,
		job.MaxAttempts,
		strings.TrimSpace(job.LastError),
		job.NextAttemptAt.UTC().Format(time.RFC3339Nano),
		job.CreatedAt.UTC().Format(time.RFC3339Nano),
		job.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return IntegrationJob{}, err
	}
	return job, nil
}

func (s *PostgresStore) ClaimDueIntegrationJob(now time.Time) (*IntegrationJob, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	current := now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRow(
		`SELECT id, provider, job_type, project_ref, external_ref, payload, status, attempt_count,
		        max_attempts, last_error, next_attempt_at, created_at, updated_at
		 FROM integration_jobs
		 WHERE status IN ($1, $2)
		   AND attempt_count < max_attempts
		   AND next_attempt_at <= $3
		 ORDER BY created_at ASC
		 FOR UPDATE SKIP LOCKED
		 LIMIT 1`,
		IntegrationJobPending,
		IntegrationJobFailed,
		current.Format(time.RFC3339Nano),
	)
	job, err := scanIntegrationJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	result, err := tx.Exec(
		`UPDATE integration_jobs
		 SET status = $1, attempt_count = attempt_count + 1, updated_at = $2
		 WHERE id = $3 AND status IN ($4, $5)`,
		IntegrationJobRunning,
		current.Format(time.RFC3339Nano),
		job.ID,
		IntegrationJobPending,
		IntegrationJobFailed,
	)
	if err != nil {
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, nil
	}

	row = tx.QueryRow(
		`SELECT id, provider, job_type, project_ref, external_ref, payload, status, attempt_count,
		        max_attempts, last_error, next_attempt_at, created_at, updated_at
		 FROM integration_jobs
		 WHERE id = $1`,
		job.ID,
	)
	job, err = scanIntegrationJob(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *PostgresStore) MarkIntegrationJobSucceededWithAuditEvent(id string, now time.Time, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.updateIntegrationJobWithAuditEvent(
		`UPDATE integration_jobs
		 SET status = $1, last_error = '', next_attempt_at = $2, updated_at = $3
		 WHERE id = $4`,
		[]any{
			IntegrationJobSucceeded,
			now.UTC().Format(time.RFC3339Nano),
			now.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(id),
		},
		event,
	)
}

func (s *PostgresStore) MarkIntegrationJobRetryWithAuditEvent(id, lastError string, nextAttemptAt, now time.Time, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.updateIntegrationJobWithAuditEvent(
		`UPDATE integration_jobs
		 SET status = $1, last_error = $2, next_attempt_at = $3, updated_at = $4
		 WHERE id = $5`,
		[]any{
			IntegrationJobFailed,
			strings.TrimSpace(lastError),
			nextAttemptAt.UTC().Format(time.RFC3339Nano),
			now.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(id),
		},
		event,
	)
}

func (s *PostgresStore) MarkIntegrationJobFailedWithAuditEvent(id, lastError string, now time.Time, event AuditEvent) error {
	return s.MarkIntegrationJobRetryWithAuditEvent(id, lastError, now, now, event)
}

func (s *PostgresStore) ListIntegrationJobs(limit int) ([]IntegrationJob, error) {
	if s == nil || s.db == nil {
		return []IntegrationJob{}, nil
	}
	maxRows := limit
	if maxRows <= 0 {
		maxRows = 100
	}
	rows, err := s.db.Query(
		`SELECT id, provider, job_type, project_ref, external_ref, payload, status, attempt_count,
		        max_attempts, last_error, next_attempt_at, created_at, updated_at
		 FROM integration_jobs
		 ORDER BY created_at DESC
		 LIMIT $1`,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []IntegrationJob{}
	for rows.Next() {
		job, err := scanIntegrationJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) CreateCLIAuthRequest(deviceCode, userCode, clientName, clientHost string, expiresAt, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	deviceHash := hashAPIKey(deviceCode, s.apiKeyHashSecret)
	userHash := hashAPIKey(userCode, s.apiKeyHashSecret)
	if deviceHash == "" || userHash == "" {
		return errors.New("device and user codes are required")
	}
	if expiresAt.IsZero() {
		return errors.New("cli auth request expiry is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO cli_auth_requests (
			device_code_hash, user_code_hash, user_code_display, client_name, client_host,
			status, requested_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT(device_code_hash) DO UPDATE SET
			user_code_hash = EXCLUDED.user_code_hash,
			user_code_display = EXCLUDED.user_code_display,
			client_name = EXCLUDED.client_name,
			client_host = EXCLUDED.client_host,
			status = EXCLUDED.status,
			requested_at = EXCLUDED.requested_at,
			expires_at = EXCLUDED.expires_at,
			approved_at = NULL,
			approved_user_id = '',
			approved_role = '',
			approved_user_label = '',
			approved_subject = '',
			approved_email = ''`,
		deviceHash,
		userHash,
		strings.TrimSpace(userCode),
		strings.TrimSpace(clientName),
		strings.TrimSpace(clientHost),
		cliAuthRequestStatusPending,
		now.UTC().Format(time.RFC3339Nano),
		expiresAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *PostgresStore) GetCLIAuthRequest(deviceCode, userCode string, now time.Time) (cliAuthRequestRecord, bool, error) {
	if s == nil || s.db == nil {
		return cliAuthRequestRecord{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var (
		query string
		arg   string
	)
	if trimmed := strings.TrimSpace(deviceCode); trimmed != "" {
		query = `SELECT device_code_hash, user_code_hash, user_code_display, client_name, client_host, status,
			requested_at, expires_at, approved_at, approved_user_id, approved_role, approved_user_label,
			approved_subject, approved_email
			FROM cli_auth_requests WHERE device_code_hash = $1`
		arg = hashAPIKey(trimmed, s.apiKeyHashSecret)
	} else if trimmed := strings.TrimSpace(userCode); trimmed != "" {
		query = `SELECT device_code_hash, user_code_hash, user_code_display, client_name, client_host, status,
			requested_at, expires_at, approved_at, approved_user_id, approved_role, approved_user_label,
			approved_subject, approved_email
			FROM cli_auth_requests WHERE user_code_hash = $1`
		arg = hashAPIKey(trimmed, s.apiKeyHashSecret)
	} else {
		return cliAuthRequestRecord{}, false, errors.New("device code or user code is required")
	}
	row := s.db.QueryRow(query, arg)
	record, err := scanCLIAuthRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return cliAuthRequestRecord{}, false, nil
	}
	if err != nil {
		return cliAuthRequestRecord{}, false, err
	}
	if !now.Before(record.ExpiresAt) {
		_, _ = s.db.Exec(`DELETE FROM cli_auth_requests WHERE device_code_hash = $1`, record.DeviceCodeHash)
		return cliAuthRequestRecord{}, false, nil
	}
	return record, true, nil
}

func (s *PostgresStore) ApproveCLIAuthRequest(deviceCode, userCode string, session cliSessionRecord, now time.Time) (cliAuthRequestRecord, error) {
	if s == nil || s.db == nil {
		return cliAuthRequestRecord{}, nil
	}
	record, found, err := s.GetCLIAuthRequest(deviceCode, userCode, now)
	if err != nil {
		return cliAuthRequestRecord{}, err
	}
	if !found {
		return cliAuthRequestRecord{}, sql.ErrNoRows
	}
	if record.Status != cliAuthRequestStatusPending {
		return cliAuthRequestRecord{}, errors.New("cli auth request is no longer pending")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err = s.db.Exec(
		`UPDATE cli_auth_requests
		 SET status = $1, approved_at = $2, approved_user_id = $3, approved_role = $4, approved_user_label = $5,
		     approved_subject = $6, approved_email = $7
		 WHERE device_code_hash = $8`,
		cliAuthRequestStatusApproved,
		now.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(session.UserID),
		string(session.Role),
		strings.TrimSpace(session.UserLabel),
		strings.TrimSpace(session.Subject),
		strings.ToLower(strings.TrimSpace(session.Email)),
		record.DeviceCodeHash,
	)
	if err != nil {
		return cliAuthRequestRecord{}, err
	}
	record.Status = cliAuthRequestStatusApproved
	record.ApprovedAt = now.UTC()
	record.ApprovedUserID = strings.TrimSpace(session.UserID)
	record.ApprovedRole = session.Role
	record.ApprovedUserLabel = strings.TrimSpace(session.UserLabel)
	record.ApprovedSubject = strings.TrimSpace(session.Subject)
	record.ApprovedEmail = strings.ToLower(strings.TrimSpace(session.Email))
	return record, nil
}

func (s *PostgresStore) ConsumeCLIAuthRequest(deviceCode string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	deviceHash := hashAPIKey(deviceCode, s.apiKeyHashSecret)
	if deviceHash == "" {
		return errors.New("device code is required")
	}
	_, err := s.db.Exec(`DELETE FROM cli_auth_requests WHERE device_code_hash = $1`, deviceHash)
	return err
}

func (s *PostgresStore) CreateCLISession(accessToken, refreshToken string, session cliSessionRecord, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	accessHash := hashAPIKey(accessToken, s.apiKeyHashSecret)
	refreshHash := hashAPIKey(refreshToken, s.apiKeyHashSecret)
	if accessHash == "" || refreshHash == "" {
		return errors.New("cli session tokens are required")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return errors.New("cli session id is required")
	}
	if !isValidRole(session.Role) {
		return errors.New("invalid cli session role")
	}
	if strings.TrimSpace(session.UserLabel) == "" {
		return errors.New("cli session user label is required")
	}
	if session.AccessExpiresAt.IsZero() || session.RefreshExpiresAt.IsZero() {
		return errors.New("cli session expiry is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.ApprovedAt.IsZero() {
		session.ApprovedAt = now
	}
	if session.LastUsedAt.IsZero() {
		session.LastUsedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO cli_sessions (
			session_id, access_token_hash, refresh_token_hash, user_id, role, user_label, subject, email,
			client_name, client_host, created_at, approved_at, last_used_at, access_expires_at, refresh_expires_at,
			revoked, revoked_at, last_ip, cli_version, last_repository, last_project_id, last_command, last_scan_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 0, '', $16, $17, $18, $19, $20, $21)
		ON CONFLICT(session_id) DO UPDATE SET
			access_token_hash = EXCLUDED.access_token_hash,
			refresh_token_hash = EXCLUDED.refresh_token_hash,
			user_id = EXCLUDED.user_id,
			role = EXCLUDED.role,
			user_label = EXCLUDED.user_label,
			subject = EXCLUDED.subject,
			email = EXCLUDED.email,
			client_name = EXCLUDED.client_name,
			client_host = EXCLUDED.client_host,
			last_ip = EXCLUDED.last_ip,
			cli_version = EXCLUDED.cli_version,
			last_repository = EXCLUDED.last_repository,
			last_project_id = EXCLUDED.last_project_id,
			last_command = EXCLUDED.last_command,
			last_scan_id = EXCLUDED.last_scan_id,
			approved_at = EXCLUDED.approved_at,
			last_used_at = EXCLUDED.last_used_at,
			access_expires_at = EXCLUDED.access_expires_at,
			refresh_expires_at = EXCLUDED.refresh_expires_at,
			revoked = 0,
			revoked_at = ''`,
		strings.TrimSpace(session.SessionID),
		accessHash,
		refreshHash,
		strings.TrimSpace(session.UserID),
		string(session.Role),
		strings.TrimSpace(session.UserLabel),
		strings.TrimSpace(session.Subject),
		strings.ToLower(strings.TrimSpace(session.Email)),
		strings.TrimSpace(session.ClientName),
		strings.TrimSpace(session.ClientHost),
		session.CreatedAt.UTC().Format(time.RFC3339Nano),
		session.ApprovedAt.UTC().Format(time.RFC3339Nano),
		session.LastUsedAt.UTC().Format(time.RFC3339Nano),
		session.AccessExpiresAt.UTC().Format(time.RFC3339Nano),
		session.RefreshExpiresAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(session.LastIP),
		strings.TrimSpace(session.CLIVersion),
		strings.TrimSpace(session.LastRepository),
		strings.TrimSpace(session.LastProjectID),
		strings.TrimSpace(session.LastCommand),
		strings.TrimSpace(session.LastScanID),
	)
	return err
}

func (s *PostgresStore) LoadCLISessionByAccessToken(accessToken string, now time.Time) (cliSessionRecord, bool, error) {
	return s.loadCLISessionByToken(accessToken, true, now)
}

func (s *PostgresStore) LoadCLISessionByRefreshToken(refreshToken string, now time.Time) (cliSessionRecord, bool, error) {
	return s.loadCLISessionByToken(refreshToken, false, now)
}

func (s *PostgresStore) RotateCLISession(session cliSessionRecord, newAccessToken, newRefreshToken string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	accessHash := hashAPIKey(newAccessToken, s.apiKeyHashSecret)
	refreshHash := hashAPIKey(newRefreshToken, s.apiKeyHashSecret)
	if accessHash == "" || refreshHash == "" {
		return errors.New("rotated cli session tokens are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`UPDATE cli_sessions
		 SET access_token_hash = $1, refresh_token_hash = $2, user_id = $3, role = $4, user_label = $5,
		     subject = $6, email = $7, client_name = $8, client_host = $9, last_ip = $10, cli_version = $11, last_repository = $12, last_project_id = $13, last_command = $14, last_scan_id = $15, last_used_at = $16,
		     access_expires_at = $17, refresh_expires_at = $18, revoked = 0, revoked_at = ''
		 WHERE session_id = $19`,
		accessHash,
		refreshHash,
		strings.TrimSpace(session.UserID),
		string(session.Role),
		strings.TrimSpace(session.UserLabel),
		strings.TrimSpace(session.Subject),
		strings.ToLower(strings.TrimSpace(session.Email)),
		strings.TrimSpace(session.ClientName),
		strings.TrimSpace(session.ClientHost),
		strings.TrimSpace(session.LastIP),
		strings.TrimSpace(session.CLIVersion),
		strings.TrimSpace(session.LastRepository),
		strings.TrimSpace(session.LastProjectID),
		strings.TrimSpace(session.LastCommand),
		strings.TrimSpace(session.LastScanID),
		now.UTC().Format(time.RFC3339Nano),
		session.AccessExpiresAt.UTC().Format(time.RFC3339Nano),
		session.RefreshExpiresAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(session.SessionID),
	)
	return err
}

func (s *PostgresStore) RevokeCLISessionByAccessToken(accessToken string, revokedAt time.Time) error {
	return s.revokeCLISessionByToken(accessToken, true, revokedAt)
}

func (s *PostgresStore) RevokeCLISessionByRefreshToken(refreshToken string, revokedAt time.Time) error {
	return s.revokeCLISessionByToken(refreshToken, false, revokedAt)
}

func (s *PostgresStore) ListCLISessions(limit int, now time.Time) ([]cliSessionRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(
		`SELECT session_id, user_id, role, user_label, subject, email, client_name, client_host, last_ip, cli_version, last_repository, last_project_id, last_command, last_scan_id,
		        created_at, approved_at, last_used_at, access_expires_at, refresh_expires_at, revoked, revoked_at
		 FROM cli_sessions
		 WHERE revoked = 0 AND refresh_expires_at > $1
		 ORDER BY last_used_at DESC, created_at DESC
		 LIMIT $2`,
		now.UTC().Format(time.RFC3339Nano),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]cliSessionRecord, 0, limit)
	for rows.Next() {
		record, err := scanCLISession(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *PostgresStore) UpdateCLISessionMetadata(sessionID, lastIP, cliVersion, repository, projectID, command, scanID string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("cli session id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`UPDATE cli_sessions
		 SET last_used_at = $1,
		     last_ip = COALESCE(NULLIF($2, ''), last_ip),
		     cli_version = COALESCE(NULLIF($3, ''), cli_version),
		     last_repository = COALESCE(NULLIF($4, ''), last_repository),
		     last_project_id = COALESCE(NULLIF($5, ''), last_project_id),
		     last_command = COALESCE(NULLIF($6, ''), last_command),
		     last_scan_id = COALESCE(NULLIF($7, ''), last_scan_id)
		 WHERE session_id = $8`,
		now.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(lastIP),
		strings.TrimSpace(cliVersion),
		strings.TrimSpace(repository),
		strings.TrimSpace(projectID),
		strings.TrimSpace(command),
		strings.TrimSpace(scanID),
		sessionID,
	)
	return err
}

func (s *PostgresStore) RevokeCLISessionByID(sessionID string, revokedAt time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false, errors.New("cli session id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	result, err := s.db.Exec(
		`UPDATE cli_sessions
		 SET revoked = 1, revoked_at = $1, last_used_at = $2
		 WHERE session_id = $3 AND revoked = 0`,
		revokedAt.UTC().Format(time.RFC3339Nano),
		revokedAt.UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rowsAffected > 0, nil
}

func (s *PostgresStore) RevokeCLISessionsByOwnerKey(ownerKey string, revokedAt time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	ownerKey = normalizeOwnerID(ownerKey)
	if ownerKey == "" {
		return 0, errors.New("cli session owner key is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	var (
		query string
		args  []any
	)
	switch {
	case strings.HasPrefix(ownerKey, "user:"):
		arg := strings.TrimSpace(strings.TrimPrefix(ownerKey, "user:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = $1, last_used_at = $2
		 WHERE revoked = 0 AND (
		     lower(btrim(user_id)) = $3
		     OR (btrim(user_id) = '' AND btrim(subject) = '' AND btrim(email) = '' AND lower(btrim(user_label)) = $4)
		 )`
		args = []any{
			revokedAt.UTC().Format(time.RFC3339Nano),
			revokedAt.UTC().Format(time.RFC3339Nano),
			arg,
			arg,
		}
	case strings.HasPrefix(ownerKey, "sub:"):
		arg := strings.TrimSpace(strings.TrimPrefix(ownerKey, "sub:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = $1, last_used_at = $2
		 WHERE revoked = 0 AND lower(btrim(subject)) = $3`
		args = []any{
			revokedAt.UTC().Format(time.RFC3339Nano),
			revokedAt.UTC().Format(time.RFC3339Nano),
			arg,
		}
	case strings.HasPrefix(ownerKey, "email:"):
		arg := strings.TrimSpace(strings.TrimPrefix(ownerKey, "email:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = $1, last_used_at = $2
		 WHERE revoked = 0 AND lower(btrim(email)) = $3`
		args = []any{
			revokedAt.UTC().Format(time.RFC3339Nano),
			revokedAt.UTC().Format(time.RFC3339Nano),
			arg,
		}
	default:
		return 0, errors.New("unsupported cli session owner key")
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func (s *PostgresStore) loadCLISessionByToken(rawToken string, access bool, now time.Time) (cliSessionRecord, bool, error) {
	if s == nil || s.db == nil {
		return cliSessionRecord{}, false, nil
	}
	tokenHash := hashAPIKey(rawToken, s.apiKeyHashSecret)
	if tokenHash == "" {
		return cliSessionRecord{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	column := "access_token_hash"
	if !access {
		column = "refresh_token_hash"
	}
	row := s.db.QueryRow(
		`SELECT session_id, user_id, role, user_label, subject, email, client_name, client_host, last_ip, cli_version, last_repository, last_project_id, last_command, last_scan_id,
		        created_at, approved_at, last_used_at, access_expires_at, refresh_expires_at, revoked, revoked_at
		 FROM cli_sessions WHERE `+column+` = $1`,
		tokenHash,
	)
	record, err := scanCLISession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return cliSessionRecord{}, false, nil
	}
	if err != nil {
		return cliSessionRecord{}, false, err
	}
	if record.Revoked || (!access && !now.Before(record.RefreshExpiresAt)) || (access && !now.Before(record.AccessExpiresAt)) {
		if !record.Revoked && !now.Before(record.RefreshExpiresAt) {
			_, _ = s.db.Exec(
				`UPDATE cli_sessions SET revoked = 1, revoked_at = $1, last_used_at = $2 WHERE session_id = $3`,
				now.UTC().Format(time.RFC3339Nano),
				now.UTC().Format(time.RFC3339Nano),
				record.SessionID,
			)
		}
		return cliSessionRecord{}, false, nil
	}
	if _, err := s.db.Exec(
		`UPDATE cli_sessions SET last_used_at = $1 WHERE session_id = $2`,
		now.UTC().Format(time.RFC3339Nano),
		record.SessionID,
	); err != nil {
		return cliSessionRecord{}, false, err
	}
	record.LastUsedAt = now.UTC()
	return record, true, nil
}

func (s *PostgresStore) revokeCLISessionByToken(rawToken string, access bool, revokedAt time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	tokenHash := hashAPIKey(rawToken, s.apiKeyHashSecret)
	if tokenHash == "" {
		return errors.New("cli session token is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	column := "access_token_hash"
	if !access {
		column = "refresh_token_hash"
	}
	_, err := s.db.Exec(
		`UPDATE cli_sessions
		 SET revoked = 1, revoked_at = $1, last_used_at = $2
		 WHERE `+column+` = $3`,
		revokedAt.UTC().Format(time.RFC3339Nano),
		revokedAt.UTC().Format(time.RFC3339Nano),
		tokenHash,
	)
	return err
}

func (s *PostgresStore) updateIntegrationJobWithAuditEvent(updateSQL string, updateArgs []any, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(updateSQL, updateArgs...); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_events (event_type, project_id, scan_id, actor, request_id, details, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.ProjectID),
		strings.TrimSpace(event.ScanID),
		strings.TrimSpace(event.Actor),
		strings.TrimSpace(event.RequestID),
		strings.TrimSpace(event.Details),
		event.CreatedAt.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func postgresNotImplemented(method string) error {
	return fmt.Errorf("postgres store: %s not implemented yet", method)
}

func marshalPostgresJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
