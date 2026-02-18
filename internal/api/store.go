package api

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type persistedAPIKey struct {
	Key      string
	Metadata APIKeyMetadata
}

// Store manages persistent API state.
type Store struct {
	db *sql.DB
}

// NewStore opens a SQLite-backed store and applies schema migrations.
func NewStore(path string) (*Store, error) {
	dbPath := strings.TrimSpace(path)
	if dbPath == "" {
		return nil, errors.New("database path is required")
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases database resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func migrateStore(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			key_value TEXT NOT NULL UNIQUE,
			name TEXT,
			role TEXT NOT NULL,
			prefix TEXT NOT NULL,
			source TEXT,
			created_at TEXT NOT NULL,
			created_by TEXT,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			project_id TEXT,
			scan_id TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);`,
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
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertAPIKey(rawKey string, metadata APIKeyMetadata) error {
	if s == nil || s.db == nil {
		return nil
	}
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return errors.New("empty API key")
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return errors.New("missing API key id")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_keys (id, key_value, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_value) DO UPDATE SET
		   id=excluded.id,
		   name=excluded.name,
		   role=excluded.role,
		   prefix=excluded.prefix,
		   source=excluded.source,
		   created_at=excluded.created_at,
		   created_by=excluded.created_by,
		   revoked=excluded.revoked,
		   revoked_at=excluded.revoked_at`,
		metadata.ID,
		key,
		strings.TrimSpace(metadata.Name),
		string(metadata.Role),
		strings.TrimSpace(metadata.Prefix),
		strings.TrimSpace(metadata.Source),
		metadata.CreatedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(metadata.CreatedBy),
		boolToInt(metadata.Revoked),
		timePtrToString(metadata.RevokedAt),
	)
	return err
}

func (s *Store) EnsureBootstrapAPIKey(rawKey string, metadata APIKeyMetadata) error {
	if s == nil || s.db == nil {
		return nil
	}
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return errors.New("empty API key")
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return errors.New("missing API key id")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_keys (id, key_value, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_value) DO NOTHING`,
		metadata.ID,
		key,
		strings.TrimSpace(metadata.Name),
		string(metadata.Role),
		strings.TrimSpace(metadata.Prefix),
		"bootstrap",
		metadata.CreatedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(metadata.CreatedBy),
		boolToInt(metadata.Revoked),
		timePtrToString(metadata.RevokedAt),
	)
	return err
}

func (s *Store) LoadAPIKeys() ([]persistedAPIKey, error) {
	if s == nil || s.db == nil {
		return []persistedAPIKey{}, nil
	}
	rows, err := s.db.Query(
		`SELECT id, key_value, name, role, prefix, source, created_at, created_by, revoked, revoked_at
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
			id, keyValue, name, roleRaw, prefix, source, createdRaw, createdBy string
			revoked                                                            int
			revokedRaw                                                         sql.NullString
		)
		if err := rows.Scan(
			&id,
			&keyValue,
			&name,
			&roleRaw,
			&prefix,
			&source,
			&createdRaw,
			&createdBy,
			&revoked,
			&revokedRaw,
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
			Key: keyValue,
			Metadata: APIKeyMetadata{
				ID:        id,
				Name:      name,
				Role:      Role(strings.ToLower(strings.TrimSpace(roleRaw))),
				Prefix:    prefix,
				Source:    source,
				CreatedAt: createdAt,
				CreatedBy: createdBy,
				Revoked:   revoked != 0,
				RevokedAt: revokedAt,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) RevokeAPIKey(id string, revokedAt time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	keyID := strings.TrimSpace(id)
	if keyID == "" {
		return errors.New("api key id is required")
	}
	result, err := s.db.Exec(
		`UPDATE api_keys
		 SET revoked = 1, revoked_at = ?
		 WHERE id = ?`,
		revokedAt.UTC().Format(time.RFC3339Nano),
		keyID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key %s not found", keyID)
	}
	return nil
}

func (s *Store) AppendAuditEvent(event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_events (event_type, project_id, scan_id, created_at)
		 VALUES (?, ?, ?, ?)`,
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.ProjectID),
		strings.TrimSpace(event.ScanID),
		event.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) LoadAuditEvents(limit int) ([]AuditEvent, error) {
	if s == nil || s.db == nil {
		return []AuditEvent{}, nil
	}
	maxRows := limit
	if maxRows <= 0 {
		maxRows = 500
	}
	rows, err := s.db.Query(
		`SELECT event_type, project_id, scan_id, created_at
		 FROM audit_events
		 ORDER BY created_at DESC
		 LIMIT ?`,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		var eventType, projectID, scanID, createdRaw string
		if err := rows.Scan(&eventType, &projectID, &scanID, &createdRaw); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return nil, err
		}
		out = append(out, AuditEvent{
			EventType: eventType,
			ProjectID: projectID,
			ScanID:    scanID,
			CreatedAt: createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) EnqueueIntegrationJob(job IntegrationJob) (IntegrationJob, error) {
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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

func (s *Store) ClaimDueIntegrationJob(now time.Time) (*IntegrationJob, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	current := now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var id string
	err = tx.QueryRow(
		`SELECT id
		 FROM integration_jobs
		 WHERE status IN (?, ?)
		   AND attempt_count < max_attempts
		   AND next_attempt_at <= ?
		 ORDER BY created_at ASC
		 LIMIT 1`,
		IntegrationJobPending,
		IntegrationJobFailed,
		current.Format(time.RFC3339Nano),
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	result, err := tx.Exec(
		`UPDATE integration_jobs
		 SET status = ?, attempt_count = attempt_count + 1, updated_at = ?
		 WHERE id = ? AND status IN (?, ?)`,
		IntegrationJobRunning,
		current.Format(time.RFC3339Nano),
		id,
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

	row := tx.QueryRow(
		`SELECT id, provider, job_type, project_ref, external_ref, payload, status, attempt_count,
		        max_attempts, last_error, next_attempt_at, created_at, updated_at
		 FROM integration_jobs
		 WHERE id = ?`,
		id,
	)
	job, err := scanIntegrationJob(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *Store) MarkIntegrationJobSucceeded(id string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	jobID := strings.TrimSpace(id)
	if jobID == "" {
		return errors.New("integration job id is required")
	}
	_, err := s.db.Exec(
		`UPDATE integration_jobs
		 SET status = ?, last_error = '', next_attempt_at = ?, updated_at = ?
		 WHERE id = ?`,
		IntegrationJobSucceeded,
		now.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
		jobID,
	)
	return err
}

func (s *Store) MarkIntegrationJobRetry(id, lastError string, nextAttemptAt, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	jobID := strings.TrimSpace(id)
	if jobID == "" {
		return errors.New("integration job id is required")
	}
	_, err := s.db.Exec(
		`UPDATE integration_jobs
		 SET status = ?, last_error = ?, next_attempt_at = ?, updated_at = ?
		 WHERE id = ?`,
		IntegrationJobFailed,
		strings.TrimSpace(lastError),
		nextAttemptAt.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
		jobID,
	)
	return err
}

func (s *Store) MarkIntegrationJobFailed(id, lastError string, now time.Time) error {
	return s.MarkIntegrationJobRetry(id, lastError, now, now)
}

func (s *Store) ListIntegrationJobs(limit int) ([]IntegrationJob, error) {
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
		 LIMIT ?`,
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

type integrationJobScanner interface {
	Scan(dest ...any) error
}

func scanIntegrationJob(scanner integrationJobScanner) (IntegrationJob, error) {
	var (
		job                                    IntegrationJob
		nextAttemptRaw, createdRaw, updatedRaw string
	)
	if err := scanner.Scan(
		&job.ID,
		&job.Provider,
		&job.JobType,
		&job.ProjectRef,
		&job.ExternalRef,
		&job.Payload,
		&job.Status,
		&job.AttemptCount,
		&job.MaxAttempts,
		&job.LastError,
		&nextAttemptRaw,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return IntegrationJob{}, err
	}
	nextAttemptAt, err := parseStoredTime(nextAttemptRaw)
	if err != nil {
		return IntegrationJob{}, err
	}
	createdAt, err := parseStoredTime(createdRaw)
	if err != nil {
		return IntegrationJob{}, err
	}
	updatedAt, err := parseStoredTime(updatedRaw)
	if err != nil {
		return IntegrationJob{}, err
	}
	job.NextAttemptAt = nextAttemptAt
	job.CreatedAt = createdAt
	job.UpdatedAt = updatedAt
	return job, nil
}

func parseStoredTime(value string) (time.Time, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return time.Time{}, errors.New("missing timestamp")
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func timePtrToString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
