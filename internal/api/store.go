package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type persistedAPIKey struct {
	KeyHash  string
	Metadata APIKeyMetadata
}

const (
	storeSchemaVersionKey     = "schema_version"
	currentStoreSchemaVersion = 3
)

type storeMigration struct {
	version    int
	statements []string
	apply      func(tx *sql.Tx) error
}

// Store manages persistent API state.
type Store struct {
	db               *sql.DB
	apiKeyHashSecret string
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

// SetAPIKeyHashSecret configures keyed hashing used when persisting API keys.
func (s *Store) SetAPIKeyHashSecret(secret string) {
	if s == nil {
		return
	}
	s.apiKeyHashSecret = strings.TrimSpace(secret)
}

// Close releases database resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping verifies database connectivity for readiness checks.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("store is not initialized")
	}
	return s.db.PingContext(ctx)
}

func migrateStore(db *sql.DB) error {
	if _, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS store_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
	); err != nil {
		return err
	}

	version, err := loadStoreSchemaVersion(db)
	if err != nil {
		return err
	}

	migrations := []storeMigration{
		{
			version: 1,
			statements: []string{
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
			},
		},
		{
			version: 2,
			statements: []string{
				`CREATE INDEX IF NOT EXISTS idx_api_keys_revoked_created_at ON api_keys(revoked, created_at DESC);`,
				`CREATE INDEX IF NOT EXISTS idx_api_keys_id_revoked ON api_keys(id, revoked);`,
				`CREATE INDEX IF NOT EXISTS idx_api_keys_source_created_at ON api_keys(source, created_at DESC);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_events_project_created_at ON audit_events(project_id, created_at DESC);`,
				`CREATE TABLE IF NOT EXISTS projects (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					repository_url TEXT,
					default_branch TEXT NOT NULL DEFAULT 'main',
					policy_set TEXT NOT NULL DEFAULT 'baseline:prod',
					created_at TEXT NOT NULL
				);`,
				`CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC);`,
				`CREATE TABLE IF NOT EXISTS scans (
					id TEXT PRIMARY KEY,
					project_id TEXT NOT NULL,
					commit_sha TEXT,
					status TEXT NOT NULL,
					violations_json TEXT,
					created_at TEXT NOT NULL
				);`,
				`CREATE INDEX IF NOT EXISTS idx_scans_project_created_at ON scans(project_id, created_at DESC);`,
				`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);`,
			},
		},
		{
			version: 3,
			apply: func(tx *sql.Tx) error {
				return migrateAPIKeysToHashedStorageTx(tx)
			},
		},
	}

	for _, migration := range migrations {
		if migration.version <= version {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migration.statements {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if migration.apply != nil {
			if err := migration.apply(tx); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := upsertStoreSchemaVersionTx(tx, migration.version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		version = migration.version
	}

	if version != currentStoreSchemaVersion {
		return fmt.Errorf("store schema version mismatch: expected %d got %d", currentStoreSchemaVersion, version)
	}
	return nil
}

func loadStoreSchemaVersion(db *sql.DB) (int, error) {
	var raw string
	err := db.QueryRow(
		`SELECT value
		 FROM store_meta
		 WHERE key = ?`,
		storeSchemaVersionKey,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	version, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid store schema version %q: %w", raw, err)
	}
	if version < 0 {
		return 0, fmt.Errorf("invalid negative schema version %d", version)
	}
	return version, nil
}

func upsertStoreSchemaVersion(db *sql.DB, version int) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(
		`INSERT INTO store_meta (key, value, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET
		   value = excluded.value,
		   updated_at = excluded.updated_at`,
		storeSchemaVersionKey,
		strconv.Itoa(version),
		now,
	)
	return err
}

func upsertStoreSchemaVersionTx(tx *sql.Tx, version int) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(
		`INSERT INTO store_meta (key, value, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET
		   value = excluded.value,
		   updated_at = excluded.updated_at`,
		storeSchemaVersionKey,
		strconv.Itoa(version),
		now,
	)
	return err
}

func migrateAPIKeysToHashedStorageTx(tx *sql.Tx) error {
	hasKeyHash, err := tableHasColumnTx(tx, "api_keys", "key_hash")
	if err != nil {
		return err
	}
	hasKeyValue, err := tableHasColumnTx(tx, "api_keys", "key_value")
	if err != nil {
		return err
	}
	if hasKeyHash && !hasKeyValue {
		return ensureAPIKeyIndexesTx(tx)
	}
	if !hasKeyValue && !hasKeyHash {
		return errors.New("api_keys table is missing both key_hash and key_value columns")
	}

	if _, err := tx.Exec(`DROP TABLE IF EXISTS api_keys_v3;`); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`CREATE TABLE api_keys_v3 (
			id TEXT PRIMARY KEY,
			key_hash TEXT NOT NULL UNIQUE,
			name TEXT,
			role TEXT NOT NULL,
			prefix TEXT NOT NULL,
			source TEXT,
			created_at TEXT NOT NULL,
			created_by TEXT,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TEXT
		);`,
	); err != nil {
		return err
	}

	query := `SELECT id, `
	if hasKeyHash {
		query += `key_hash`
	} else {
		query += `'' AS key_hash`
	}
	query += `, `
	if hasKeyValue {
		query += `key_value`
	} else {
		query += `'' AS key_value`
	}
	query += `,
		name, role, prefix, source, created_at, created_by, revoked, revoked_at
		FROM api_keys
		ORDER BY created_at DESC`
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, name, roleRaw, prefix, source, createdRaw, createdBy string
			revoked                                                  int
			hashRaw, valueRaw, revokedRaw                            sql.NullString
		)
		if err := rows.Scan(
			&id,
			&hashRaw,
			&valueRaw,
			&name,
			&roleRaw,
			&prefix,
			&source,
			&createdRaw,
			&createdBy,
			&revoked,
			&revokedRaw,
		); err != nil {
			return err
		}
		keyHash := normalizeStoredAPIKeyHash(hashRaw.String)
		if keyHash == "" {
			raw := strings.TrimSpace(valueRaw.String)
			if raw == "" {
				return fmt.Errorf("api key row %s has no key material to hash", strings.TrimSpace(id))
			}
			keyHash = hashAPIKey(raw, "")
		}
		if keyHash == "" {
			return fmt.Errorf("api key row %s resolved to empty key hash", strings.TrimSpace(id))
		}
		if _, err := tx.Exec(
			`INSERT INTO api_keys_v3 (id, key_hash, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(key_hash) DO UPDATE SET
			   id=excluded.id,
			   name=excluded.name,
			   role=excluded.role,
			   prefix=excluded.prefix,
			   source=excluded.source,
			   created_at=excluded.created_at,
			   created_by=excluded.created_by,
			   revoked=excluded.revoked,
			   revoked_at=excluded.revoked_at`,
			strings.TrimSpace(id),
			keyHash,
			strings.TrimSpace(name),
			string(Role(strings.ToLower(strings.TrimSpace(roleRaw)))),
			strings.TrimSpace(prefix),
			strings.TrimSpace(source),
			strings.TrimSpace(createdRaw),
			strings.TrimSpace(createdBy),
			revoked,
			strings.TrimSpace(revokedRaw.String),
		); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := tx.Exec(`DROP TABLE api_keys;`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE api_keys_v3 RENAME TO api_keys;`); err != nil {
		return err
	}
	return ensureAPIKeyIndexesTx(tx)
}

func ensureAPIKeyIndexesTx(tx *sql.Tx) error {
	indexStatements := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_revoked_created_at ON api_keys(revoked, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_id_revoked ON api_keys(id, revoked);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_source_created_at ON api_keys(source, created_at DESC);`,
	}
	for _, stmt := range indexStatements {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func tableHasColumnTx(tx *sql.Tx, tableName, columnName string) (bool, error) {
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA table_info(%s);`, tableName))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	normalized := strings.ToLower(strings.TrimSpace(columnName))
	for rows.Next() {
		var (
			cid      int
			name     string
			dataType string
			notNull  int
			dflt     sql.NullString
			pk       int
		)
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.ToLower(strings.TrimSpace(name)) == normalized {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) UpsertAPIKey(rawKey string, metadata APIKeyMetadata) error {
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
		`INSERT INTO api_keys (id, key_hash, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_hash) DO UPDATE SET
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
		keyHash,
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
	keyHash := hashAPIKey(key, s.apiKeyHashSecret)
	if keyHash == "" {
		return errors.New("empty API key hash")
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return errors.New("missing API key id")
	}
	_, err := s.db.Exec(
		`INSERT INTO api_keys (id, key_hash, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_hash) DO NOTHING`,
		metadata.ID,
		keyHash,
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
		`SELECT id, key_hash, name, role, prefix, source, created_at, created_by, revoked, revoked_at
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
			KeyHash: normalizeStoredAPIKeyHash(keyHash),
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

func hashAPIKey(rawKey, hashSecret string) string {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return ""
	}
	secret := strings.TrimSpace(hashSecret)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(trimmed))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	return "sha256:" + legacyAPIKeyHash(trimmed)
}

func legacyAPIKeyHash(rawKey string) string {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

func normalizeStoredAPIKeyHash(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) == 2 {
		algo := strings.ToLower(strings.TrimSpace(parts[0]))
		digest := strings.ToLower(strings.TrimSpace(parts[1]))
		if algo == "" || digest == "" {
			return ""
		}
		return algo + ":" + digest
	}
	return strings.ToLower(trimmed)
}

func apiKeyHashCandidates(rawKey, hashSecret string) []string {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return []string{}
	}
	legacy := legacyAPIKeyHash(trimmed)
	out := []string{
		hashAPIKey(trimmed, hashSecret),
		"sha256:" + legacy,
		legacy,
	}
	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(out))
	for _, candidate := range out {
		normalized := normalizeStoredAPIKeyHash(candidate)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		deduped = append(deduped, normalized)
	}
	return deduped
}

func constantTimeAPIKeyHashEqual(a, b string) bool {
	left := normalizeStoredAPIKeyHash(a)
	right := normalizeStoredAPIKeyHash(b)
	if left == "" || right == "" {
		return false
	}
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
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
