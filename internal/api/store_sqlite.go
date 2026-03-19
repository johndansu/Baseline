package api

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	storeSchemaVersionKey     = "schema_version"
	currentStoreSchemaVersion = 14
)

type storeMigration struct {
	version    int
	statements []string
	apply      func(tx *sql.Tx) error
}

// NewStore opens the default SQLite-backed store for local and current production use.
func NewStore(path string) (*Store, error) {
	return NewSQLiteStore(path)
}

// NewSQLiteStore opens a SQLite-backed store and applies SQLite schema migrations.
func NewSQLiteStore(path string) (*Store, error) {
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
	if err := migrateSQLiteStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func migrateSQLiteStore(db *sql.DB) error {
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
					actor TEXT,
					request_id TEXT,
					details TEXT NOT NULL DEFAULT '',
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
		{
			version: 4,
			statements: []string{
				`CREATE TABLE IF NOT EXISTS users (
					id TEXT PRIMARY KEY,
					display_name TEXT,
					email TEXT,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					last_login_at TEXT NOT NULL
				);`,
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
			},
		},
		{
			version: 5,
			apply: func(tx *sql.Tx) error {
				return migrateAuditEventsActorAndRequestIDTx(tx)
			},
		},
		{
			version: 6,
			apply: func(tx *sql.Tx) error {
				return migrateUserAndAPIKeyOwnershipTx(tx)
			},
		},
		{
			version: 7,
			apply: func(tx *sql.Tx) error {
				return migrateProjectAndScanOwnershipTx(tx)
			},
		},
		{
			version: 8,
			apply: func(tx *sql.Tx) error {
				return migrateScanFilesScannedTx(tx)
			},
		},
		{
			version: 9,
			apply: func(tx *sql.Tx) error {
				return migrateAuditEventDetailsTx(tx)
			},
		},
		{
			version: 10,
			apply: func(tx *sql.Tx) error {
				return migrateCLITracesTx(tx)
			},
		},
		{
			version: 11,
			apply: func(tx *sql.Tx) error {
				return migrateCLISessionsTx(tx)
			},
		},
		{
			version: 12,
			apply: func(tx *sql.Tx) error {
				return migrateCLISessionMetadataTx(tx)
			},
		},
		{
			version: 13,
			apply: func(tx *sql.Tx) error {
				return migrateCLISessionCommandMetadataTx(tx)
			},
		},
		{
			version: 14,
			apply: func(tx *sql.Tx) error {
				return migrateCLITraceSessionIDTx(tx)
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
