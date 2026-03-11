package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	currentStoreSchemaVersion = 7
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
					actor TEXT,
					request_id TEXT,
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

func migrateAuditEventsActorAndRequestIDTx(tx *sql.Tx) error {
	hasActor, err := tableHasColumnTx(tx, "audit_events", "actor")
	if err != nil {
		return err
	}
	if !hasActor {
		if _, err := tx.Exec(`ALTER TABLE audit_events ADD COLUMN actor TEXT`); err != nil {
			return err
		}
	}

	hasRequestID, err := tableHasColumnTx(tx, "audit_events", "request_id")
	if err != nil {
		return err
	}
	if !hasRequestID {
		if _, err := tx.Exec(`ALTER TABLE audit_events ADD COLUMN request_id TEXT`); err != nil {
			return err
		}
	}
	return nil
}

func migrateUserAndAPIKeyOwnershipTx(tx *sql.Tx) error {
	if err := ensureColumnWithDefaultTx(tx, "users", "role", "TEXT NOT NULL DEFAULT 'viewer'"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "users", "status", "TEXT NOT NULL DEFAULT 'active'"); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET role = 'viewer' WHERE role IS NULL OR TRIM(role) = ''`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET status = 'active' WHERE status IS NULL OR TRIM(status) = ''`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role, status, updated_at DESC);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`); err != nil {
		return err
	}

	if err := ensureColumnWithDefaultTx(tx, "api_keys", "owner_user_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "api_keys", "owner_subject", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "api_keys", "owner_email", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "api_keys", "created_by_user_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "api_keys", "revoked_by_user_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "api_keys", "revocation_reason", "TEXT"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_owner_user_revoked_created_at ON api_keys(owner_user_id, revoked, created_at DESC);`); err != nil {
		return err
	}
	return nil
}

func migrateProjectAndScanOwnershipTx(tx *sql.Tx) error {
	if err := ensureColumnWithDefaultTx(tx, "projects", "owner_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumnWithDefaultTx(tx, "scans", "owner_id", "TEXT"); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_projects_owner_created_at ON projects(owner_id, created_at DESC);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_scans_owner_created_at ON scans(owner_id, created_at DESC);`); err != nil {
		return err
	}
	return nil
}

func (s *Store) UpsertProject(project Project, now time.Time) error {
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
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name,
		   repository_url = excluded.repository_url,
		   default_branch = excluded.default_branch,
		   policy_set = excluded.policy_set,
		   owner_id = excluded.owner_id`,
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

func (s *Store) LoadProjects() ([]Project, error) {
	if s == nil || s.db == nil {
		return []Project{}, nil
	}
	rows, err := s.db.Query(
		`SELECT id, name, repository_url, default_branch, policy_set, owner_id
		 FROM projects
		 ORDER BY created_at DESC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	projects := []Project{}
	for rows.Next() {
		var id, name, repositoryURL, defaultBranch, policySet sql.NullString
		var ownerID sql.NullString
		if err := rows.Scan(&id, &name, &repositoryURL, &defaultBranch, &policySet, &ownerID); err != nil {
			return nil, err
		}
		projects = append(projects, Project{
			ID:            strings.TrimSpace(id.String),
			Name:          strings.TrimSpace(name.String),
			RepositoryURL: strings.TrimSpace(repositoryURL.String),
			DefaultBranch: strings.TrimSpace(defaultBranch.String),
			PolicySet:     strings.TrimSpace(policySet.String),
			OwnerID:       strings.TrimSpace(ownerID.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return projects, nil
}

func (s *Store) UpdateProjectOwner(projectID, ownerID string) (Project, error) {
	if s == nil || s.db == nil {
		return Project{}, nil
	}
	id := strings.TrimSpace(projectID)
	if id == "" {
		return Project{}, errors.New("project id is required")
	}
	result, err := s.db.Exec(
		`UPDATE projects
		 SET owner_id = ?
		 WHERE id = ?`,
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
	return s.GetProjectByID(id)
}

func (s *Store) GetProjectByID(projectID string) (Project, error) {
	if s == nil || s.db == nil {
		return Project{}, nil
	}
	id := strings.TrimSpace(projectID)
	if id == "" {
		return Project{}, errors.New("project id is required")
	}
	var name, repositoryURL, defaultBranch, policySet sql.NullString
	var ownerID sql.NullString
	err := s.db.QueryRow(
		`SELECT name, repository_url, default_branch, policy_set, owner_id
		 FROM projects
		 WHERE id = ?`,
		id,
	).Scan(&name, &repositoryURL, &defaultBranch, &policySet, &ownerID)
	if err != nil {
		return Project{}, err
	}
	return Project{
		ID:            id,
		Name:          strings.TrimSpace(name.String),
		RepositoryURL: strings.TrimSpace(repositoryURL.String),
		DefaultBranch: strings.TrimSpace(defaultBranch.String),
		PolicySet:     strings.TrimSpace(policySet.String),
		OwnerID:       strings.TrimSpace(ownerID.String),
	}, nil
}

func (s *Store) UpsertScan(scan ScanSummary) error {
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
		`INSERT INTO scans (id, project_id, commit_sha, status, violations_json, created_at, owner_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   project_id = excluded.project_id,
		   commit_sha = excluded.commit_sha,
		   status = excluded.status,
		   violations_json = excluded.violations_json,
		   owner_id = excluded.owner_id`,
		id,
		projectID,
		strings.TrimSpace(scan.CommitSHA),
		strings.TrimSpace(scan.Status),
		string(violationsJSON),
		createdAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(scan.OwnerID),
	)
	return err
}

func (s *Store) LoadScans(limit int) ([]ScanSummary, error) {
	if s == nil || s.db == nil {
		return []ScanSummary{}, nil
	}
	maxRows := limit
	if maxRows <= 0 {
		maxRows = 1000
	}
	rows, err := s.db.Query(
		`SELECT id, project_id, commit_sha, status, violations_json, created_at, owner_id
		 FROM scans
		 ORDER BY created_at DESC, id ASC
		 LIMIT ?`,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scans := []ScanSummary{}
	for rows.Next() {
		var id, projectID, commitSHA, status, violationsRaw, createdRaw sql.NullString
		var ownerID sql.NullString
		if err := rows.Scan(&id, &projectID, &commitSHA, &status, &violationsRaw, &createdRaw, &ownerID); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdRaw.String)
		if err != nil {
			return nil, err
		}
		violations := []ScanViolation{}
		if strings.TrimSpace(violationsRaw.String) != "" {
			if err := json.Unmarshal([]byte(violationsRaw.String), &violations); err != nil {
				return nil, err
			}
		}
		scans = append(scans, ScanSummary{
			ID:         strings.TrimSpace(id.String),
			ProjectID:  strings.TrimSpace(projectID.String),
			CommitSHA:  strings.TrimSpace(commitSHA.String),
			Status:     strings.TrimSpace(status.String),
			Violations: violations,
			CreatedAt:  createdAt,
			OwnerID:    strings.TrimSpace(ownerID.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scans, nil
}

func ensureColumnWithDefaultTx(tx *sql.Tx, tableName, columnName, columnDDL string) error {
	hasColumn, err := tableHasColumnTx(tx, tableName, columnName)
	if err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	_, err = tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, columnName, columnDDL))
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
		`INSERT INTO api_keys (
			id, key_hash, name, role, prefix, source, owner_user_id, owner_subject, owner_email,
			created_at, created_by, created_by_user_id, revoked, revoked_at, revoked_by_user_id, revocation_reason
		)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_hash) DO UPDATE SET
		   id=excluded.id,
		   name=excluded.name,
		   role=excluded.role,
		   prefix=excluded.prefix,
		   source=excluded.source,
		   owner_user_id=excluded.owner_user_id,
		   owner_subject=excluded.owner_subject,
		   owner_email=excluded.owner_email,
		   created_at=excluded.created_at,
		   created_by=excluded.created_by,
		   created_by_user_id=excluded.created_by_user_id,
		   revoked=excluded.revoked,
		   revoked_at=excluded.revoked_at,
		   revoked_by_user_id=excluded.revoked_by_user_id,
		   revocation_reason=excluded.revocation_reason`,
		metadata.ID,
		keyHash,
		strings.TrimSpace(metadata.Name),
		string(metadata.Role),
		strings.TrimSpace(metadata.Prefix),
		strings.TrimSpace(metadata.Source),
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
		`INSERT INTO api_keys (
			id, key_hash, name, role, prefix, source, owner_user_id, owner_subject, owner_email,
			created_at, created_by, created_by_user_id, revoked, revoked_at, revoked_by_user_id, revocation_reason
		)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

func (s *Store) LoadAPIKeys() ([]persistedAPIKey, error) {
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
				ID:               id,
				Name:             name,
				Role:             Role(strings.ToLower(strings.TrimSpace(roleRaw))),
				Prefix:           prefix,
				Source:           source,
				OwnerUserID:      strings.TrimSpace(ownerUserID.String),
				OwnerSubject:     strings.TrimSpace(ownerSubject.String),
				OwnerEmail:       strings.ToLower(strings.TrimSpace(ownerEmail.String)),
				CreatedAt:        createdAt,
				CreatedBy:        createdBy,
				CreatedByUserID:  strings.TrimSpace(createdByUserID.String),
				Revoked:          revoked != 0,
				RevokedAt:        revokedAt,
				RevokedByUserID:  strings.TrimSpace(revokedByUserID.String),
				RevocationReason: strings.TrimSpace(revocationReason.String),
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) RevokeAPIKey(id string, revokedAt time.Time) error {
	return s.RevokeAPIKeyWithContext(id, revokedAt, "", "")
}

func (s *Store) RevokeAPIKeyWithContext(id string, revokedAt time.Time, revokedByUserID, reason string) error {
	if s == nil || s.db == nil {
		return nil
	}
	keyID := strings.TrimSpace(id)
	if keyID == "" {
		return errors.New("api key id is required")
	}
	result, err := s.db.Exec(
		`UPDATE api_keys
		 SET revoked = 1, revoked_at = ?, revoked_by_user_id = ?, revocation_reason = ?
		 WHERE id = ?`,
		revokedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(revokedByUserID),
		strings.TrimSpace(reason),
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
		insertAuditEventSQL(),
		auditEventInsertArgs(event)...,
	)
	return err
}

func insertAuditEventSQL() string {
	return `INSERT INTO audit_events (event_type, project_id, scan_id, actor, request_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`
}

func auditEventInsertArgs(event AuditEvent) []any {
	return []any{
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.ProjectID),
		strings.TrimSpace(event.ScanID),
		strings.TrimSpace(event.Actor),
		strings.TrimSpace(event.RequestID),
		event.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
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
		`SELECT event_type, project_id, scan_id, actor, request_id, created_at
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
		var eventType, createdRaw string
		var projectID, scanID, actor, requestID sql.NullString
		if err := rows.Scan(&eventType, &projectID, &scanID, &actor, &requestID, &createdRaw); err != nil {
			return nil, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return nil, err
		}
		out = append(out, AuditEvent{
			EventType: eventType,
			ProjectID: strings.TrimSpace(projectID.String),
			ScanID:    strings.TrimSpace(scanID.String),
			Actor:     strings.TrimSpace(actor.String),
			RequestID: strings.TrimSpace(requestID.String),
			CreatedAt: createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListAuditEventsByActors(actors []string, limit, offset int, eventType string, from, to *time.Time) (UserListResult, []AuditEvent, error) {
	if s == nil || s.db == nil {
		return UserListResult{Limit: limit, Offset: offset}, []AuditEvent{}, nil
	}
	if len(actors) == 0 {
		return UserListResult{Limit: limit, Offset: offset}, []AuditEvent{}, nil
	}

	maxRows := limit
	if maxRows <= 0 || maxRows > 200 {
		maxRows = 50
	}
	start := offset
	if start < 0 {
		start = 0
	}

	placeholders := make([]string, 0, len(actors))
	args := make([]any, 0, len(actors))
	for _, actor := range actors {
		value := strings.TrimSpace(actor)
		if value == "" {
			continue
		}
		placeholders = append(placeholders, "?")
		args = append(args, value)
	}
	if len(placeholders) == 0 {
		return UserListResult{Limit: maxRows, Offset: start}, []AuditEvent{}, nil
	}

	whereClauses := []string{"actor IN (" + strings.Join(placeholders, ",") + ")"}
	filteredEventType := strings.TrimSpace(strings.ToLower(eventType))
	if filteredEventType != "" {
		whereClauses = append(whereClauses, "event_type = ?")
		args = append(args, filteredEventType)
	}
	if from != nil {
		whereClauses = append(whereClauses, "julianday(created_at) >= julianday(?)")
		args = append(args, from.UTC().Format(time.RFC3339Nano))
	}
	if to != nil {
		whereClauses = append(whereClauses, "julianday(created_at) <= julianday(?)")
		args = append(args, to.UTC().Format(time.RFC3339Nano))
	}

	where := " WHERE " + strings.Join(whereClauses, " AND ")

	var totalQueryBuilder strings.Builder
	totalQueryBuilder.WriteString("SELECT COUNT(1) FROM audit_events")
	totalQueryBuilder.WriteString(where)
	totalQuery := totalQueryBuilder.String()
	var total int
	if err := s.db.QueryRow(totalQuery, args...).Scan(&total); err != nil {
		return UserListResult{}, nil, err
	}

	var queryBuilder strings.Builder
	queryBuilder.WriteString("SELECT event_type, project_id, scan_id, actor, request_id, created_at FROM audit_events")
	queryBuilder.WriteString(where)
	queryBuilder.WriteString(" ORDER BY created_at DESC LIMIT ? OFFSET ?")
	query := queryBuilder.String()
	queryArgs := append(append([]any{}, args...), maxRows, start)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return UserListResult{}, nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		var eventType, createdRaw string
		var projectID, scanID, actor, requestID sql.NullString
		if err := rows.Scan(&eventType, &projectID, &scanID, &actor, &requestID, &createdRaw); err != nil {
			return UserListResult{}, nil, err
		}
		createdAt, err := parseStoredTime(createdRaw)
		if err != nil {
			return UserListResult{}, nil, err
		}
		out = append(out, AuditEvent{
			EventType: eventType,
			ProjectID: strings.TrimSpace(projectID.String),
			ScanID:    strings.TrimSpace(scanID.String),
			Actor:     strings.TrimSpace(actor.String),
			RequestID: strings.TrimSpace(requestID.String),
			CreatedAt: createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return UserListResult{}, nil, err
	}

	hasMore := start+len(out) < total
	meta := UserListResult{
		Total:   total,
		Limit:   maxRows,
		Offset:  start,
		HasMore: hasMore,
	}
	return meta, out, nil
}

func (s *Store) UpsertOIDCUser(provider, subject, email, displayName string, now time.Time) (string, error) {
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
	defer func() {
		_ = tx.Rollback()
	}()

	var userID string
	err = tx.QueryRow(
		`SELECT user_id
		 FROM user_identities
		 WHERE provider = ? AND subject = ?`,
		providerKey,
		subjectKey,
	).Scan(&userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	if errors.Is(err, sql.ErrNoRows) {
		userID = "usr_" + randomToken(12)
		if strings.TrimSpace(userID) == "usr_" {
			userID = fmt.Sprintf("usr_%d", time.Now().UTC().UnixNano())
		}
		_, err = tx.Exec(
			`INSERT INTO users (id, display_name, email, created_at, updated_at, last_login_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
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
			 VALUES (?, ?, ?, ?, ?, ?)`,
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
	if scanErr := tx.QueryRow(`SELECT display_name, email FROM users WHERE id = ?`, userID).Scan(&currentName, &currentEmail); scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
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
		 SET display_name = ?, email = ?, updated_at = ?, last_login_at = ?
		 WHERE id = ?`,
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
		 VALUES (?, ?, ?, ?, ?, ?)
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

type UserListFilter struct {
	Limit   int
	Offset  int
	SortBy  string
	SortDir string
	Role    Role
	Status  UserStatus
	Query   string
}

type UserListResult struct {
	Users   []UserRecord
	Total   int
	Limit   int
	Offset  int
	HasMore bool
}

func (s *Store) ListUsers(filter UserListFilter) ([]UserRecord, error) {
	result, err := s.ListUsersPage(filter)
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

func (s *Store) ListUsersPage(filter UserListFilter) (UserListResult, error) {
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
		 WHERE (? = '' OR role = ?)
		   AND (? = '' OR status = ?)
		   AND (? = '' OR lower(display_name) LIKE '%' || ? || '%' OR lower(email) LIKE '%' || ? || '%')`,
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
		 WHERE (? = '' OR role = ?)
		   AND (? = '' OR status = ?)
		   AND (? = '' OR lower(display_name) LIKE '%%' || ? || '%%' OR lower(email) LIKE '%%' || ? || '%%')
		 ORDER BY %s %s, id ASC
		 LIMIT ? OFFSET ?`,
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

func (s *Store) GetUserByID(userID string) (UserRecord, bool, error) {
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
		 WHERE id = ?`,
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

func (s *Store) UpdateUserRoleAndStatus(userID string, role Role, status UserStatus, updatedAt time.Time) (UserRecord, error) {
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
		 SET role = ?, status = ?, updated_at = ?
		 WHERE id = ?`,
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

func (s *Store) ListAPIKeysByOwnerUserID(ownerUserID string, includeRevoked bool, limit int) ([]APIKeyMetadata, error) {
	if s == nil || s.db == nil {
		return []APIKeyMetadata{}, nil
	}
	ownerID := strings.TrimSpace(ownerUserID)
	if ownerID == "" {
		return []APIKeyMetadata{}, errors.New("owner user id is required")
	}
	maxRows := limit
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 100
	}
	revokedFilter := 0
	if includeRevoked {
		revokedFilter = 1
	}

	rows, err := s.db.Query(
		`SELECT id, name, role, prefix, source, owner_user_id, owner_subject, owner_email,
		        created_at, created_by, created_by_user_id, revoked, revoked_at, revoked_by_user_id, revocation_reason
		 FROM api_keys
		 WHERE owner_user_id = ?
		   AND (? = 1 OR revoked = 0)
		 ORDER BY created_at DESC
		 LIMIT ?`,
		ownerID,
		revokedFilter,
		maxRows,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIKeyMetadata{}
	for rows.Next() {
		var (
			id, name, roleRaw, prefix, source, createdRaw, createdBy string
			ownerUser, ownerSubject, ownerEmail                      sql.NullString
			createdByUserID, revokedByUserID, revocationReason       sql.NullString
			revoked                                                  int
			revokedRaw                                               sql.NullString
		)
		if err := rows.Scan(
			&id,
			&name,
			&roleRaw,
			&prefix,
			&source,
			&ownerUser,
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
		out = append(out, APIKeyMetadata{
			ID:               strings.TrimSpace(id),
			Name:             strings.TrimSpace(name),
			Role:             Role(strings.ToLower(strings.TrimSpace(roleRaw))),
			Prefix:           strings.TrimSpace(prefix),
			Source:           strings.TrimSpace(source),
			OwnerUserID:      strings.TrimSpace(ownerUser.String),
			OwnerSubject:     strings.TrimSpace(ownerSubject.String),
			OwnerEmail:       strings.ToLower(strings.TrimSpace(ownerEmail.String)),
			CreatedAt:        createdAt,
			CreatedBy:        strings.TrimSpace(createdBy),
			CreatedByUserID:  strings.TrimSpace(createdByUserID.String),
			Revoked:          revoked != 0,
			RevokedAt:        revokedAt,
			RevokedByUserID:  strings.TrimSpace(revokedByUserID.String),
			RevocationReason: strings.TrimSpace(revocationReason.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpsertAuthSession(rawToken string, session dashboardSession, now time.Time) error {
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')
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

func (s *Store) LoadAuthSession(rawToken string, now time.Time) (dashboardSession, bool, error) {
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
		 WHERE token_hash = ?`,
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
			 SET revoked = 1, revoked_at = ?, last_seen_at = ?
			 WHERE token_hash = ?`,
			nowRaw,
			nowRaw,
			tokenHash,
		)
		return dashboardSession{}, false, nil
	}

	_, _ = s.db.Exec(
		`UPDATE auth_sessions
		 SET last_seen_at = ?
		 WHERE token_hash = ?`,
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

func (s *Store) RevokeAuthSession(rawToken string, revokedAt time.Time) error {
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
		 SET revoked = 1, revoked_at = ?, last_seen_at = ?
		 WHERE token_hash = ?`,
		revokedRaw,
		revokedRaw,
		tokenHash,
	)
	return err
}

func (s *Store) CountActiveAuthSessions(now time.Time) (int, error) {
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
		 WHERE revoked = 0 AND expires_at > ?`,
		now.UTC().Format(time.RFC3339Nano),
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
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

func (s *Store) MarkIntegrationJobSucceededWithAuditEvent(id string, now time.Time, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.updateIntegrationJobWithAuditEvent(
		`UPDATE integration_jobs
		 SET status = ?, last_error = '', next_attempt_at = ?, updated_at = ?
		 WHERE id = ?`,
		[]any{
			IntegrationJobSucceeded,
			now.UTC().Format(time.RFC3339Nano),
			now.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(id),
		},
		event,
	)
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

func (s *Store) MarkIntegrationJobRetryWithAuditEvent(id, lastError string, nextAttemptAt, now time.Time, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.updateIntegrationJobWithAuditEvent(
		`UPDATE integration_jobs
		 SET status = ?, last_error = ?, next_attempt_at = ?, updated_at = ?
		 WHERE id = ?`,
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

func (s *Store) MarkIntegrationJobFailed(id, lastError string, now time.Time) error {
	return s.MarkIntegrationJobRetry(id, lastError, now, now)
}

func (s *Store) MarkIntegrationJobFailedWithAuditEvent(id, lastError string, now time.Time, event AuditEvent) error {
	return s.MarkIntegrationJobRetryWithAuditEvent(id, lastError, now, now, event)
}

func (s *Store) updateIntegrationJobWithAuditEvent(updateSQL string, updateArgs []any, event AuditEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(updateSQL, updateArgs...); err != nil {
		return err
	}
	if _, err := tx.Exec(insertAuditEventSQL(), auditEventInsertArgs(event)...); err != nil {
		return err
	}
	return tx.Commit()
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

type userRecordScanner interface {
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

func scanUserRecord(scanner userRecordScanner) (UserRecord, error) {
	var (
		user                                       UserRecord
		id, displayName, email, roleRaw, statusRaw string
		lastLoginRaw, createdRaw, updatedRaw       string
	)
	if err := scanner.Scan(
		&id,
		&displayName,
		&email,
		&roleRaw,
		&statusRaw,
		&lastLoginRaw,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return UserRecord{}, err
	}
	lastLoginAt, err := parseStoredTime(lastLoginRaw)
	if err != nil {
		return UserRecord{}, err
	}
	createdAt, err := parseStoredTime(createdRaw)
	if err != nil {
		return UserRecord{}, err
	}
	updatedAt, err := parseStoredTime(updatedRaw)
	if err != nil {
		return UserRecord{}, err
	}
	user = UserRecord{
		ID:          strings.TrimSpace(id),
		DisplayName: strings.TrimSpace(displayName),
		Email:       strings.ToLower(strings.TrimSpace(email)),
		Role:        Role(strings.ToLower(strings.TrimSpace(roleRaw))),
		Status:      UserStatus(strings.ToLower(strings.TrimSpace(statusRaw))),
		LastLoginAt: lastLoginAt,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if !isValidRole(user.Role) {
		user.Role = RoleViewer
	}
	if !isValidUserStatus(user.Status) {
		user.Status = UserStatusActive
	}
	return user, nil
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
