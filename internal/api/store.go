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
