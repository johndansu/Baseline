package api

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStoreBootstrapsVersionedSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh_store.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	version := currentStoreSchemaVersionForTest(t, store.db)
	if version != currentStoreSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", currentStoreSchemaVersion, version)
	}

	for _, table := range []string{
		"store_meta",
		"api_keys",
		"audit_events",
		"integration_jobs",
		"projects",
		"scans",
	} {
		assertSQLiteObjectExists(t, store.db, "table", table)
	}

	for _, index := range []string{
		"idx_audit_events_created_at",
		"idx_integration_jobs_due",
		"idx_api_keys_revoked_created_at",
		"idx_api_keys_id_revoked",
		"idx_api_keys_source_created_at",
		"idx_audit_events_project_created_at",
		"idx_projects_created_at",
		"idx_scans_project_created_at",
		"idx_scans_created_at",
	} {
		assertSQLiteObjectExists(t, store.db, "index", index)
	}

	now := time.Now().UTC()
	apiKey := "fresh-bootstrap-key"
	meta := APIKeyMetadata{
		ID:        "key_fresh_bootstrap",
		Name:      "fresh-key",
		Role:      RoleAdmin,
		Prefix:    keyPrefix(apiKey),
		Source:    "bootstrap",
		CreatedAt: now,
		CreatedBy: "test",
	}
	if err := store.UpsertAPIKey(apiKey, meta); err != nil {
		t.Fatalf("UpsertAPIKey returned error: %v", err)
	}
	keys, err := store.LoadAPIKeys()
	if err != nil {
		t.Fatalf("LoadAPIKeys returned error: %v", err)
	}
	if len(keys) != 1 || keys[0].Metadata.ID != meta.ID {
		t.Fatalf("unexpected api keys after bootstrap: %+v", keys)
	}

	event := AuditEvent{
		EventType: "fresh_bootstrap_validated",
		ProjectID: "proj_fresh",
		ScanID:    "scan_fresh",
		CreatedAt: now,
	}
	if err := store.AppendAuditEvent(event); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}
	events, err := store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents returned error: %v", err)
	}
	if len(events) == 0 || events[0].EventType != event.EventType {
		t.Fatalf("unexpected audit events after bootstrap: %+v", events)
	}
}

func TestNewStoreMigratesLegacySchemaAndPreservesData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_store.db")
	createLegacyStoreSchema(t, dbPath)

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error for legacy db: %v", err)
	}
	defer store.Close()

	version := currentStoreSchemaVersionForTest(t, store.db)
	if version != currentStoreSchemaVersion {
		t.Fatalf("expected upgraded schema version %d, got %d", currentStoreSchemaVersion, version)
	}

	for _, table := range []string{"projects", "scans", "store_meta"} {
		assertSQLiteObjectExists(t, store.db, "table", table)
	}
	for _, index := range []string{
		"idx_api_keys_revoked_created_at",
		"idx_api_keys_id_revoked",
		"idx_audit_events_project_created_at",
		"idx_scans_project_created_at",
	} {
		assertSQLiteObjectExists(t, store.db, "index", index)
	}

	keys, err := store.LoadAPIKeys()
	if err != nil {
		t.Fatalf("LoadAPIKeys returned error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected one legacy key after migration, got %d", len(keys))
	}
	if keys[0].Metadata.ID != "legacy_key_id" || keys[0].Key != "legacy-key-value" {
		t.Fatalf("legacy api key was not preserved: %+v", keys[0])
	}

	events, err := store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents returned error: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "legacy_event" {
		t.Fatalf("legacy audit event was not preserved: %+v", events)
	}
}

func createLegacyStoreSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("failed to open legacy db: %v", err)
	}
	defer db.Close()

	legacyStatements := []string{
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
	for _, stmt := range legacyStatements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to create legacy schema: %v", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(
		`INSERT INTO api_keys (id, key_value, name, role, prefix, source, created_at, created_by, revoked, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy_key_id",
		"legacy-key-value",
		"legacy-key",
		"admin",
		keyPrefix("legacy-key-value"),
		"bootstrap",
		now,
		"legacy-env",
		0,
		"",
	); err != nil {
		t.Fatalf("failed to seed legacy api key: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_events (event_type, project_id, scan_id, created_at)
		 VALUES (?, ?, ?, ?)`,
		"legacy_event",
		"legacy_project",
		"legacy_scan",
		now,
	); err != nil {
		t.Fatalf("failed to seed legacy audit event: %v", err)
	}
}

func currentStoreSchemaVersionForTest(t *testing.T, db *sql.DB) int {
	t.Helper()
	version, err := loadStoreSchemaVersion(db)
	if err != nil {
		t.Fatalf("loadStoreSchemaVersion returned error: %v", err)
	}
	return version
}

func assertSQLiteObjectExists(t *testing.T, db *sql.DB, objectType, objectName string) {
	t.Helper()
	var exists int
	err := db.QueryRow(
		`SELECT 1
		 FROM sqlite_master
		 WHERE type = ? AND name = ?
		 LIMIT 1`,
		objectType,
		objectName,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("expected %s %q to exist: %v", objectType, objectName, err)
	}
}
