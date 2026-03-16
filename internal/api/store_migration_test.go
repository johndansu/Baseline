package api

import (
	"database/sql"
	"path/filepath"
	"strings"
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
		"users",
		"user_identities",
		"auth_sessions",
	} {
		assertSQLiteObjectExists(t, store.db, "table", table)
	}

	for _, index := range []string{
		"idx_api_keys_key_hash",
		"idx_audit_events_created_at",
		"idx_integration_jobs_due",
		"idx_api_keys_revoked_created_at",
		"idx_api_keys_id_revoked",
		"idx_api_keys_source_created_at",
		"idx_api_keys_owner_user_revoked_created_at",
		"idx_audit_events_project_created_at",
		"idx_projects_created_at",
		"idx_scans_project_created_at",
		"idx_scans_created_at",
		"idx_user_identities_user_id",
		"idx_auth_sessions_active",
		"idx_auth_sessions_user_id",
		"idx_users_role_status",
		"idx_users_email",
	} {
		assertSQLiteObjectExists(t, store.db, "index", index)
	}
	assertSQLiteColumnExists(t, store.db, "users", "role")
	assertSQLiteColumnExists(t, store.db, "users", "status")
	assertSQLiteColumnExists(t, store.db, "api_keys", "owner_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "created_by_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "revoked_by_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "revocation_reason")
	assertSQLiteColumnExists(t, store.db, "audit_events", "details")

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
	if keys[0].KeyHash != hashAPIKey(apiKey, "") {
		t.Fatalf("expected hashed api key material, got %q", keys[0].KeyHash)
	}

	event := AuditEvent{
		EventType: "fresh_bootstrap_validated",
		ProjectID: "proj_fresh",
		ScanID:    "scan_fresh",
		Details:   "command scan | status ok",
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
	if events[0].Details != event.Details {
		t.Fatalf("expected audit details %q, got %q", event.Details, events[0].Details)
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
		"idx_api_keys_key_hash",
		"idx_api_keys_revoked_created_at",
		"idx_api_keys_id_revoked",
		"idx_api_keys_owner_user_revoked_created_at",
		"idx_audit_events_project_created_at",
		"idx_scans_project_created_at",
		"idx_user_identities_user_id",
		"idx_auth_sessions_active",
		"idx_users_role_status",
		"idx_users_email",
	} {
		assertSQLiteObjectExists(t, store.db, "index", index)
	}
	assertSQLiteColumnExists(t, store.db, "users", "role")
	assertSQLiteColumnExists(t, store.db, "users", "status")
	assertSQLiteColumnExists(t, store.db, "api_keys", "owner_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "created_by_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "revoked_by_user_id")
	assertSQLiteColumnExists(t, store.db, "api_keys", "revocation_reason")
	assertSQLiteColumnExists(t, store.db, "audit_events", "details")

	keys, err := store.LoadAPIKeys()
	if err != nil {
		t.Fatalf("LoadAPIKeys returned error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected one legacy key after migration, got %d", len(keys))
	}
	if keys[0].Metadata.ID != "legacy_key_id" || keys[0].KeyHash != hashAPIKey("legacy-key-value", "") {
		t.Fatalf("legacy api key was not preserved: %+v", keys[0])
	}
	assertSQLiteColumnMissing(t, store.db, "api_keys", "key_value")
	assertSQLiteColumnExists(t, store.db, "api_keys", "key_hash")

	events, err := store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents returned error: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "legacy_event" {
		t.Fatalf("legacy audit event was not preserved: %+v", events)
	}
	if events[0].Details != "" {
		t.Fatalf("expected migrated legacy audit event details to default empty string, got %q", events[0].Details)
	}
}

func TestStoreAuthPersistenceLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth_persistence.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser(
		"https://issuer.example.com",
		"subject-123",
		"Person@Example.com",
		"Person Example",
		now,
	)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}
	if strings.TrimSpace(userID) == "" {
		t.Fatal("expected non-empty user id from UpsertOIDCUser")
	}

	userID2, err := store.UpsertOIDCUser(
		"https://issuer.example.com",
		"subject-123",
		"updated@example.com",
		"Updated Person",
		now.Add(1*time.Minute),
	)
	if err != nil {
		t.Fatalf("UpsertOIDCUser (existing identity) returned error: %v", err)
	}
	if userID2 != userID {
		t.Fatalf("expected stable user id for existing identity, got %q vs %q", userID2, userID)
	}

	token := "session-token-1"
	session := dashboardSession{
		UserID:     userID,
		Role:       RoleViewer,
		User:       "updated@example.com",
		Subject:    "subject-123",
		Email:      "updated@example.com",
		AuthSource: "oidc",
		ExpiresAt:  now.Add(1 * time.Hour),
	}
	if err := store.UpsertAuthSession(token, session, now); err != nil {
		t.Fatalf("UpsertAuthSession returned error: %v", err)
	}

	loaded, found, err := store.LoadAuthSession(token, now.Add(1*time.Second))
	if err != nil {
		t.Fatalf("LoadAuthSession returned error: %v", err)
	}
	if !found {
		t.Fatal("expected persisted auth session to be found")
	}
	if loaded.UserID != userID || loaded.User != session.User || loaded.Email != session.Email || loaded.Role != session.Role {
		t.Fatalf("unexpected loaded auth session: %+v", loaded)
	}

	activeCount, err := store.CountActiveAuthSessions(now.Add(1 * time.Second))
	if err != nil {
		t.Fatalf("CountActiveAuthSessions returned error: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("expected 1 active auth session, got %d", activeCount)
	}

	if err := store.RevokeAuthSession(token, now.Add(2*time.Second)); err != nil {
		t.Fatalf("RevokeAuthSession returned error: %v", err)
	}
	_, found, err = store.LoadAuthSession(token, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("LoadAuthSession after revoke returned error: %v", err)
	}
	if found {
		t.Fatal("expected revoked auth session to be unavailable")
	}

	activeCount, err = store.CountActiveAuthSessions(now.Add(3 * time.Second))
	if err != nil {
		t.Fatalf("CountActiveAuthSessions after revoke returned error: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("expected 0 active auth sessions after revoke, got %d", activeCount)
	}
}

func TestStoreUserAdminAndOwnedAPIKeyHelpers(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "user_admin_owned_keys.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userA, err := store.UpsertOIDCUser("https://issuer.example.com", "sub-user-a", "user.a@example.com", "User A", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser(userA) returned error: %v", err)
	}
	userB, err := store.UpsertOIDCUser("https://issuer.example.com", "sub-user-b", "user.b@example.com", "User B", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("UpsertOIDCUser(userB) returned error: %v", err)
	}

	users, err := store.ListUsers(UserListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	userARecord, found, err := store.GetUserByID(userA)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}
	if !found {
		t.Fatal("expected userA to exist")
	}
	if userARecord.Role != RoleViewer || userARecord.Status != UserStatusActive {
		t.Fatalf("expected default role/status for userA, got role=%s status=%s", userARecord.Role, userARecord.Status)
	}

	updatedUserA, err := store.UpdateUserRoleAndStatus(userA, RoleOperator, UserStatusSuspended, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("UpdateUserRoleAndStatus returned error: %v", err)
	}
	if updatedUserA.Role != RoleOperator || updatedUserA.Status != UserStatusSuspended {
		t.Fatalf("expected updated role/status for userA, got role=%s status=%s", updatedUserA.Role, updatedUserA.Status)
	}

	ownedKeyRaw := "owned-key-for-user-a"
	ownedMeta := APIKeyMetadata{
		ID:               "key_user_owned_a",
		Name:             "owned-by-user-a",
		Role:             RoleOperator,
		Prefix:           keyPrefix(ownedKeyRaw),
		Source:           "managed",
		OwnerUserID:      userA,
		OwnerSubject:     "sub-user-a",
		OwnerEmail:       "user.a@example.com",
		CreatedAt:        now,
		CreatedBy:        "admin",
		CreatedByUserID:  userB,
		Revoked:          false,
		RevocationReason: "",
	}
	if err := store.UpsertAPIKey(ownedKeyRaw, ownedMeta); err != nil {
		t.Fatalf("UpsertAPIKey(owned) returned error: %v", err)
	}

	ownedActive, err := store.ListAPIKeysByOwnerUserID(userA, false, 10)
	if err != nil {
		t.Fatalf("ListAPIKeysByOwnerUserID(active) returned error: %v", err)
	}
	if len(ownedActive) != 1 {
		t.Fatalf("expected 1 active owned key, got %d", len(ownedActive))
	}
	if ownedActive[0].OwnerUserID != userA || ownedActive[0].CreatedByUserID != userB {
		t.Fatalf("unexpected ownership metadata on owned key: %+v", ownedActive[0])
	}

	revokedAt := now.Add(3 * time.Minute)
	if err := store.RevokeAPIKeyWithContext(ownedMeta.ID, revokedAt, userB, "rotation"); err != nil {
		t.Fatalf("RevokeAPIKeyWithContext returned error: %v", err)
	}

	ownedStillActive, err := store.ListAPIKeysByOwnerUserID(userA, false, 10)
	if err != nil {
		t.Fatalf("ListAPIKeysByOwnerUserID(active-after-revoke) returned error: %v", err)
	}
	if len(ownedStillActive) != 0 {
		t.Fatalf("expected 0 active owned keys after revoke, got %d", len(ownedStillActive))
	}

	ownedAll, err := store.ListAPIKeysByOwnerUserID(userA, true, 10)
	if err != nil {
		t.Fatalf("ListAPIKeysByOwnerUserID(include-revoked) returned error: %v", err)
	}
	if len(ownedAll) != 1 {
		t.Fatalf("expected 1 owned key (including revoked), got %d", len(ownedAll))
	}
	if !ownedAll[0].Revoked || ownedAll[0].RevokedByUserID != userB || ownedAll[0].RevocationReason != "rotation" {
		t.Fatalf("unexpected revoked metadata on owned key: %+v", ownedAll[0])
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

func assertSQLiteColumnExists(t *testing.T, db *sql.DB, tableName, columnName string) {
	t.Helper()
	if !sqliteTableHasColumn(t, db, tableName, columnName) {
		t.Fatalf("expected table %q to include column %q", tableName, columnName)
	}
}

func assertSQLiteColumnMissing(t *testing.T, db *sql.DB, tableName, columnName string) {
	t.Helper()
	if sqliteTableHasColumn(t, db, tableName, columnName) {
		t.Fatalf("expected table %q to exclude column %q", tableName, columnName)
	}
}

func sqliteTableHasColumn(t *testing.T, db *sql.DB, tableName, columnName string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + tableName + ");")
	if err != nil {
		t.Fatalf("failed to inspect table %q columns: %v", tableName, err)
	}
	defer rows.Close()
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
			t.Fatalf("failed to scan column metadata for table %q: %v", tableName, err)
		}
		if name == columnName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("failed reading table %q metadata: %v", tableName, err)
	}
	return false
}
