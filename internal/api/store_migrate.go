package api

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type TableMigrationResult struct {
	Table        string
	SourceRows   int
	MigratedRows int
	TargetRows   int
}

type SQLiteToPostgresMigrationReport struct {
	Results []TableMigrationResult
}

func (r SQLiteToPostgresMigrationReport) TotalSourceRows() int {
	total := 0
	for _, result := range r.Results {
		total += result.SourceRows
	}
	return total
}

func (r SQLiteToPostgresMigrationReport) TotalMigratedRows() int {
	total := 0
	for _, result := range r.Results {
		total += result.MigratedRows
	}
	return total
}

func (r SQLiteToPostgresMigrationReport) TotalTargetRows() int {
	total := 0
	for _, result := range r.Results {
		total += result.TargetRows
	}
	return total
}

type migrationTableSpec struct {
	Name            string
	ColumnCount     int
	SourceCountSQL  string
	SourceSelectSQL string
	TargetCountSQL  string
	TargetUpsertSQL string
}

var sqliteToPostgresMigrationTables = []migrationTableSpec{
	{
		Name:           "api_keys",
		ColumnCount:    16,
		SourceCountSQL: `SELECT COUNT(1) FROM api_keys`,
		SourceSelectSQL: `SELECT id, key_hash, name, role, prefix, source,
			owner_user_id, owner_subject, owner_email,
			created_at, created_by, created_by_user_id,
			revoked, revoked_at, revoked_by_user_id, revocation_reason
		FROM api_keys`,
		TargetCountSQL: `SELECT COUNT(1) FROM api_keys`,
		TargetUpsertSQL: `INSERT INTO api_keys (
			id, key_hash, name, role, prefix, source,
			owner_user_id, owner_subject, owner_email,
			created_at, created_by, created_by_user_id,
			revoked, revoked_at, revoked_by_user_id, revocation_reason
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16
		) ON CONFLICT (key_hash) DO UPDATE SET
			id = EXCLUDED.id,
			name = EXCLUDED.name,
			role = EXCLUDED.role,
			prefix = EXCLUDED.prefix,
			source = EXCLUDED.source,
			owner_user_id = EXCLUDED.owner_user_id,
			owner_subject = EXCLUDED.owner_subject,
			owner_email = EXCLUDED.owner_email,
			created_at = EXCLUDED.created_at,
			created_by = EXCLUDED.created_by,
			created_by_user_id = EXCLUDED.created_by_user_id,
			revoked = EXCLUDED.revoked,
			revoked_at = EXCLUDED.revoked_at,
			revoked_by_user_id = EXCLUDED.revoked_by_user_id,
			revocation_reason = EXCLUDED.revocation_reason`,
	},
	{
		Name:           "audit_events",
		ColumnCount:    8,
		SourceCountSQL: `SELECT COUNT(1) FROM audit_events`,
		SourceSelectSQL: `SELECT id, event_type, project_id, scan_id, actor, request_id, details, created_at
		FROM audit_events
		ORDER BY id ASC`,
		TargetCountSQL: `SELECT COUNT(1) FROM audit_events`,
		TargetUpsertSQL: `INSERT INTO audit_events (
			id, event_type, project_id, scan_id, actor, request_id, details, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) ON CONFLICT (id) DO UPDATE SET
			event_type = EXCLUDED.event_type,
			project_id = EXCLUDED.project_id,
			scan_id = EXCLUDED.scan_id,
			actor = EXCLUDED.actor,
			request_id = EXCLUDED.request_id,
			details = EXCLUDED.details,
			created_at = EXCLUDED.created_at`,
	},
	{
		Name:           "integration_jobs",
		ColumnCount:    13,
		SourceCountSQL: `SELECT COUNT(1) FROM integration_jobs`,
		SourceSelectSQL: `SELECT id, provider, job_type, project_ref, external_ref, payload, status,
			attempt_count, max_attempts, last_error, next_attempt_at, created_at, updated_at
		FROM integration_jobs`,
		TargetCountSQL: `SELECT COUNT(1) FROM integration_jobs`,
		TargetUpsertSQL: `INSERT INTO integration_jobs (
			id, provider, job_type, project_ref, external_ref, payload, status,
			attempt_count, max_attempts, last_error, next_attempt_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13
		) ON CONFLICT (id) DO UPDATE SET
			provider = EXCLUDED.provider,
			job_type = EXCLUDED.job_type,
			project_ref = EXCLUDED.project_ref,
			external_ref = EXCLUDED.external_ref,
			payload = EXCLUDED.payload,
			status = EXCLUDED.status,
			attempt_count = EXCLUDED.attempt_count,
			max_attempts = EXCLUDED.max_attempts,
			last_error = EXCLUDED.last_error,
			next_attempt_at = EXCLUDED.next_attempt_at,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
	},
	{
		Name:           "projects",
		ColumnCount:    7,
		SourceCountSQL: `SELECT COUNT(1) FROM projects`,
		SourceSelectSQL: `SELECT id, name, repository_url, default_branch, policy_set, owner_id, created_at
		FROM projects`,
		TargetCountSQL: `SELECT COUNT(1) FROM projects`,
		TargetUpsertSQL: `INSERT INTO projects (
			id, name, repository_url, default_branch, policy_set, owner_id, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		) ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			repository_url = EXCLUDED.repository_url,
			default_branch = EXCLUDED.default_branch,
			policy_set = EXCLUDED.policy_set,
			owner_id = EXCLUDED.owner_id,
			created_at = EXCLUDED.created_at`,
	},
	{
		Name:           "scans",
		ColumnCount:    8,
		SourceCountSQL: `SELECT COUNT(1) FROM scans`,
		SourceSelectSQL: `SELECT id, project_id, commit_sha, status, violations_json, files_scanned, owner_id, created_at
		FROM scans`,
		TargetCountSQL: `SELECT COUNT(1) FROM scans`,
		TargetUpsertSQL: `INSERT INTO scans (
			id, project_id, commit_sha, status, violations_json, files_scanned, owner_id, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) ON CONFLICT (id) DO UPDATE SET
			project_id = EXCLUDED.project_id,
			commit_sha = EXCLUDED.commit_sha,
			status = EXCLUDED.status,
			violations_json = EXCLUDED.violations_json,
			files_scanned = EXCLUDED.files_scanned,
			owner_id = EXCLUDED.owner_id,
			created_at = EXCLUDED.created_at`,
	},
	{
		Name:           "users",
		ColumnCount:    8,
		SourceCountSQL: `SELECT COUNT(1) FROM users`,
		SourceSelectSQL: `SELECT id, display_name, email, role, status, created_at, updated_at, last_login_at
		FROM users`,
		TargetCountSQL: `SELECT COUNT(1) FROM users`,
		TargetUpsertSQL: `INSERT INTO users (
			id, display_name, email, role, status, created_at, updated_at, last_login_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) ON CONFLICT (id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			email = EXCLUDED.email,
			role = EXCLUDED.role,
			status = EXCLUDED.status,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at,
			last_login_at = EXCLUDED.last_login_at`,
	},
	{
		Name:           "user_identities",
		ColumnCount:    6,
		SourceCountSQL: `SELECT COUNT(1) FROM user_identities`,
		SourceSelectSQL: `SELECT provider, subject, user_id, email, created_at, updated_at
		FROM user_identities`,
		TargetCountSQL: `SELECT COUNT(1) FROM user_identities`,
		TargetUpsertSQL: `INSERT INTO user_identities (
			provider, subject, user_id, email, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6
		) ON CONFLICT (provider, subject) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			email = EXCLUDED.email,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
	},
	{
		Name:           "auth_sessions",
		ColumnCount:    12,
		SourceCountSQL: `SELECT COUNT(1) FROM auth_sessions`,
		SourceSelectSQL: `SELECT token_hash, user_id, role, user_label, subject, email, auth_source,
			expires_at, created_at, last_seen_at, revoked, revoked_at
		FROM auth_sessions`,
		TargetCountSQL: `SELECT COUNT(1) FROM auth_sessions`,
		TargetUpsertSQL: `INSERT INTO auth_sessions (
			token_hash, user_id, role, user_label, subject, email, auth_source,
			expires_at, created_at, last_seen_at, revoked, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12
		) ON CONFLICT (token_hash) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			role = EXCLUDED.role,
			user_label = EXCLUDED.user_label,
			subject = EXCLUDED.subject,
			email = EXCLUDED.email,
			auth_source = EXCLUDED.auth_source,
			expires_at = EXCLUDED.expires_at,
			created_at = EXCLUDED.created_at,
			last_seen_at = EXCLUDED.last_seen_at,
			revoked = EXCLUDED.revoked,
			revoked_at = EXCLUDED.revoked_at`,
	},
	{
		Name:           "cli_traces",
		ColumnCount:    17,
		SourceCountSQL: `SELECT COUNT(1) FROM cli_traces`,
		SourceSelectSQL: `SELECT trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
			started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		FROM cli_traces
		ORDER BY started_at ASC, trace_id ASC`,
		TargetCountSQL: `SELECT COUNT(1) FROM cli_traces`,
		TargetUpsertSQL: `INSERT INTO cli_traces (
			trace_id, session_id, command, repository, project_id, scan_id, status, message, version,
			started_at, finished_at, duration_ms, event_count, files_scanned, security_issues, violation_count, attributes_json
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15, $16, $17
		) ON CONFLICT (trace_id) DO UPDATE SET
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
	},
	{
		Name:           "cli_trace_events",
		ColumnCount:    12,
		SourceCountSQL: `SELECT COUNT(1) FROM cli_trace_events`,
		SourceSelectSQL: `SELECT id, trace_id, span_id, parent_span_id, event_type, component, function_name, branch, status, message, attributes_json, created_at
		FROM cli_trace_events
		ORDER BY id ASC`,
		TargetCountSQL: `SELECT COUNT(1) FROM cli_trace_events`,
		TargetUpsertSQL: `INSERT INTO cli_trace_events (
			id, trace_id, span_id, parent_span_id, event_type, component, function_name, branch, status, message, attributes_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) ON CONFLICT (id) DO UPDATE SET
			trace_id = EXCLUDED.trace_id,
			span_id = EXCLUDED.span_id,
			parent_span_id = EXCLUDED.parent_span_id,
			event_type = EXCLUDED.event_type,
			component = EXCLUDED.component,
			function_name = EXCLUDED.function_name,
			branch = EXCLUDED.branch,
			status = EXCLUDED.status,
			message = EXCLUDED.message,
			attributes_json = EXCLUDED.attributes_json,
			created_at = EXCLUDED.created_at`,
	},
	{
		Name:           "cli_auth_requests",
		ColumnCount:    14,
		SourceCountSQL: `SELECT COUNT(1) FROM cli_auth_requests`,
		SourceSelectSQL: `SELECT device_code_hash, user_code_hash, user_code_display, client_name, client_host, status,
			requested_at, expires_at, approved_at, approved_user_id, approved_role, approved_user_label,
			approved_subject, approved_email
		FROM cli_auth_requests`,
		TargetCountSQL: `SELECT COUNT(1) FROM cli_auth_requests`,
		TargetUpsertSQL: `INSERT INTO cli_auth_requests (
			device_code_hash, user_code_hash, user_code_display, client_name, client_host, status,
			requested_at, expires_at, approved_at, approved_user_id, approved_role, approved_user_label,
			approved_subject, approved_email
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14
		) ON CONFLICT (device_code_hash) DO UPDATE SET
			user_code_hash = EXCLUDED.user_code_hash,
			user_code_display = EXCLUDED.user_code_display,
			client_name = EXCLUDED.client_name,
			client_host = EXCLUDED.client_host,
			status = EXCLUDED.status,
			requested_at = EXCLUDED.requested_at,
			expires_at = EXCLUDED.expires_at,
			approved_at = EXCLUDED.approved_at,
			approved_user_id = EXCLUDED.approved_user_id,
			approved_role = EXCLUDED.approved_role,
			approved_user_label = EXCLUDED.approved_user_label,
			approved_subject = EXCLUDED.approved_subject,
			approved_email = EXCLUDED.approved_email`,
	},
	{
		Name:           "cli_sessions",
		ColumnCount:    23,
		SourceCountSQL: `SELECT COUNT(1) FROM cli_sessions`,
		SourceSelectSQL: `SELECT session_id, access_token_hash, refresh_token_hash, user_id, role, user_label, subject, email,
			client_name, client_host, last_ip, cli_version, last_repository, last_project_id, last_command, last_scan_id,
			created_at, approved_at, last_used_at, access_expires_at, refresh_expires_at, revoked, revoked_at
		FROM cli_sessions`,
		TargetCountSQL: `SELECT COUNT(1) FROM cli_sessions`,
		TargetUpsertSQL: `INSERT INTO cli_sessions (
			session_id, access_token_hash, refresh_token_hash, user_id, role, user_label, subject, email,
			client_name, client_host, last_ip, cli_version, last_repository, last_project_id, last_command, last_scan_id,
			created_at, approved_at, last_used_at, access_expires_at, refresh_expires_at, revoked, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22, $23
		) ON CONFLICT (session_id) DO UPDATE SET
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
			created_at = EXCLUDED.created_at,
			approved_at = EXCLUDED.approved_at,
			last_used_at = EXCLUDED.last_used_at,
			access_expires_at = EXCLUDED.access_expires_at,
			refresh_expires_at = EXCLUDED.refresh_expires_at,
			revoked = EXCLUDED.revoked,
			revoked_at = EXCLUDED.revoked_at`,
	},
}

func MigrateSQLiteToPostgres(sqlitePath, databaseURL string, resetTarget bool) (SQLiteToPostgresMigrationReport, error) {
	sqliteSource, err := NewSQLiteStore(strings.TrimSpace(sqlitePath))
	if err != nil {
		return SQLiteToPostgresMigrationReport{}, fmt.Errorf("open sqlite source: %w", err)
	}
	defer func() { _ = sqliteSource.Close() }()

	postgresTarget, err := NewPostgresStore(strings.TrimSpace(databaseURL))
	if err != nil {
		return SQLiteToPostgresMigrationReport{}, fmt.Errorf("open postgres target: %w", err)
	}
	defer func() { _ = postgresTarget.Close() }()

	if sqliteSource == nil || sqliteSource.db == nil {
		return SQLiteToPostgresMigrationReport{}, errors.New("sqlite source store is not initialized")
	}
	if postgresTarget == nil || postgresTarget.db == nil {
		return SQLiteToPostgresMigrationReport{}, errors.New("postgres target store is not initialized")
	}

	tx, err := postgresTarget.db.Begin()
	if err != nil {
		return SQLiteToPostgresMigrationReport{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if resetTarget {
		if err := resetPostgresMigrationTarget(tx); err != nil {
			return SQLiteToPostgresMigrationReport{}, err
		}
	}

	report := SQLiteToPostgresMigrationReport{Results: make([]TableMigrationResult, 0, len(sqliteToPostgresMigrationTables))}
	for _, table := range sqliteToPostgresMigrationTables {
		sourceRows, migratedRows, err := copySQLiteTableToPostgres(sqliteSource.db, tx, table)
		if err != nil {
			return SQLiteToPostgresMigrationReport{}, fmt.Errorf("migrate table %s: %w", table.Name, err)
		}
		targetRows, err := countRowsTx(tx, table.TargetCountSQL)
		if err != nil {
			return SQLiteToPostgresMigrationReport{}, fmt.Errorf("count target rows for %s: %w", table.Name, err)
		}
		report.Results = append(report.Results, TableMigrationResult{
			Table:        table.Name,
			SourceRows:   sourceRows,
			MigratedRows: migratedRows,
			TargetRows:   targetRows,
		})
	}

	if err := resetAuditEventsSequence(tx); err != nil {
		return SQLiteToPostgresMigrationReport{}, fmt.Errorf("reset audit_events sequence: %w", err)
	}
	if err := resetCLITraceEventsSequence(tx); err != nil {
		return SQLiteToPostgresMigrationReport{}, fmt.Errorf("reset cli_trace_events sequence: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return SQLiteToPostgresMigrationReport{}, err
	}
	return report, nil
}

func resetPostgresMigrationTarget(tx *sql.Tx) error {
	_, err := tx.Exec(`TRUNCATE TABLE
		cli_trace_events,
		cli_traces,
		cli_sessions,
		cli_auth_requests,
		auth_sessions,
		user_identities,
		users,
		scans,
		projects,
		api_keys,
		integration_jobs,
		audit_events
		RESTART IDENTITY`)
	return err
}

func copySQLiteTableToPostgres(source *sql.DB, target *sql.Tx, spec migrationTableSpec) (int, int, error) {
	sourceCount, err := countRows(source, spec.SourceCountSQL)
	if err != nil {
		return 0, 0, err
	}
	if sourceCount == 0 {
		return 0, 0, nil
	}

	rows, err := source.Query(spec.SourceSelectSQL)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	stmt, err := target.Prepare(spec.TargetUpsertSQL)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = stmt.Close() }()

	migrated := 0
	for rows.Next() {
		args, err := scanDynamicRowValues(rows, spec.ColumnCount)
		if err != nil {
			return sourceCount, migrated, err
		}
		if _, err := stmt.Exec(args...); err != nil {
			return sourceCount, migrated, err
		}
		migrated++
	}
	if err := rows.Err(); err != nil {
		return sourceCount, migrated, err
	}
	return sourceCount, migrated, nil
}

func scanDynamicRowValues(rows *sql.Rows, width int) ([]any, error) {
	dest := make([]any, width)
	scanArgs := make([]any, width)
	for i := range scanArgs {
		scanArgs[i] = &dest[i]
	}
	if err := rows.Scan(scanArgs...); err != nil {
		return nil, err
	}
	for i := range dest {
		switch value := dest[i].(type) {
		case []byte:
			dest[i] = string(value)
		default:
			dest[i] = value
		}
	}
	return dest, nil
}

func countRows(db *sql.DB, query string) (int, error) {
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func countRowsTx(tx *sql.Tx, query string) (int, error) {
	var count int
	if err := tx.QueryRow(query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func resetAuditEventsSequence(tx *sql.Tx) error {
	_, err := tx.Exec(`SELECT setval(pg_get_serial_sequence('audit_events', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM audit_events`)
	return err
}

func resetCLITraceEventsSequence(tx *sql.Tx) error {
	_, err := tx.Exec(`SELECT setval(pg_get_serial_sequence('cli_trace_events', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM cli_trace_events`)
	return err
}
