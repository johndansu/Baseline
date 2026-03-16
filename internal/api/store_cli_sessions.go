package api

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const (
	cliAuthRequestStatusPending  = "pending"
	cliAuthRequestStatusApproved = "approved"
	cliAuthRequestStatusConsumed = "consumed"
	cliSessionAuthSource         = "cli_session"
)

type cliAuthRequestRecord struct {
	DeviceCodeHash    string
	UserCodeHash      string
	UserCodeDisplay   string
	ClientName        string
	ClientHost        string
	Status            string
	RequestedAt       time.Time
	ExpiresAt         time.Time
	ApprovedAt        time.Time
	ApprovedUserID    string
	ApprovedRole      Role
	ApprovedUserLabel string
	ApprovedSubject   string
	ApprovedEmail     string
}

type cliSessionRecord struct {
	SessionID        string
	UserID           string
	Role             Role
	UserLabel        string
	Subject          string
	Email            string
	ClientName       string
	ClientHost       string
	LastIP           string
	CLIVersion       string
	LastRepository   string
	LastProjectID    string
	LastCommand      string
	LastScanID       string
	CreatedAt        time.Time
	ApprovedAt       time.Time
	LastUsedAt       time.Time
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Revoked          bool
	RevokedAt        time.Time
}

func migrateCLISessionsTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS cli_auth_requests (
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
	);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_cli_auth_requests_status_expires_at ON cli_auth_requests(status, expires_at);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS cli_sessions (
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
	);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_cli_sessions_access_active ON cli_sessions(access_token_hash, revoked, access_expires_at);`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_cli_sessions_refresh_active ON cli_sessions(refresh_token_hash, revoked, refresh_expires_at);`); err != nil {
		return err
	}
	return nil
}

func (s *Store) CreateCLIAuthRequest(deviceCode, userCode, clientName, clientHost string, expiresAt, now time.Time) error {
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_code_hash) DO UPDATE SET
			user_code_hash = excluded.user_code_hash,
			user_code_display = excluded.user_code_display,
			client_name = excluded.client_name,
			client_host = excluded.client_host,
			status = excluded.status,
			requested_at = excluded.requested_at,
			expires_at = excluded.expires_at,
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

func (s *Store) GetCLIAuthRequest(deviceCode, userCode string, now time.Time) (cliAuthRequestRecord, bool, error) {
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
			FROM cli_auth_requests WHERE device_code_hash = ?`
		arg = hashAPIKey(trimmed, s.apiKeyHashSecret)
	} else if trimmed := strings.TrimSpace(userCode); trimmed != "" {
		query = `SELECT device_code_hash, user_code_hash, user_code_display, client_name, client_host, status,
			requested_at, expires_at, approved_at, approved_user_id, approved_role, approved_user_label,
			approved_subject, approved_email
			FROM cli_auth_requests WHERE user_code_hash = ?`
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
		_, _ = s.db.Exec(`DELETE FROM cli_auth_requests WHERE device_code_hash = ?`, record.DeviceCodeHash)
		return cliAuthRequestRecord{}, false, nil
	}
	return record, true, nil
}

func (s *Store) ApproveCLIAuthRequest(deviceCode, userCode string, session cliSessionRecord, now time.Time) (cliAuthRequestRecord, error) {
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
		 SET status = ?, approved_at = ?, approved_user_id = ?, approved_role = ?, approved_user_label = ?,
		     approved_subject = ?, approved_email = ?
		 WHERE device_code_hash = ?`,
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

func (s *Store) ConsumeCLIAuthRequest(deviceCode string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	deviceHash := hashAPIKey(deviceCode, s.apiKeyHashSecret)
	if deviceHash == "" {
		return errors.New("device code is required")
	}
	_, err := s.db.Exec(`DELETE FROM cli_auth_requests WHERE device_code_hash = ?`, deviceHash)
	return err
}

func (s *Store) CreateCLISession(accessToken, refreshToken string, session cliSessionRecord, now time.Time) error {
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			access_token_hash = excluded.access_token_hash,
			refresh_token_hash = excluded.refresh_token_hash,
			user_id = excluded.user_id,
			role = excluded.role,
			user_label = excluded.user_label,
			subject = excluded.subject,
			email = excluded.email,
			client_name = excluded.client_name,
			client_host = excluded.client_host,
			last_ip = excluded.last_ip,
			cli_version = excluded.cli_version,
			last_repository = excluded.last_repository,
			last_project_id = excluded.last_project_id,
			last_command = excluded.last_command,
			last_scan_id = excluded.last_scan_id,
			approved_at = excluded.approved_at,
			last_used_at = excluded.last_used_at,
			access_expires_at = excluded.access_expires_at,
			refresh_expires_at = excluded.refresh_expires_at,
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

func (s *Store) LoadCLISessionByAccessToken(accessToken string, now time.Time) (cliSessionRecord, bool, error) {
	return s.loadCLISessionByToken(accessToken, true, now)
}

func (s *Store) LoadCLISessionByRefreshToken(refreshToken string, now time.Time) (cliSessionRecord, bool, error) {
	return s.loadCLISessionByToken(refreshToken, false, now)
}

func (s *Store) loadCLISessionByToken(rawToken string, access bool, now time.Time) (cliSessionRecord, bool, error) {
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
		 FROM cli_sessions WHERE `+column+` = ?`,
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
				`UPDATE cli_sessions SET revoked = 1, revoked_at = ?, last_used_at = ? WHERE session_id = ?`,
				now.UTC().Format(time.RFC3339Nano),
				now.UTC().Format(time.RFC3339Nano),
				record.SessionID,
			)
		}
		return cliSessionRecord{}, false, nil
	}
	if _, err := s.db.Exec(
		`UPDATE cli_sessions SET last_used_at = ? WHERE session_id = ?`,
		now.UTC().Format(time.RFC3339Nano),
		record.SessionID,
	); err != nil {
		return cliSessionRecord{}, false, err
	}
	record.LastUsedAt = now.UTC()
	return record, true, nil
}

func (s *Store) RotateCLISession(session cliSessionRecord, newAccessToken, newRefreshToken string, now time.Time) error {
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
		 SET access_token_hash = ?, refresh_token_hash = ?, user_id = ?, role = ?, user_label = ?,
		     subject = ?, email = ?, client_name = ?, client_host = ?, last_ip = ?, cli_version = ?, last_repository = ?, last_project_id = ?, last_command = ?, last_scan_id = ?, last_used_at = ?,
		     access_expires_at = ?, refresh_expires_at = ?, revoked = 0, revoked_at = ''
		 WHERE session_id = ?`,
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

func (s *Store) RevokeCLISessionByAccessToken(accessToken string, revokedAt time.Time) error {
	return s.revokeCLISessionByToken(accessToken, true, revokedAt)
}

func (s *Store) RevokeCLISessionByRefreshToken(refreshToken string, revokedAt time.Time) error {
	return s.revokeCLISessionByToken(refreshToken, false, revokedAt)
}

func (s *Store) ListCLISessions(limit int, now time.Time) ([]cliSessionRecord, error) {
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
		 WHERE revoked = 0 AND refresh_expires_at > ?
		 ORDER BY last_used_at DESC, created_at DESC
		 LIMIT ?`,
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

func (s *Store) UpdateCLISessionMetadata(sessionID, lastIP, cliVersion, repository, projectID, command, scanID string, now time.Time) error {
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
		 SET last_used_at = ?,
		     last_ip = COALESCE(NULLIF(?, ''), last_ip),
		     cli_version = COALESCE(NULLIF(?, ''), cli_version),
		     last_repository = COALESCE(NULLIF(?, ''), last_repository),
		     last_project_id = COALESCE(NULLIF(?, ''), last_project_id),
		     last_command = COALESCE(NULLIF(?, ''), last_command),
		     last_scan_id = COALESCE(NULLIF(?, ''), last_scan_id)
		 WHERE session_id = ?`,
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

func (s *Store) RevokeCLISessionByID(sessionID string, revokedAt time.Time) (bool, error) {
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
		 SET revoked = 1, revoked_at = ?, last_used_at = ?
		 WHERE session_id = ? AND revoked = 0`,
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

func (s *Store) RevokeCLISessionsByOwnerKey(ownerKey string, revokedAt time.Time) (int64, error) {
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
		arg   string
	)
	switch {
	case strings.HasPrefix(ownerKey, "user:"):
		arg = strings.TrimSpace(strings.TrimPrefix(ownerKey, "user:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = ?, last_used_at = ?
		 WHERE revoked = 0 AND (
		     lower(trim(user_id)) = ?
		     OR (trim(user_id) = '' AND trim(subject) = '' AND trim(email) = '' AND lower(trim(user_label)) = ?)
		 )`
	case strings.HasPrefix(ownerKey, "sub:"):
		arg = strings.TrimSpace(strings.TrimPrefix(ownerKey, "sub:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = ?, last_used_at = ?
		 WHERE revoked = 0 AND lower(trim(subject)) = ?`
	case strings.HasPrefix(ownerKey, "email:"):
		arg = strings.TrimSpace(strings.TrimPrefix(ownerKey, "email:"))
		if arg == "" {
			return 0, errors.New("cli session owner key is required")
		}
		query = `UPDATE cli_sessions
		 SET revoked = 1, revoked_at = ?, last_used_at = ?
		 WHERE revoked = 0 AND lower(trim(email)) = ?`
	default:
		return 0, errors.New("unsupported cli session owner key")
	}
	args := []any{
		revokedAt.UTC().Format(time.RFC3339Nano),
		revokedAt.UTC().Format(time.RFC3339Nano),
		arg,
	}
	if strings.HasPrefix(ownerKey, "user:") {
		args = append(args, arg)
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

func (s *Store) revokeCLISessionByToken(rawToken string, access bool, revokedAt time.Time) error {
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
		 SET revoked = 1, revoked_at = ?, last_used_at = ?
		 WHERE `+column+` = ?`,
		revokedAt.UTC().Format(time.RFC3339Nano),
		revokedAt.UTC().Format(time.RFC3339Nano),
		tokenHash,
	)
	return err
}

type cliAuthRequestScanner interface {
	Scan(dest ...any) error
}

func scanCLIAuthRequest(scanner cliAuthRequestScanner) (cliAuthRequestRecord, error) {
	var record cliAuthRequestRecord
	var requestedRaw, expiresRaw string
	var approvedRaw, approvedUserID, approvedRole, approvedUserLabel, approvedSubject, approvedEmail sql.NullString
	if err := scanner.Scan(
		&record.DeviceCodeHash,
		&record.UserCodeHash,
		&record.UserCodeDisplay,
		&record.ClientName,
		&record.ClientHost,
		&record.Status,
		&requestedRaw,
		&expiresRaw,
		&approvedRaw,
		&approvedUserID,
		&approvedRole,
		&approvedUserLabel,
		&approvedSubject,
		&approvedEmail,
	); err != nil {
		return cliAuthRequestRecord{}, err
	}
	requestedAt, err := parseStoredTime(requestedRaw)
	if err != nil {
		return cliAuthRequestRecord{}, err
	}
	expiresAt, err := parseStoredTime(expiresRaw)
	if err != nil {
		return cliAuthRequestRecord{}, err
	}
	record.RequestedAt = requestedAt
	record.ExpiresAt = expiresAt
	if strings.TrimSpace(approvedRaw.String) != "" {
		record.ApprovedAt, err = parseStoredTime(approvedRaw.String)
		if err != nil {
			return cliAuthRequestRecord{}, err
		}
	}
	record.ApprovedUserID = strings.TrimSpace(approvedUserID.String)
	record.ApprovedRole = Role(strings.ToLower(strings.TrimSpace(approvedRole.String)))
	record.ApprovedUserLabel = strings.TrimSpace(approvedUserLabel.String)
	record.ApprovedSubject = strings.TrimSpace(approvedSubject.String)
	record.ApprovedEmail = strings.ToLower(strings.TrimSpace(approvedEmail.String))
	if !isValidRole(record.ApprovedRole) {
		record.ApprovedRole = RoleViewer
	}
	return record, nil
}

type cliSessionScanner interface {
	Scan(dest ...any) error
}

func scanCLISession(scanner cliSessionScanner) (cliSessionRecord, error) {
	var record cliSessionRecord
	var roleRaw, createdRaw, approvedRaw, lastUsedRaw, accessExpiryRaw, refreshExpiryRaw string
	var userID, subject, email, clientName, clientHost, lastIP, cliVersion, lastRepository, lastProjectID, lastCommand, lastScanID, revokedRaw sql.NullString
	var revoked int
	if err := scanner.Scan(
		&record.SessionID,
		&userID,
		&roleRaw,
		&record.UserLabel,
		&subject,
		&email,
		&clientName,
		&clientHost,
		&lastIP,
		&cliVersion,
		&lastRepository,
		&lastProjectID,
		&lastCommand,
		&lastScanID,
		&createdRaw,
		&approvedRaw,
		&lastUsedRaw,
		&accessExpiryRaw,
		&refreshExpiryRaw,
		&revoked,
		&revokedRaw,
	); err != nil {
		return cliSessionRecord{}, err
	}
	var err error
	record.CreatedAt, err = parseStoredTime(createdRaw)
	if err != nil {
		return cliSessionRecord{}, err
	}
	record.ApprovedAt, err = parseStoredTime(approvedRaw)
	if err != nil {
		return cliSessionRecord{}, err
	}
	record.LastUsedAt, err = parseStoredTime(lastUsedRaw)
	if err != nil {
		return cliSessionRecord{}, err
	}
	record.AccessExpiresAt, err = parseStoredTime(accessExpiryRaw)
	if err != nil {
		return cliSessionRecord{}, err
	}
	record.RefreshExpiresAt, err = parseStoredTime(refreshExpiryRaw)
	if err != nil {
		return cliSessionRecord{}, err
	}
	record.UserID = strings.TrimSpace(userID.String)
	record.Role = Role(strings.ToLower(strings.TrimSpace(roleRaw)))
	record.Subject = strings.TrimSpace(subject.String)
	record.Email = strings.ToLower(strings.TrimSpace(email.String))
	record.ClientName = strings.TrimSpace(clientName.String)
	record.ClientHost = strings.TrimSpace(clientHost.String)
	record.LastIP = strings.TrimSpace(lastIP.String)
	record.CLIVersion = strings.TrimSpace(cliVersion.String)
	record.LastRepository = strings.TrimSpace(lastRepository.String)
	record.LastProjectID = strings.TrimSpace(lastProjectID.String)
	record.LastCommand = strings.TrimSpace(lastCommand.String)
	record.LastScanID = strings.TrimSpace(lastScanID.String)
	record.Revoked = revoked != 0
	if strings.TrimSpace(revokedRaw.String) != "" {
		record.RevokedAt, err = parseStoredTime(revokedRaw.String)
		if err != nil {
			return cliSessionRecord{}, err
		}
	}
	if !isValidRole(record.Role) {
		record.Role = RoleViewer
	}
	return record, nil
}

func migrateCLISessionMetadataTx(tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE cli_sessions ADD COLUMN last_ip TEXT`,
		`ALTER TABLE cli_sessions ADD COLUMN cli_version TEXT`,
		`ALTER TABLE cli_sessions ADD COLUMN last_repository TEXT`,
		`ALTER TABLE cli_sessions ADD COLUMN last_project_id TEXT`,
	} {
		if _, err := tx.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
}

func migrateCLISessionCommandMetadataTx(tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE cli_sessions ADD COLUMN last_command TEXT`,
		`ALTER TABLE cli_sessions ADD COLUMN last_scan_id TEXT`,
	} {
		if _, err := tx.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
}
