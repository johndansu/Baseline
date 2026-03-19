package api

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresStoreUserAndAuthSessionFlow(t *testing.T) {
	store := newPostgresStoreForTest(t)

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser("supabase", "subject-1", "user@example.com", "Baseline User", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}
	if strings.TrimSpace(userID) == "" {
		t.Fatal("expected user id to be returned")
	}

	user, found, err := store.GetUserByEmail("user@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail returned error: %v", err)
	}
	if !found {
		t.Fatal("expected user to be found by email")
	}
	if user.ID != userID {
		t.Fatalf("expected user id %q, got %q", userID, user.ID)
	}

	updatedUser, err := store.UpdateUserRoleAndStatus(userID, RoleAdmin, UserStatusActive, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("UpdateUserRoleAndStatus returned error: %v", err)
	}
	if updatedUser.Role != RoleAdmin {
		t.Fatalf("expected role admin, got %q", updatedUser.Role)
	}

	sessionToken := "dashboard-token"
	expiresAt := now.Add(2 * time.Hour)
	if err := store.UpsertAuthSession(sessionToken, dashboardSession{
		UserID:     userID,
		Role:       RoleAdmin,
		User:       "Baseline User",
		Subject:    "subject-1",
		Email:      "user@example.com",
		AuthSource: "session",
		ExpiresAt:  expiresAt,
	}, now); err != nil {
		t.Fatalf("UpsertAuthSession returned error: %v", err)
	}

	session, found, err := store.LoadAuthSession(sessionToken, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("LoadAuthSession returned error: %v", err)
	}
	if !found {
		t.Fatal("expected auth session to be found")
	}
	if session.UserID != userID {
		t.Fatalf("expected session user id %q, got %q", userID, session.UserID)
	}

	count, err := store.CountActiveAuthSessions(now.Add(5 * time.Minute))
	if err != nil {
		t.Fatalf("CountActiveAuthSessions returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 active auth session, got %d", count)
	}

	if err := store.RevokeAuthSession(sessionToken, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("RevokeAuthSession returned error: %v", err)
	}
	_, found, err = store.LoadAuthSession(sessionToken, now.Add(11*time.Minute))
	if err != nil {
		t.Fatalf("LoadAuthSession after revoke returned error: %v", err)
	}
	if found {
		t.Fatal("expected revoked auth session to be unavailable")
	}
}

func TestPostgresStoreProjectAndScanFlow(t *testing.T) {
	store := newPostgresStoreForTest(t)

	now := time.Now().UTC()
	project := Project{
		ID:            "proj_pg",
		Name:          "Postgres Project",
		RepositoryURL: "https://github.com/acme/postgres-project",
		DefaultBranch: "main",
		PolicySet:     "baseline:prod",
		OwnerID:       "user:owner-1",
	}
	if err := store.UpsertProject(project, now); err != nil {
		t.Fatalf("UpsertProject returned error: %v", err)
	}

	projects, err := store.LoadProjects()
	if err != nil {
		t.Fatalf("LoadProjects returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if projects[0].ID != project.ID {
		t.Fatalf("expected project id %q, got %q", project.ID, projects[0].ID)
	}

	updatedProject, err := store.UpdateProjectOwner(project.ID, "user:owner-2")
	if err != nil {
		t.Fatalf("UpdateProjectOwner returned error: %v", err)
	}
	if updatedProject.OwnerID != "user:owner-2" {
		t.Fatalf("expected updated owner id, got %q", updatedProject.OwnerID)
	}

	scan := ScanSummary{
		ID:           "scan_pg",
		ProjectID:    project.ID,
		CommitSHA:    "abc123",
		FilesScanned: 42,
		Status:       "warn",
		Violations: []ScanViolation{
			{PolicyID: "G1", Severity: "high", Message: "missing tests"},
		},
		CreatedAt: now,
		OwnerID:   "user:owner-2",
	}
	if err := store.UpsertScan(scan); err != nil {
		t.Fatalf("UpsertScan returned error: %v", err)
	}

	scans, err := store.LoadScans(10)
	if err != nil {
		t.Fatalf("LoadScans returned error: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}
	if scans[0].ID != scan.ID {
		t.Fatalf("expected scan id %q, got %q", scan.ID, scans[0].ID)
	}
	if len(scans[0].Violations) != 1 || scans[0].Violations[0].PolicyID != "G1" {
		t.Fatalf("expected persisted violation payload, got %#v", scans[0].Violations)
	}
}

func TestPostgresStoreCLISessionAndTraceFlow(t *testing.T) {
	store := newPostgresStoreForTest(t)

	now := time.Now().UTC()
	if err := store.CreateCLIAuthRequest("device-1", "ABCD-EFGH", "Baseline CLI", "workstation", now.Add(10*time.Minute), now); err != nil {
		t.Fatalf("CreateCLIAuthRequest returned error: %v", err)
	}

	request, found, err := store.GetCLIAuthRequest("", "ABCD-EFGH", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("GetCLIAuthRequest returned error: %v", err)
	}
	if !found {
		t.Fatal("expected CLI auth request to be found")
	}
	if request.Status != cliAuthRequestStatusPending {
		t.Fatalf("expected pending auth request, got %q", request.Status)
	}

	sessionRecord := cliSessionRecord{
		SessionID:        "cli_sess_1",
		UserID:           "usr_1",
		Role:             RoleAdmin,
		UserLabel:        "Baseline Admin",
		Subject:          "subject-1",
		Email:            "admin@example.com",
		ClientName:       "Baseline CLI",
		ClientHost:       "workstation",
		CreatedAt:        now,
		ApprovedAt:       now,
		LastUsedAt:       now,
		AccessExpiresAt:  now.Add(30 * time.Minute),
		RefreshExpiresAt: now.Add(24 * time.Hour),
	}

	request, err = store.ApproveCLIAuthRequest("device-1", "", sessionRecord, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ApproveCLIAuthRequest returned error: %v", err)
	}
	if request.Status != cliAuthRequestStatusApproved {
		t.Fatalf("expected approved auth request, got %q", request.Status)
	}

	if err := store.CreateCLISession("access-token-1", "refresh-token-1", sessionRecord, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("CreateCLISession returned error: %v", err)
	}

	session, found, err := store.LoadCLISessionByAccessToken("access-token-1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("LoadCLISessionByAccessToken returned error: %v", err)
	}
	if !found {
		t.Fatal("expected CLI session by access token to be found")
	}
	if session.SessionID != sessionRecord.SessionID {
		t.Fatalf("expected session id %q, got %q", sessionRecord.SessionID, session.SessionID)
	}

	if err := store.UpdateCLISessionMetadata(session.SessionID, "127.0.0.1", "dev", "Baseline", "proj_pg", "scan", "scan_pg", now.Add(4*time.Minute)); err != nil {
		t.Fatalf("UpdateCLISessionMetadata returned error: %v", err)
	}

	sessions, err := store.ListCLISessions(10, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("ListCLISessions returned error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active CLI session, got %d", len(sessions))
	}
	if sessions[0].LastCommand != "scan" {
		t.Fatalf("expected last command scan, got %q", sessions[0].LastCommand)
	}

	trace := CLITraceDetail{
		Summary: CLITraceSummary{
			TraceID:        "trace-1",
			SessionID:      session.SessionID,
			Command:        "scan",
			Repository:     "Baseline",
			ProjectID:      "proj_pg",
			ScanID:         "scan_pg",
			Status:         "ok",
			Message:        "completed",
			Version:        "dev",
			StartedAt:      now,
			FinishedAt:     now.Add(2 * time.Second),
			DurationMS:     2000,
			EventCount:     1,
			FilesScanned:   42,
			SecurityIssues: 0,
			ViolationCount: 1,
			Attributes: map[string]string{
				"repository": "Baseline",
			},
		},
		Events: []CLITraceEvent{
			{
				SpanID:    "span-1",
				Type:      "cli_command_completed",
				Component: "cli",
				Status:    "ok",
				Message:   "completed",
				Attributes: map[string]string{
					"command": "scan",
				},
				CreatedAt: now.Add(time.Second),
			},
		},
	}
	if err := store.CreateCLITrace(trace); err != nil {
		t.Fatalf("CreateCLITrace returned error: %v", err)
	}

	traces, err := store.ListCLITraces(10, "scan", "ok", "proj_pg")
	if err != nil {
		t.Fatalf("ListCLITraces returned error: %v", err)
	}
	if len(traces) != 1 {
		t.Fatalf("expected 1 CLI trace, got %d", len(traces))
	}

	detail, err := store.GetCLITrace("trace-1")
	if err != nil {
		t.Fatalf("GetCLITrace returned error: %v", err)
	}
	if len(detail.Events) != 1 {
		t.Fatalf("expected 1 CLI trace event, got %d", len(detail.Events))
	}

	sessionTraces, err := store.ListCLITracesBySessionID(session.SessionID, 10)
	if err != nil {
		t.Fatalf("ListCLITracesBySessionID returned error: %v", err)
	}
	if len(sessionTraces) != 1 {
		t.Fatalf("expected 1 CLI trace for session, got %d", len(sessionTraces))
	}

	revoked, err := store.RevokeCLISessionByID(session.SessionID, now.Add(6*time.Minute))
	if err != nil {
		t.Fatalf("RevokeCLISessionByID returned error: %v", err)
	}
	if !revoked {
		t.Fatal("expected CLI session to be revoked")
	}
}

func TestPostgresStoreIntegrationJobFlow(t *testing.T) {
	store := newPostgresStoreForTest(t)

	now := time.Now().UTC()
	job, err := store.EnqueueIntegrationJob(IntegrationJob{
		Provider:    "github",
		JobType:     "pr_sync",
		ProjectRef:  "proj_pg",
		ExternalRef: "123",
		Status:      IntegrationJobPending,
	})
	if err != nil {
		t.Fatalf("EnqueueIntegrationJob returned error: %v", err)
	}
	if strings.TrimSpace(job.ID) == "" {
		t.Fatal("expected integration job id to be assigned")
	}

	claimed, err := store.ClaimDueIntegrationJob(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimDueIntegrationJob returned error: %v", err)
	}
	if claimed == nil {
		t.Fatal("expected due integration job to be claimed")
	}
	if claimed.Status != IntegrationJobRunning {
		t.Fatalf("expected claimed job status running, got %q", claimed.Status)
	}

	retryEvent := AuditEvent{
		EventType: "cli_error",
		ProjectID: "proj_pg",
		Actor:     "system",
		Details:   "retrying sync",
		CreatedAt: now.Add(2 * time.Minute),
	}
	if err := store.MarkIntegrationJobRetryWithAuditEvent(job.ID, "temporary failure", now.Add(10*time.Minute), now.Add(2*time.Minute), retryEvent); err != nil {
		t.Fatalf("MarkIntegrationJobRetryWithAuditEvent returned error: %v", err)
	}

	successEvent := AuditEvent{
		EventType: "cli_health",
		ProjectID: "proj_pg",
		Actor:     "system",
		Details:   "sync complete",
		CreatedAt: now.Add(3 * time.Minute),
	}
	if err := store.MarkIntegrationJobSucceededWithAuditEvent(job.ID, now.Add(3*time.Minute), successEvent); err != nil {
		t.Fatalf("MarkIntegrationJobSucceededWithAuditEvent returned error: %v", err)
	}

	jobs, err := store.ListIntegrationJobs(10)
	if err != nil {
		t.Fatalf("ListIntegrationJobs returned error: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 integration job, got %d", len(jobs))
	}
	if jobs[0].Status != IntegrationJobSucceeded {
		t.Fatalf("expected job status succeeded, got %q", jobs[0].Status)
	}

	events, err := store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents returned error: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected audit events from integration job flow, got %d", len(events))
	}

	if err := store.DeleteAuditEventsByPrefixBefore("cli_", now.Add(4*time.Minute)); err != nil {
		t.Fatalf("DeleteAuditEventsByPrefixBefore returned error: %v", err)
	}
	events, err = store.LoadAuditEvents(10)
	if err != nil {
		t.Fatalf("LoadAuditEvents after delete returned error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected prefixed audit events to be deleted, got %d", len(events))
	}
}

func newPostgresStoreForTest(t *testing.T) *PostgresStore {
	t.Helper()

	databaseURL := strings.TrimSpace(os.Getenv("BASELINE_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("skipping postgres store test; BASELINE_TEST_POSTGRES_URL is not set")
	}

	store, err := NewPostgresStore(databaseURL)
	if err != nil {
		t.Fatalf("NewPostgresStore returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	store.SetAPIKeyHashSecret("postgres-test-secret")
	resetPostgresStoreForTest(t, store)
	return store
}

func resetPostgresStoreForTest(t *testing.T, store *PostgresStore) {
	t.Helper()

	statements := []string{
		`DELETE FROM cli_trace_events`,
		`DELETE FROM cli_traces`,
		`DELETE FROM cli_sessions`,
		`DELETE FROM cli_auth_requests`,
		`DELETE FROM auth_sessions`,
		`DELETE FROM user_identities`,
		`DELETE FROM users`,
		`DELETE FROM scans`,
		`DELETE FROM projects`,
		`DELETE FROM api_keys`,
		`DELETE FROM integration_jobs`,
		`DELETE FROM audit_events`,
	}
	for _, stmt := range statements {
		if _, err := store.db.Exec(stmt); err != nil {
			t.Fatalf("reset statement failed (%s): %v", stmt, err)
		}
	}
}
