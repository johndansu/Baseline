package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUsersEndpointsRequireAdminAndSupportRoleStatusUpdate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_admin_endpoints.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser("https://issuer.example", "sub-user-1", "user1@example.com", "User One", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin users list, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin users list, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, userID) {
		t.Fatalf("expected users list to include seeded user id=%q, body=%s", userID, body)
	}

	resp, body = mustRequest(t, client, http.MethodPatch, ts.URL+"/v1/users/"+userID, map[string]any{
		"role":   "operator",
		"status": "suspended",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 patching user role/status, got %d body=%s", resp.StatusCode, body)
	}
	var updated UserRecord
	if err := json.Unmarshal([]byte(body), &updated); err != nil {
		t.Fatalf("failed to decode updated user response: %v body=%s", err, body)
	}
	if updated.Role != RoleOperator || updated.Status != UserStatusSuspended {
		t.Fatalf("unexpected updated user role/status: %+v", updated)
	}
	persisted, found, err := store.GetUserByID(userID)
	if err != nil {
		t.Fatalf("GetUserByID returned error after patch: %v", err)
	}
	if !found {
		t.Fatalf("expected patched user to remain in store")
	}
	if persisted.Role != RoleOperator || persisted.Status != UserStatusSuspended {
		t.Fatalf("expected persisted role/status to match update, got %+v", persisted)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID, nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 getting user detail, got %d body=%s", resp.StatusCode, body)
	}
}

func TestAdminCanCreateUsersAndLaterOIDCSignInReusesThem(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_create_endpoints.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/users", map[string]any{
		"email":        "created.user@example.com",
		"display_name": "Created User",
		"role":         "operator",
		"status":       "active",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating user, got %d body=%s", resp.StatusCode, body)
	}
	var created UserRecord
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode created user response: %v body=%s", err, body)
	}
	if strings.TrimSpace(created.ID) == "" {
		t.Fatalf("expected created user id, body=%s", body)
	}
	if created.Email != "created.user@example.com" || created.Role != RoleOperator || created.Status != UserStatusActive {
		t.Fatalf("unexpected created user payload: %+v", created)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/users", map[string]any{
		"email": "created.user@example.com",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate created user email, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/users", map[string]any{
		"email": "blocked@example.com",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin create user, got %d body=%s", resp.StatusCode, body)
	}

	signedInID, err := store.UpsertOIDCUser("https://issuer.example", "sub-created-user", "created.user@example.com", "Created User Signed In", time.Now().UTC())
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error for admin-created user: %v", err)
	}
	if signedInID != created.ID {
		t.Fatalf("expected sign-in to reuse created user id=%q, got %q", created.ID, signedInID)
	}

	persisted, found, err := store.GetUserByID(created.ID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}
	if !found {
		t.Fatalf("expected created user to remain in store")
	}
	if persisted.Role != RoleOperator || persisted.Status != UserStatusActive {
		t.Fatalf("expected created user's role/status to persist after sign-in, got %+v", persisted)
	}
	if persisted.Email != "created.user@example.com" {
		t.Fatalf("expected created user's email to remain normalized, got %+v", persisted)
	}
}

func TestUserScopedAPIKeysAdminAndSelfService(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_api_keys_endpoints.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser("https://issuer.example", "sub-user-2", "user2@example.com", "User Two", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}
	if _, err := store.UpdateUserRoleAndStatus(userID, RoleOperator, UserStatusActive, now); err != nil {
		t.Fatalf("UpdateUserRoleAndStatus returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/users/"+userID+"/api-keys", map[string]any{
		"name": "user2-operator-key",
		"role": "operator",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating owned api key, got %d body=%s", resp.StatusCode, body)
	}
	var createdByAdmin struct {
		ID     string `json:"id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &createdByAdmin); err != nil {
		t.Fatalf("failed to decode created key payload: %v body=%s", err, body)
	}
	if strings.TrimSpace(createdByAdmin.APIKey) == "" || strings.TrimSpace(createdByAdmin.ID) == "" {
		t.Fatalf("expected created key id and secret, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/me/api-keys", nil, map[string]string{
		"Authorization": "Bearer " + createdByAdmin.APIKey,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 listing own api keys, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, createdByAdmin.ID) {
		t.Fatalf("expected own api key list to include issued key id=%q body=%s", createdByAdmin.ID, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/me/api-keys", map[string]any{
		"name": "forbidden-escalation",
		"role": "admin",
	}, map[string]string{
		"Authorization": "Bearer " + createdByAdmin.APIKey,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for self-service role escalation, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/me/api-keys", map[string]any{
		"name": "self-viewer-key",
		"role": "viewer",
	}, map[string]string{
		"Authorization": "Bearer " + createdByAdmin.APIKey,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating self-service key, got %d body=%s", resp.StatusCode, body)
	}
	var selfIssued struct {
		ID     string `json:"id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &selfIssued); err != nil {
		t.Fatalf("failed to decode self key payload: %v body=%s", err, body)
	}
	if strings.TrimSpace(selfIssued.APIKey) == "" || strings.TrimSpace(selfIssued.ID) == "" {
		t.Fatalf("expected self key id and secret, body=%s", body)
	}

	deleteHeaders := map[string]string{
		"Authorization":      "Bearer " + createdByAdmin.APIKey,
		"X-Baseline-Confirm": "revoke_api_key",
		"X-Baseline-Reason":  "self-service revoke test",
	}
	resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/me/api-keys/"+selfIssued.ID, nil, deleteHeaders)
	if resp.StatusCode == http.StatusPreconditionRequired {
		reauthResp, reauthBody := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/reauth", map[string]any{}, map[string]string{
			"Authorization": "Bearer " + createdByAdmin.APIKey,
		})
		if reauthResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 issuing reauth token, got %d body=%s", reauthResp.StatusCode, reauthBody)
		}
		var reauthPayload struct {
			ReauthToken string `json:"reauth_token"`
		}
		if err := json.Unmarshal([]byte(reauthBody), &reauthPayload); err != nil {
			t.Fatalf("failed to decode reauth response: %v body=%s", err, reauthBody)
		}
		if strings.TrimSpace(reauthPayload.ReauthToken) == "" {
			t.Fatalf("expected non-empty reauth token, body=%s", reauthBody)
		}
		deleteHeaders["X-Baseline-Reauth"] = reauthPayload.ReauthToken
		resp, body = mustRequest(t, client, http.MethodDelete, ts.URL+"/v1/me/api-keys/"+selfIssued.ID, nil, deleteHeaders)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 revoking self key, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + selfIssued.APIKey,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked self key auth to fail, got %d body=%s", resp.StatusCode, body)
	}
}

func TestMeAPIKeysRequiresBoundUserIdentity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/me/api-keys", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when api key is not bound to a user identity, got %d body=%s", resp.StatusCode, body)
	}
}

func TestUsersCollectionPaginationMetadata(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_pagination.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		subject := "sub-pagination-" + strconv.Itoa(i+1)
		email := "pagination" + strconv.Itoa(i+1) + "@example.com"
		if _, err := store.UpsertOIDCUser("https://issuer.example", subject, email, "User "+strconv.Itoa(i+1), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("UpsertOIDCUser returned error: %v", err)
		}
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users?limit=1&offset=0", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for paged users list, got %d body=%s", resp.StatusCode, body)
	}
	var page struct {
		Users   []UserRecord `json:"users"`
		Total   int          `json:"total"`
		Limit   int          `json:"limit"`
		Offset  int          `json:"offset"`
		HasMore bool         `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("failed to decode paged users payload: %v body=%s", err, body)
	}
	if len(page.Users) != 1 {
		t.Fatalf("expected 1 user in paged response, got %d body=%s", len(page.Users), body)
	}
	if page.Total < 3 {
		t.Fatalf("expected total >= 3, got %d body=%s", page.Total, body)
	}
	if page.Limit != 1 || page.Offset != 0 {
		t.Fatalf("expected limit=1 offset=0, got limit=%d offset=%d body=%s", page.Limit, page.Offset, body)
	}
	if !page.HasMore {
		t.Fatalf("expected has_more=true when limit=1 and total=%d body=%s", page.Total, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users?limit=1&offset=1", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for second users page, got %d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("failed to decode second paged users payload: %v body=%s", err, body)
	}
	if page.Offset != 1 || page.Limit != 1 {
		t.Fatalf("expected limit=1 offset=1 on second page, got limit=%d offset=%d body=%s", page.Limit, page.Offset, body)
	}
}

func TestUsersCollectionSortingAndValidation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_sorting.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	users := []struct {
		subject string
		email   string
	}{
		{subject: "sub-sort-1", email: "zeta@example.com"},
		{subject: "sub-sort-2", email: "alpha@example.com"},
		{subject: "sub-sort-3", email: "mike@example.com"},
	}
	for i, user := range users {
		if _, err := store.UpsertOIDCUser("https://issuer.example", user.subject, user.email, "Sort User "+strconv.Itoa(i+1), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("UpsertOIDCUser returned error: %v", err)
		}
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users?limit=10&sort_by=user&sort_dir=asc", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for sorted users list, got %d body=%s", resp.StatusCode, body)
	}
	var sortedPayload struct {
		Users []UserRecord `json:"users"`
	}
	if err := json.Unmarshal([]byte(body), &sortedPayload); err != nil {
		t.Fatalf("failed to decode sorted users payload: %v body=%s", err, body)
	}
	if len(sortedPayload.Users) < 3 {
		t.Fatalf("expected at least 3 users in sorted payload, got %d body=%s", len(sortedPayload.Users), body)
	}
	got := []string{
		sortedPayload.Users[0].Email,
		sortedPayload.Users[1].Email,
		sortedPayload.Users[2].Email,
	}
	expected := []string{"alpha@example.com", "mike@example.com", "zeta@example.com"}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("unexpected sorted order at index %d: got=%q expected=%q full=%v", i, got[i], expected[i], got)
		}
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users?sort_by=invalid", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid sort_by, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users?sort_dir=sideways", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid sort_dir, got %d body=%s", resp.StatusCode, body)
	}
}

func TestUserActivityEndpointFiltersByUserActorAndPaginates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_activity.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser("https://issuer.example", "sub-activity-1", "activity1@example.com", "Activity One", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}
	if _, err := store.UpsertOIDCUser("https://issuer.example", "sub-activity-2", "activity2@example.com", "Activity Two", now); err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}

	actor := "session_user:" + strings.ToLower(userID)
	if err := store.AppendAuditEvent(AuditEvent{
		EventType: "user_updated",
		Actor:     actor,
		CreatedAt: now.Add(1 * time.Minute),
	}); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}
	if err := store.AppendAuditEvent(AuditEvent{
		EventType: "api_key_issued",
		Actor:     actor,
		CreatedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}
	if err := store.AppendAuditEvent(AuditEvent{
		EventType: "project_registered",
		Actor:     "session_user:someone_else",
		CreatedAt: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key":    RoleAdmin,
		"operator-key": RoleOperator,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?limit=1&offset=0", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for user activity list, got %d body=%s", resp.StatusCode, body)
	}
	var page struct {
		UserID  string       `json:"user_id"`
		Events  []AuditEvent `json:"events"`
		Total   int          `json:"total"`
		Limit   int          `json:"limit"`
		Offset  int          `json:"offset"`
		HasMore bool         `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("failed to decode user activity response: %v body=%s", err, body)
	}
	if page.UserID != userID {
		t.Fatalf("expected user_id=%q got %q body=%s", userID, page.UserID, body)
	}
	if len(page.Events) != 1 {
		t.Fatalf("expected one activity row for first page, got %d body=%s", len(page.Events), body)
	}
	if page.Total != 2 {
		t.Fatalf("expected total=2 for user activity, got %d body=%s", page.Total, body)
	}
	if !page.HasMore {
		t.Fatalf("expected has_more=true for first activity page, body=%s", body)
	}
	if page.Events[0].Actor != actor {
		t.Fatalf("expected actor=%q, got %q body=%s", actor, page.Events[0].Actor, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?limit=1&offset=1", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for second activity page, got %d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("failed to decode second activity response: %v body=%s", err, body)
	}
	if page.Offset != 1 || page.Limit != 1 {
		t.Fatalf("expected offset=1 limit=1 got offset=%d limit=%d body=%s", page.Offset, page.Limit, body)
	}
	if page.HasMore {
		t.Fatalf("expected has_more=false on last page body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity", nil, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin user activity access, got %d body=%s", resp.StatusCode, body)
	}
}

func TestUserActivityEndpointSupportsFilterQueries(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users_activity_filters.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	userID, err := store.UpsertOIDCUser("https://issuer.example", "sub-activity-filter-1", "activity-filter@example.com", "Activity Filter", now)
	if err != nil {
		t.Fatalf("UpsertOIDCUser returned error: %v", err)
	}

	actor := "session_user:" + strings.ToLower(userID)
	if err := store.AppendAuditEvent(AuditEvent{
		EventType: "user_updated",
		Actor:     actor,
		CreatedAt: now.Add(1 * time.Minute),
	}); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}
	if err := store.AppendAuditEvent(AuditEvent{
		EventType: "api_key_issued",
		Actor:     actor,
		CreatedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("AppendAuditEvent returned error: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DBPath = dbPath
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	client := &http.Client{}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?event_type=api_key_issued", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for event_type filter, got %d body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Events []AuditEvent `json:"events"`
		Total  int          `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode filtered activity response: %v body=%s", err, body)
	}
	if payload.Total != 1 || len(payload.Events) != 1 {
		t.Fatalf("expected one event for event_type filter, total=%d len=%d body=%s", payload.Total, len(payload.Events), body)
	}
	if payload.Events[0].EventType != "api_key_issued" {
		t.Fatalf("expected api_key_issued, got %q body=%s", payload.Events[0].EventType, body)
	}

	from := now.Add(90 * time.Second).Format(time.RFC3339)
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?from="+url.QueryEscape(from), nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for from filter, got %d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode from-filtered response: %v body=%s", err, body)
	}
	if payload.Total != 1 || len(payload.Events) != 1 || payload.Events[0].EventType != "api_key_issued" {
		t.Fatalf("expected one api_key_issued event for from filter, body=%s", body)
	}

	to := now.Add(90 * time.Second).Format(time.RFC3339)
	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?to="+url.QueryEscape(to), nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for to filter, got %d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("failed to decode to-filtered response: %v body=%s", err, body)
	}
	if payload.Total != 1 || len(payload.Events) != 1 || payload.Events[0].EventType != "user_updated" {
		t.Fatalf("expected one user_updated event for to filter, body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?event_type=bad value", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid event_type, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/users/"+userID+"/activity?from=not-a-time", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid from, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(
		t,
		client,
		http.MethodGet,
		ts.URL+"/v1/users/"+userID+"/activity?from="+url.QueryEscape(now.Add(2*time.Hour).Format(time.RFC3339))+"&to="+url.QueryEscape(now.Add(1*time.Hour).Format(time.RFC3339)),
		nil,
		map[string]string{"Authorization": "Bearer admin-key"},
	)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for from>to, got %d body=%s", resp.StatusCode, body)
	}
}
