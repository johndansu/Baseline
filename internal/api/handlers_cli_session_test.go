package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISessionDeviceFlowLifecycle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_session_flow.db"))
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	cliClient := &http.Client{}
	resp, body := mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/start", map[string]any{
		"client_name": "Johns Laptop",
		"client_host": "DESKTOP-123",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 starting cli session, got %d body=%s", resp.StatusCode, body)
	}

	var startPayload struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURL         string `json:"verification_url"`
		CompleteVerificationURL string `json:"complete_verification_url"`
	}
	if err := json.Unmarshal([]byte(body), &startPayload); err != nil {
		t.Fatalf("decode start payload: %v body=%s", err, body)
	}
	if startPayload.DeviceCode == "" || startPayload.UserCode == "" {
		t.Fatalf("expected device and user codes, payload=%+v", startPayload)
	}
	if !strings.Contains(startPayload.VerificationURL, "/cli-login.html") {
		t.Fatalf("expected cli-login verification URL, got %q", startPayload.VerificationURL)
	}
	if !strings.Contains(startPayload.CompleteVerificationURL, "device_code=") || !strings.Contains(startPayload.CompleteVerificationURL, "user_code=") {
		t.Fatalf("expected complete verification URL with device and user code, got %q", startPayload.CompleteVerificationURL)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/poll", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 before approval, got %d body=%s", resp.StatusCode, body)
	}

	jar, _ := cookiejar.New(nil)
	dashboardClient := &http.Client{Jar: jar}
	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating dashboard session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/cli/session/approve", map[string]any{
		"user_code": startPayload.UserCode,
	}, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving cli session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/poll", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after approval, got %d body=%s", resp.StatusCode, body)
	}

	var tokenPayload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Role         Role   `json:"role"`
		User         string `json:"user"`
		ClientName   string `json:"client_name"`
	}
	if err := json.Unmarshal([]byte(body), &tokenPayload); err != nil {
		t.Fatalf("decode poll payload: %v body=%s", err, body)
	}
	if tokenPayload.AccessToken == "" || tokenPayload.RefreshToken == "" {
		t.Fatalf("expected cli tokens after approval, payload=%+v", tokenPayload)
	}
	if tokenPayload.Role != RoleAdmin {
		t.Fatalf("expected admin role from approving dashboard session, got %q", tokenPayload.Role)
	}

	resp, body = mustRequest(t, cliClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 auth/me for cli access token, got %d body=%s", resp.StatusCode, body)
	}
	if !containsAll(body, `"auth_source":"cli_session"`, `"client_name":"Johns Laptop"`) {
		t.Fatalf("expected cli session auth/me response, body=%s", body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodDelete, ts.URL+"/v1/cli/session", nil, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 revoking cli session, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after cli session revoke, got %d body=%s", resp.StatusCode, body)
	}
}

func TestCLISessionRefreshRotatesTokens(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleOperator

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_session_refresh.db"))
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	cliClient := &http.Client{}
	resp, body := mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/start", map[string]any{
		"client_name": "Operator Laptop",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 starting cli session, got %d body=%s", resp.StatusCode, body)
	}
	var startPayload struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal([]byte(body), &startPayload); err != nil {
		t.Fatalf("decode start payload: %v body=%s", err, body)
	}

	jar, _ := cookiejar.New(nil)
	dashboardClient := &http.Client{Jar: jar}
	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating dashboard session, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/cli/session/approve", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving cli session, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/poll", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 polling approved cli session, got %d body=%s", resp.StatusCode, body)
	}
	var tokenPayload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(body), &tokenPayload); err != nil {
		t.Fatalf("decode token payload: %v body=%s", err, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/refresh", map[string]any{
		"refresh_token": tokenPayload.RefreshToken,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 rotating cli session, got %d body=%s", resp.StatusCode, body)
	}
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(body), &rotated); err != nil {
		t.Fatalf("decode rotated payload: %v body=%s", err, body)
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" {
		t.Fatalf("expected rotated cli tokens, payload=%+v", rotated)
	}
	if rotated.AccessToken == tokenPayload.AccessToken || rotated.RefreshToken == tokenPayload.RefreshToken {
		t.Fatalf("expected token rotation to replace both tokens")
	}

	resp, body = mustRequest(t, cliClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + rotated.AccessToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for rotated access token, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/refresh", map[string]any{
		"refresh_token": tokenPayload.RefreshToken,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale refresh token, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale access token, got %d body=%s", resp.StatusCode, body)
	}
}

func TestCLISessionAdminListAndRevokeByID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_session_admin_list.db"))
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	cliClient := &http.Client{}
	resp, body := mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/start", map[string]any{
		"client_name": "Admin Laptop",
		"client_host": "DESKTOP-ADMIN",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 starting cli session, got %d body=%s", resp.StatusCode, body)
	}
	var startPayload struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal([]byte(body), &startPayload); err != nil {
		t.Fatalf("decode start payload: %v body=%s", err, body)
	}

	jar, _ := cookiejar.New(nil)
	dashboardClient := &http.Client{Jar: jar}
	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating dashboard session, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/cli/session/approve", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving cli session, got %d body=%s", resp.StatusCode, body)
	}
	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/poll", map[string]any{
		"device_code": startPayload.DeviceCode,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 polling approved cli session, got %d body=%s", resp.StatusCode, body)
	}
	var tokenPayload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tokenPayload); err != nil {
		t.Fatalf("decode token payload: %v body=%s", err, body)
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "baseline_repo",
		"name": "Baseline",
	}, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project for cli session metadata, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/events", map[string]any{
		"event_type": "cli_completed",
		"command":    "scan",
		"repository": "Baseline",
		"project_id": "baseline_repo",
		"version":    "dev",
		"status":     "ok",
		"message":    "scan completed",
	}, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 recording cli event for session metadata, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/traces", map[string]any{
		"trace_id":      "trc_session_detail_0",
		"command":       "report",
		"repository":    "OtherRepo",
		"project_id":    "other_repo",
		"scan_id":       "",
		"status":        "error",
		"message":       "report failed",
		"version":       "dev",
		"started_at":    "2026-03-16T09:56:00Z",
		"finished_at":   "2026-03-16T09:57:00Z",
		"duration_ms":   60000,
		"event_count":   1,
		"files_scanned": 0,
		"events": []map[string]any{
			{
				"span_id":    "spn_session_0",
				"type":       "cli_command_completed",
				"component":  "cli",
				"function":   "report",
				"status":     "error",
				"message":    "report failed",
				"created_at": "2026-03-16T09:57:00Z",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 recording prior cli trace for session detail, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/traces", map[string]any{
		"trace_id":      "trc_session_detail_1",
		"command":       "scan",
		"repository":    "Baseline",
		"project_id":    "baseline_repo",
		"scan_id":       "scan_123",
		"status":        "error",
		"message":       "scan failed",
		"version":       "0.9.0",
		"started_at":    "2026-03-16T10:00:00Z",
		"finished_at":   "2026-03-16T10:00:02Z",
		"duration_ms":   2000,
		"event_count":   1,
		"files_scanned": 42,
		"events": []map[string]any{
			{
				"span_id":    "spn_session_1",
				"type":       "cli_command_completed",
				"component":  "cli",
				"function":   "scan",
				"status":     "error",
				"message":    "scan failed",
				"created_at": "2026-03-16T10:00:02Z",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 recording cli trace for session detail, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodGet, ts.URL+"/v1/cli/session?limit=20", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 listing cli sessions, got %d body=%s", resp.StatusCode, body)
	}
	var listPayload struct {
		Sessions []struct {
			SessionID      string `json:"session_id"`
			ClientName     string `json:"client_name"`
			CLIVersion     string `json:"cli_version"`
			LastRepository string `json:"last_repository"`
			LastProjectID  string `json:"last_project_id"`
			LastCommand    string `json:"last_command"`
			LastScanID     string `json:"last_scan_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(body), &listPayload); err != nil {
		t.Fatalf("decode session list payload: %v body=%s", err, body)
	}
	if len(listPayload.Sessions) != 1 {
		t.Fatalf("expected 1 cli session in list, got %d body=%s", len(listPayload.Sessions), body)
	}
	if listPayload.Sessions[0].SessionID == "" || listPayload.Sessions[0].ClientName != "Admin Laptop" {
		t.Fatalf("unexpected listed cli session payload: %+v", listPayload.Sessions[0])
	}
	if listPayload.Sessions[0].CLIVersion != "0.9.0" || listPayload.Sessions[0].LastRepository != "Baseline" || listPayload.Sessions[0].LastProjectID != "baseline_repo" || listPayload.Sessions[0].LastCommand != "scan" {
		t.Fatalf("expected cli session metadata to be tracked, got %+v", listPayload.Sessions[0])
	}
	if listPayload.Sessions[0].LastScanID != "scan_123" {
		t.Fatalf("expected session metadata to reflect last traced scan, got %+v", listPayload.Sessions[0])
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodGet, ts.URL+"/v1/cli/session/"+listPayload.Sessions[0].SessionID, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 loading cli session detail, got %d body=%s", resp.StatusCode, body)
	}
	var detailPayload struct {
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
		RecentTraces []struct {
			TraceID   string `json:"trace_id"`
			SessionID string `json:"session_id"`
		} `json:"recent_traces"`
		Timeline []struct {
			Kind   string `json:"kind"`
			Title  string `json:"title"`
			Status string `json:"status"`
		} `json:"timeline"`
		RiskSignals []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"risk_signals"`
		AnomalyFlags []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"anomaly_flags"`
	}
	if err := json.Unmarshal([]byte(body), &detailPayload); err != nil {
		t.Fatalf("decode session detail payload: %v body=%s", err, body)
	}
	if detailPayload.Session.SessionID != listPayload.Sessions[0].SessionID {
		t.Fatalf("expected matching cli session detail id, got %+v", detailPayload.Session)
	}
	if len(detailPayload.RecentTraces) == 0 || detailPayload.RecentTraces[0].TraceID != "trc_session_detail_1" {
		t.Fatalf("expected recent trace in cli session detail, got %+v", detailPayload.RecentTraces)
	}
	if detailPayload.RecentTraces[0].SessionID != listPayload.Sessions[0].SessionID {
		t.Fatalf("expected trace to be associated with cli session, got %+v", detailPayload.RecentTraces[0])
	}
	if len(detailPayload.Timeline) == 0 {
		t.Fatalf("expected session timeline in cli session detail, got %+v", detailPayload)
	}
	if detailPayload.Timeline[0].Kind == "" || detailPayload.Timeline[0].Title == "" {
		t.Fatalf("expected timeline entries to be populated, got %+v", detailPayload.Timeline[0])
	}
	if len(detailPayload.RiskSignals) == 0 {
		t.Fatalf("expected risk signals in cli session detail, got %+v", detailPayload)
	}
	if detailPayload.RiskSignals[0].ID == "" || detailPayload.RiskSignals[0].Severity == "" {
		t.Fatalf("expected populated risk signal entry, got %+v", detailPayload.RiskSignals[0])
	}
	if len(detailPayload.AnomalyFlags) == 0 {
		t.Fatalf("expected anomaly flags in cli session detail, got %+v", detailPayload)
	}
	if detailPayload.AnomalyFlags[0].ID == "" || detailPayload.AnomalyFlags[0].Severity == "" {
		t.Fatalf("expected populated anomaly flag entry, got %+v", detailPayload.AnomalyFlags[0])
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodDelete, ts.URL+"/v1/cli/session/"+listPayload.Sessions[0].SessionID, nil, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 revoking cli session by id, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, cliClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + tokenPayload.AccessToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after admin revoked cli session by id, got %d body=%s", resp.StatusCode, body)
	}
}

func TestCLISessionAdminRevokeAllByUserID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_session_revoke_all.db"))
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	dashboardClient := &http.Client{Jar: jar}
	resp, body := mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating dashboard session, got %d body=%s", resp.StatusCode, body)
	}

	startAndApprove := func(clientName string) string {
		cliClient := &http.Client{}
		resp, body := mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/start", map[string]any{
			"client_name": clientName,
		}, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 starting cli session, got %d body=%s", resp.StatusCode, body)
		}
		var startPayload struct {
			DeviceCode string `json:"device_code"`
		}
		if err := json.Unmarshal([]byte(body), &startPayload); err != nil {
			t.Fatalf("decode start payload: %v body=%s", err, body)
		}
		resp, body = mustRequest(t, dashboardClient, http.MethodPost, ts.URL+"/v1/cli/session/approve", map[string]any{
			"device_code": startPayload.DeviceCode,
		}, map[string]string{
			csrfHeaderName: csrfHeaderValue,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 approving cli session, got %d body=%s", resp.StatusCode, body)
		}
		resp, body = mustRequest(t, cliClient, http.MethodPost, ts.URL+"/v1/cli/session/poll", map[string]any{
			"device_code": startPayload.DeviceCode,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 polling approved cli session, got %d body=%s", resp.StatusCode, body)
		}
		var tokenPayload struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal([]byte(body), &tokenPayload); err != nil {
			t.Fatalf("decode token payload: %v body=%s", err, body)
		}
		return tokenPayload.AccessToken
	}

	accessTokenA := startAndApprove("Admin Laptop")
	accessTokenB := startAndApprove("Admin Desktop")

	resp, body = mustRequest(t, dashboardClient, http.MethodGet, ts.URL+"/v1/cli/session?limit=20", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 listing cli sessions, got %d body=%s", resp.StatusCode, body)
	}
	var listPayload struct {
		Sessions []struct {
			OwnerKey string `json:"owner_key"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(body), &listPayload); err != nil {
		t.Fatalf("decode session list payload: %v body=%s", err, body)
	}
	if len(listPayload.Sessions) < 2 {
		t.Fatalf("expected at least 2 cli sessions in list, got %d body=%s", len(listPayload.Sessions), body)
	}
	ownerKey := listPayload.Sessions[0].OwnerKey
	if ownerKey == "" {
		t.Fatalf("expected owner key in listed session payload, body=%s", body)
	}

	resp, body = mustRequest(t, dashboardClient, http.MethodDelete, ts.URL+"/v1/cli/session/owner/"+ownerKey, nil, map[string]string{
		csrfHeaderName: csrfHeaderValue,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 revoking cli sessions by owner key, got %d body=%s", resp.StatusCode, body)
	}

	for _, token := range []string{accessTokenA, accessTokenB} {
		resp, body = mustRequest(t, &http.Client{}, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
			"Authorization": "Bearer " + token,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 after admin revoked all cli sessions by owner key, got %d body=%s", resp.StatusCode, body)
		}
	}
}

func containsAll(body string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(body, fragment) {
			return false
		}
	}
	return true
}
