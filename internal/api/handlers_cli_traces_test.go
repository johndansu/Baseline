package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestCLITraceCreateListAndDetail(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"operator-key": RoleOperator,
		"admin-key":    RoleAdmin,
	}

	store, err := NewStore(filepath.Join(t.TempDir(), "cli_traces.db"))
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

	client := &http.Client{}
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/projects", map[string]any{
		"id":   "baseline_repo",
		"name": "Baseline",
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating project for CLI trace ingest, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/cli/traces", map[string]any{
		"trace_id":      "trc_test_1",
		"command":       "scan",
		"repository":    "Baseline",
		"project_id":    "baseline_repo",
		"status":        "ok",
		"message":       "scan completed",
		"version":       "dev",
		"started_at":    "2026-03-16T10:00:00Z",
		"finished_at":   "2026-03-16T10:00:02Z",
		"duration_ms":   2000,
		"event_count":   3,
		"files_scanned": 176,
		"events": []map[string]any{
			{
				"span_id":    "spn_1",
				"type":       "cli_command_started",
				"component":  "cli",
				"function":   "scan",
				"status":     "started",
				"message":    "command invoked",
				"created_at": "2026-03-16T10:00:00Z",
			},
			{
				"span_id":        "spn_2",
				"parent_span_id": "spn_1",
				"type":           "cli_branch_taken",
				"component":      "cli",
				"function":       "HandleScan",
				"branch":         "clean_exit",
				"status":         "ok",
				"message":        "branch selected",
				"created_at":     "2026-03-16T10:00:01Z",
				"attributes":     map[string]string{"files_scanned": "176"},
			},
			{
				"span_id":        "spn_3",
				"parent_span_id": "spn_1",
				"type":           "cli_command_completed",
				"component":      "cli",
				"function":       "scan",
				"status":         "ok",
				"message":        "scan completed",
				"created_at":     "2026-03-16T10:00:02Z",
			},
		},
	}, map[string]string{
		"Authorization": "Bearer operator-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for CLI trace ingest, got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/cli/traces?limit=10", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for CLI trace list, got %d body=%s", resp.StatusCode, body)
	}
	var listPayload struct {
		Traces []CLITraceSummary `json:"traces"`
	}
	if err := json.Unmarshal([]byte(body), &listPayload); err != nil {
		t.Fatalf("decode trace list response: %v body=%s", err, body)
	}
	if len(listPayload.Traces) != 1 {
		t.Fatalf("expected one trace in list, got %d", len(listPayload.Traces))
	}
	if listPayload.Traces[0].TraceID != "trc_test_1" {
		t.Fatalf("expected trace_id trc_test_1, got %+v", listPayload.Traces[0])
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/cli/traces/trc_test_1", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for CLI trace detail, got %d body=%s", resp.StatusCode, body)
	}
	var detail CLITraceDetail
	if err := json.Unmarshal([]byte(body), &detail); err != nil {
		t.Fatalf("decode trace detail response: %v body=%s", err, body)
	}
	if detail.Summary.TraceID != "trc_test_1" {
		t.Fatalf("expected trace detail id trc_test_1, got %+v", detail.Summary)
	}
	if len(detail.Events) != 3 {
		t.Fatalf("expected 3 trace events, got %d", len(detail.Events))
	}
}
