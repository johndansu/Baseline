package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmitCLIEventPostsTelemetry(t *testing.T) {
	var captured map[string]any
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/cli/events" {
			http.NotFound(w, r)
			return
		}
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode event payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	emitCLIEvent(dashboardConnectionConfig{
		APIBaseURL: server.URL,
		APIKey:     "telemetry-key",
		ProjectID:  "proj_saved",
	}, cliEventPayload{
		EventType:      "cli_warning",
		Command:        "scan",
		Message:        "scan completed with blocking policy violations",
		Status:         "violations_found",
		FilesScanned:   11,
		SecurityIssues: 1,
		ViolationCount: 2,
		DurationMS:     900,
	})

	if authHeader != "Bearer telemetry-key" {
		t.Fatalf("expected bearer auth header, got %q", authHeader)
	}
	if captured["event_type"] != "cli_warning" {
		t.Fatalf("expected cli_warning payload, got %#v", captured["event_type"])
	}
	if captured["project_id"] != "proj_saved" {
		t.Fatalf("expected project_id from saved connection, got %#v", captured["project_id"])
	}
	if captured["command"] != "scan" {
		t.Fatalf("expected command scan, got %#v", captured["command"])
	}
}
