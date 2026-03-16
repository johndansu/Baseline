package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
)

func TestBuildCLITracePayloadRedactsSensitiveAttributes(t *testing.T) {
	traceCtx := clitrace.Start("scan")
	traceCtx.SetMetadata("repository", "Baseline")
	traceCtx.SetMetadata("api_key", "super-secret-key")
	traceCtx.SetMetadata("auth_token", "secret-token")
	span := traceCtx.HelperEnter("cli", "example", "testing redaction", map[string]string{
		"password": "very-secret",
		"project":  "baseline_repo",
	})
	traceCtx.HelperExit(span, "cli", "example", "ok", "done", map[string]string{
		"session_cookie": "cookie-value",
		"status":         "ok",
	})
	traceCtx.Complete("ok", "done", map[string]string{
		"secret_value": "top-secret",
	})

	payload := buildCLITracePayload("scan", traceCtx)

	if payload.Attributes["api_key"] != "[REDACTED]" {
		t.Fatalf("expected api_key to be redacted, got %q", payload.Attributes["api_key"])
	}
	if payload.Attributes["auth_token"] != "[REDACTED]" {
		t.Fatalf("expected auth_token to be redacted, got %q", payload.Attributes["auth_token"])
	}
	foundRedactedEvent := false
	for _, event := range payload.Events {
		if event.Function == "example" {
			if event.Attributes["password"] == "[REDACTED]" || event.Attributes["session_cookie"] == "[REDACTED]" {
				foundRedactedEvent = true
			}
		}
	}
	if !foundRedactedEvent {
		t.Fatal("expected sensitive event attributes to be redacted")
	}
}

func TestRunTracedCommandFlushesTraceOnPanic(t *testing.T) {
	type traceEnvelope struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		TraceID string `json:"trace_id"`
	}

	var (
		mu             sync.Mutex
		tracePosts     []traceEnvelope
		eventPostCount int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/cli/events":
			mu.Lock()
			eventPostCount++
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case "/v1/cli/traces":
			defer r.Body.Close()
			var payload traceEnvelope
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode trace payload: %v", err)
			}
			mu.Lock()
			tracePosts = append(tracePosts, payload)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connection := dashboardConnectionConfig{
		APIBaseURL: server.URL,
		APIKey:     "test-api-key",
		ProjectID:  "baseline_repo",
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("expected panic to escape runTracedCommand")
		}
		mu.Lock()
		defer mu.Unlock()
		if eventPostCount == 0 {
			t.Fatal("expected panic path to emit CLI trace events")
		}
		if len(tracePosts) != 1 {
			t.Fatalf("expected one CLI trace payload on panic, got %d", len(tracePosts))
		}
		if tracePosts[0].Status != "panic" {
			t.Fatalf("expected panic trace status, got %q", tracePosts[0].Status)
		}
		if tracePosts[0].Message != "command panicked" {
			t.Fatalf("expected panic trace message, got %q", tracePosts[0].Message)
		}
		if tracePosts[0].TraceID == "" {
			t.Fatal("expected panic trace to include trace id")
		}
	}()

	_ = runTracedCommand("panic-test", connection, func(traceCtx *clitrace.Context) tracedCommandResult {
		traceCtx.SetMetadata("repository", "Baseline")
		panic("boom")
	})
}

func TestRunTracedCommandWarnsWhenTraceUploadSkipped(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
	}()

	result := runTracedCommand("version", dashboardConnectionConfig{}, func(traceCtx *clitrace.Context) tracedCommandResult {
		traceCtx.SetMetadata("repository", "Baseline")
		return tracedCommandResult{
			ExitCode:     0,
			TraceStatus:  "ok",
			TraceMessage: "version completed",
		}
	})

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if result != 0 {
		t.Fatalf("expected success exit code, got %d", result)
	}
	if !strings.Contains(output, "Trace upload skipped") {
		t.Fatalf("expected skipped trace warning, got %q", output)
	}
}
