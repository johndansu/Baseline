package log

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func withTestLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := Logger
	Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	t.Cleanup(func() {
		Logger = original
	})
	return &buf
}

func TestInfoRedactsSensitiveStructuredKeys(t *testing.T) {
	buf := withTestLogger(t)

	Info(
		"security_event",
		"authorization", "Bearer top-secret-token",
		"cookie", "session=abc123",
		"api_key", "baseline-api-key",
		"request_id", "req-1",
	)

	logged := buf.String()
	if !strings.Contains(logged, "request_id=req-1") {
		t.Fatalf("expected non-sensitive field in log, got: %s", logged)
	}
	if !strings.Contains(logged, "authorization=<redacted>") {
		t.Fatalf("expected authorization redaction, got: %s", logged)
	}
	if !strings.Contains(logged, "cookie=<redacted>") {
		t.Fatalf("expected cookie redaction, got: %s", logged)
	}
	if !strings.Contains(logged, "api_key=<redacted>") {
		t.Fatalf("expected api_key redaction, got: %s", logged)
	}
	if strings.Contains(logged, "top-secret-token") || strings.Contains(logged, "session=abc123") || strings.Contains(logged, "baseline-api-key") {
		t.Fatalf("sensitive values leaked in log output: %s", logged)
	}
}

func TestWarnRedactsBearerTokenPatternFromErrorValues(t *testing.T) {
	buf := withTestLogger(t)

	Warn("oidc_error", "error", errors.New("provider responded with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))

	logged := buf.String()
	if !strings.Contains(logged, "Bearer <redacted>") {
		t.Fatalf("expected bearer token redaction in error value, got: %s", logged)
	}
	if strings.Contains(logged, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Fatalf("raw bearer token should not appear in logs: %s", logged)
	}
}

func TestInfoRedactsSensitiveValuesInsideMapFields(t *testing.T) {
	buf := withTestLogger(t)

	Info("request_headers", "headers", map[string]string{
		"Authorization": "Bearer token-from-header",
		"Cookie":        "baseline_dashboard_session=secret",
		"X-Request-ID":  "req-2",
	})

	logged := buf.String()
	if !strings.Contains(logged, "X-Request-ID:req-2") {
		t.Fatalf("expected non-sensitive map field in log output, got: %s", logged)
	}
	if !strings.Contains(logged, "Authorization:<redacted>") || !strings.Contains(logged, "Cookie:<redacted>") {
		t.Fatalf("expected sensitive header values to be redacted in map output, got: %s", logged)
	}
	if strings.Contains(logged, "token-from-header") || strings.Contains(logged, "baseline_dashboard_session=secret") {
		t.Fatalf("sensitive map values leaked in log output: %s", logged)
	}
}

func TestInfoRedactsBearerTokensInSliceValues(t *testing.T) {
	buf := withTestLogger(t)

	Info("auth_context", "details", []string{
		"Bearer token-one",
		"safe-value",
	})

	logged := buf.String()
	if !strings.Contains(logged, "Bearer <redacted>") {
		t.Fatalf("expected bearer token redaction in slice values, got: %s", logged)
	}
	if strings.Contains(logged, "token-one") {
		t.Fatalf("raw bearer token leaked in slice values: %s", logged)
	}
	if !strings.Contains(logged, "safe-value") {
		t.Fatalf("expected non-sensitive value retained, got: %s", logged)
	}
}
