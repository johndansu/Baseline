package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
	"github.com/baseline/baseline/internal/version"
)

type cliEventPayload struct {
	EventType      string `json:"event_type"`
	Command        string `json:"command"`
	Repository     string `json:"repository,omitempty"`
	Message        string `json:"message,omitempty"`
	Status         string `json:"status,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	ScanID         string `json:"scan_id,omitempty"`
	Version        string `json:"version,omitempty"`
	FilesScanned   int    `json:"files_scanned,omitempty"`
	SecurityIssues int    `json:"security_issues,omitempty"`
	ViolationCount int    `json:"violation_count,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
	TraceID        string `json:"trace_id,omitempty"`
	SpanID         string `json:"span_id,omitempty"`
	ParentSpanID   string `json:"parent_span_id,omitempty"`
	Component      string `json:"component,omitempty"`
	Function       string `json:"function,omitempty"`
	Branch         string `json:"branch,omitempty"`
}

type cliTracePayload struct {
	TraceID        string              `json:"trace_id"`
	Command        string              `json:"command"`
	Repository     string              `json:"repository,omitempty"`
	ProjectID      string              `json:"project_id,omitempty"`
	ScanID         string              `json:"scan_id,omitempty"`
	Status         string              `json:"status,omitempty"`
	Message        string              `json:"message,omitempty"`
	Version        string              `json:"version,omitempty"`
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     time.Time           `json:"finished_at"`
	DurationMS     int64               `json:"duration_ms"`
	EventCount     int                 `json:"event_count"`
	FilesScanned   int                 `json:"files_scanned,omitempty"`
	SecurityIssues int                 `json:"security_issues,omitempty"`
	ViolationCount int                 `json:"violation_count,omitempty"`
	Attributes     map[string]string   `json:"attributes,omitempty"`
	Events         []cliTraceEventBody `json:"events"`
}

type cliTraceEventBody struct {
	TraceID      string            `json:"trace_id,omitempty"`
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Type         string            `json:"type"`
	Component    string            `json:"component,omitempty"`
	Function     string            `json:"function,omitempty"`
	Branch       string            `json:"branch,omitempty"`
	Status       string            `json:"status,omitempty"`
	Message      string            `json:"message,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type cliTelemetryContext struct {
	connection dashboardConnectionConfig
	command    string
	projectID  string
	scanID     string
	startedAt  time.Time
}

func resolveCLITelemetryConnection() dashboardConnectionConfig {
	_ = loadAPIEnvFiles()
	connection, err := resolveDashboardUploadConfigForScan(scanCommandOptions{})
	if err != nil {
		return dashboardConnectionConfig{}
	}
	if connection.Prompted && !connection.Enabled {
		return dashboardConnectionConfig{}
	}
	connection.APIBaseURL = strings.TrimSpace(connection.APIBaseURL)
	if connection.APIBaseURL == "" {
		return dashboardConnectionConfig{}
	}
	if strings.TrimSpace(connection.APIKey) == "" {
		connection.APIKey = strings.TrimSpace(os.Getenv("BASELINE_API_KEY"))
	}
	if strings.TrimSpace(connection.APIKey) == "" {
		return dashboardConnectionConfig{}
	}
	return connection
}

func emitCLIEvent(connection dashboardConnectionConfig, event cliEventPayload) {
	baseURL := strings.TrimRight(strings.TrimSpace(connection.APIBaseURL), "/")
	apiKey := strings.TrimSpace(connection.APIKey)
	if baseURL == "" || apiKey == "" {
		return
	}
	if strings.TrimSpace(event.ProjectID) == "" {
		event.ProjectID = strings.TrimSpace(connection.ProjectID)
	}
	if strings.TrimSpace(event.Repository) == "" {
		event.Repository = currentRepositoryName()
	}
	if strings.TrimSpace(event.Version) == "" {
		event.Version = version.Short()
	}
	event.EventType = strings.TrimSpace(event.EventType)
	event.Command = strings.TrimSpace(event.Command)
	if event.EventType == "" || event.Command == "" {
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/cli/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func emitCLITrace(connection dashboardConnectionConfig, payload cliTracePayload) {
	baseURL := strings.TrimRight(strings.TrimSpace(connection.APIBaseURL), "/")
	apiKey := strings.TrimSpace(connection.APIKey)
	if baseURL == "" || apiKey == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/cli/traces", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func startCLICommandTelemetry(command, projectID, scanID string) cliTelemetryContext {
	ctx := cliTelemetryContext{
		connection: resolveCLITelemetryConnection(),
		command:    strings.TrimSpace(command),
		projectID:  strings.TrimSpace(projectID),
		scanID:     strings.TrimSpace(scanID),
		startedAt:  time.Now(),
	}
	ctx.emit("cli_started", "command invoked", "started", nil)
	return ctx
}

func (c cliTelemetryContext) elapsed() time.Duration {
	if c.startedAt.IsZero() {
		return 0
	}
	return time.Since(c.startedAt)
}

func (c cliTelemetryContext) emit(eventType, message, status string, mutate func(*cliEventPayload)) {
	payload := cliEventPayload{
		EventType:  eventType,
		Command:    c.command,
		Message:    strings.TrimSpace(message),
		Status:     strings.TrimSpace(status),
		ProjectID:  c.projectID,
		ScanID:     c.scanID,
		DurationMS: c.elapsed().Milliseconds(),
	}
	if mutate != nil {
		mutate(&payload)
	}
	emitCLIEvent(c.connection, payload)
}

func (c cliTelemetryContext) emitFromScan(eventType, message, status string, results types.ScanResults) {
	payload := cliEventFromScan(eventType, message, status, c.projectID, c.scanID, results, c.elapsed())
	payload.Command = c.command
	emitCLIEvent(c.connection, payload)
}

func cliEventFromScan(eventType, message, status string, projectID, scanID string, results types.ScanResults, duration time.Duration) cliEventPayload {
	return cliEventPayload{
		EventType:      eventType,
		Command:        "scan",
		Message:        strings.TrimSpace(message),
		Status:         strings.TrimSpace(status),
		ProjectID:      strings.TrimSpace(projectID),
		ScanID:         strings.TrimSpace(scanID),
		FilesScanned:   results.FilesScanned,
		SecurityIssues: results.SecurityIssues,
		ViolationCount: len(results.Violations),
		DurationMS:     duration.Milliseconds(),
	}
}

func cliEventFromCheck(eventType, message, status string, violationCount int, duration time.Duration) cliEventPayload {
	return cliEventPayload{
		EventType:      eventType,
		Command:        "check",
		Message:        strings.TrimSpace(message),
		Status:         strings.TrimSpace(status),
		ViolationCount: violationCount,
		DurationMS:     duration.Milliseconds(),
	}
}

func emitCLITraceEvents(connection dashboardConnectionConfig, command string, metadata map[string]string, events []clitrace.Event) {
	for _, event := range events {
		payload := cliEventPayload{
			EventType:    strings.TrimSpace(event.Type),
			Command:      strings.TrimSpace(command),
			Message:      strings.TrimSpace(event.Message),
			Status:       strings.TrimSpace(event.Status),
			TraceID:      strings.TrimSpace(event.TraceID),
			SpanID:       strings.TrimSpace(event.SpanID),
			ParentSpanID: strings.TrimSpace(event.ParentSpanID),
			Component:    strings.TrimSpace(event.Component),
			Function:     strings.TrimSpace(event.Function),
			Branch:       strings.TrimSpace(event.Branch),
		}
		mergeCLITraceEventFields(&payload, metadata)
		mergeCLITraceEventFields(&payload, event.Attributes)
		emitCLIEvent(connection, payload)
	}
}

func mergeCLITraceEventFields(payload *cliEventPayload, attrs map[string]string) {
	if payload == nil || len(attrs) == 0 {
		return
	}
	for key, value := range attrs {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "repository":
			if payload.Repository == "" {
				payload.Repository = strings.TrimSpace(value)
			}
		case "project_id":
			if payload.ProjectID == "" {
				payload.ProjectID = strings.TrimSpace(value)
			}
		case "scan_id":
			if payload.ScanID == "" {
				payload.ScanID = strings.TrimSpace(value)
			}
		case "version":
			if payload.Version == "" {
				payload.Version = strings.TrimSpace(value)
			}
		case "files_scanned":
			if payload.FilesScanned == 0 {
				payload.FilesScanned = parseCLITraceInt(value)
			}
		case "security_issues":
			if payload.SecurityIssues == 0 {
				payload.SecurityIssues = parseCLITraceInt(value)
			}
		case "violation_count":
			if payload.ViolationCount == 0 {
				payload.ViolationCount = parseCLITraceInt(value)
			}
		case "duration_ms":
			if payload.DurationMS == 0 {
				payload.DurationMS = int64(parseCLITraceInt(value))
			}
		}
	}
}

func parseCLITraceInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func buildCLITracePayload(command string, ctx *clitrace.Context) cliTracePayload {
	events := ctx.Events()
	metadata := sanitizeCLITraceAttributes(ctx.Metadata())
	payload := cliTracePayload{
		TraceID:    strings.TrimSpace(ctx.TraceID()),
		Command:    strings.TrimSpace(command),
		Repository: strings.TrimSpace(metadata["repository"]),
		ProjectID:  strings.TrimSpace(metadata["project_id"]),
		ScanID:     strings.TrimSpace(metadata["scan_id"]),
		Version:    strings.TrimSpace(metadata["version"]),
		StartedAt:  ctx.StartedAt().UTC(),
		Events:     make([]cliTraceEventBody, 0, len(events)),
		Attributes: metadata,
	}
	var latest time.Time
	for _, event := range events {
		if event.Timestamp.After(latest) {
			latest = event.Timestamp
		}
		payload.Events = append(payload.Events, cliTraceEventBody{
			TraceID:      strings.TrimSpace(event.TraceID),
			SpanID:       strings.TrimSpace(event.SpanID),
			ParentSpanID: strings.TrimSpace(event.ParentSpanID),
			Type:         strings.TrimSpace(event.Type),
			Component:    strings.TrimSpace(event.Component),
			Function:     strings.TrimSpace(event.Function),
			Branch:       strings.TrimSpace(event.Branch),
			Status:       strings.TrimSpace(event.Status),
			Message:      strings.TrimSpace(event.Message),
			Attributes:   sanitizeCLITraceAttributes(event.Attributes),
			CreatedAt:    event.Timestamp.UTC(),
		})
		if strings.HasPrefix(strings.TrimSpace(event.Type), "cli_command_completed") {
			payload.Status = strings.TrimSpace(event.Status)
			payload.Message = strings.TrimSpace(event.Message)
		}
	}
	payload.EventCount = len(payload.Events)
	if latest.IsZero() {
		latest = payload.StartedAt
	}
	payload.FinishedAt = latest.UTC()
	payload.DurationMS = payload.FinishedAt.Sub(payload.StartedAt).Milliseconds()
	payload.FilesScanned = parseCLITraceInt(metadata["files_scanned"])
	payload.SecurityIssues = parseCLITraceInt(metadata["security_issues"])
	payload.ViolationCount = parseCLITraceInt(metadata["violation_count"])
	if payload.Status == "" {
		payload.Status = strings.TrimSpace(metadata["status"])
	}
	return payload
}

func sanitizeCLITraceAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return map[string]string{}
	}
	sanitized := make(map[string]string, len(attrs))
	for key, value := range attrs {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		sanitized[trimmedKey] = sanitizeCLITraceValue(trimmedKey, value)
	}
	return sanitized
}

func sanitizeCLITraceValue(key, value string) string {
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return ""
	}
	if strings.Contains(lowerKey, "key") ||
		strings.Contains(lowerKey, "token") ||
		strings.Contains(lowerKey, "secret") ||
		strings.Contains(lowerKey, "password") ||
		strings.Contains(lowerKey, "authorization") ||
		strings.Contains(lowerKey, "cookie") {
		return "[REDACTED]"
	}
	return trimmedValue
}
