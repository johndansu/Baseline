package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	secret := strings.TrimSpace(s.config.GitHubWebhookSecret)
	if secret == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "github webhook integration is disabled")
		return
	}

	body, ok := s.readRequestBody(w, r)
	if !ok {
		return
	}
	signature := strings.TrimSpace(r.Header.Get("X-Hub-Signature-256"))
	if !validGitHubSignature(body, secret, signature) {
		writeError(w, http.StatusForbidden, "forbidden", "invalid github webhook signature")
		return
	}

	var payload struct {
		Action      string `json:"action"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return
	}
	eventName := sanitizeEventToken(r.Header.Get("X-GitHub-Event"), "unknown")
	repository := strings.TrimSpace(payload.Repository.FullName)
	action := sanitizeEventToken(payload.Action, "unknown")
	prNumber := payload.PullRequest.Number

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "github_webhook_received",
		ProjectID: repository,
		ScanID:    integrationRef(prNumber),
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()
	jobID, err := s.enqueueIntegrationJob(IntegrationJob{
		Provider:    "github",
		JobType:     "webhook_event",
		ProjectRef:  repository,
		ExternalRef: integrationRef(prNumber),
		Payload:     string(body),
		MaxAttempts: 5,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to enqueue integration job")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "github",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"pr_number":  prNumber,
		"job_id":     jobID,
	})
}

func (s *Server) handleGitLabWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	token := strings.TrimSpace(s.config.GitLabWebhookToken)
	if token == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "gitlab webhook integration is disabled")
		return
	}
	headerToken := strings.TrimSpace(r.Header.Get("X-Gitlab-Token"))
	if !secureEquals(headerToken, token) {
		writeError(w, http.StatusForbidden, "forbidden", "invalid gitlab webhook token")
		return
	}
	body, ok := s.readRequestBody(w, r)
	if !ok {
		return
	}

	var payload struct {
		ObjectKind       string `json:"object_kind"`
		ObjectAttributes struct {
			Action string `json:"action"`
			IID    int    `json:"iid"`
		} `json:"object_attributes"`
		Project struct {
			PathWithNamespace string `json:"path_with_namespace"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON request")
		return
	}
	eventName := sanitizeEventToken(r.Header.Get("X-Gitlab-Event"), payload.ObjectKind)
	repository := strings.TrimSpace(payload.Project.PathWithNamespace)
	action := sanitizeEventToken(payload.ObjectAttributes.Action, "unknown")
	mrIID := payload.ObjectAttributes.IID

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "gitlab_webhook_received",
		ProjectID: repository,
		ScanID:    integrationRef(mrIID),
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()
	jobID, err := s.enqueueIntegrationJob(IntegrationJob{
		Provider:    "gitlab",
		JobType:     "webhook_event",
		ProjectRef:  repository,
		ExternalRef: integrationRef(mrIID),
		Payload:     string(body),
		MaxAttempts: 5,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to enqueue integration job")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"provider":   "gitlab",
		"event":      eventName,
		"action":     action,
		"repository": repository,
		"mr_iid":     mrIID,
		"job_id":     jobID,
	})
}

func (s *Server) handleGitHubCheckRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if role == RoleViewer {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	if !s.enforceSessionCSRF(w, r, authSource) {
		return
	}

	token := strings.TrimSpace(s.config.GitHubAPIToken)
	baseURL := strings.TrimSpace(s.config.GitHubAPIBaseURL)
	if token == "" || baseURL == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "github status publishing is disabled")
		return
	}

	var req struct {
		Owner      string `json:"owner"`
		Repository string `json:"repository"`
		HeadSHA    string `json:"head_sha"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		DetailsURL string `json:"details_url"`
		ExternalID string `json:"external_id"`
		Output     struct {
			Title   string `json:"title"`
			Summary string `json:"summary"`
		} `json:"output"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	repo := strings.TrimSpace(req.Repository)
	headSHA := strings.TrimSpace(req.HeadSHA)
	name := strings.TrimSpace(req.Name)
	if owner == "" || repo == "" || headSHA == "" || name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "owner, repository, head_sha, and name are required")
		return
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "completed"
	}
	switch status {
	case "queued", "in_progress", "completed":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "status must be one of queued|in_progress|completed")
		return
	}

	conclusion := strings.ToLower(strings.TrimSpace(req.Conclusion))
	if status == "completed" && conclusion == "" {
		conclusion = "neutral"
	}

	payload := map[string]any{
		"name":     name,
		"head_sha": headSHA,
		"status":   status,
	}
	if conclusion != "" {
		payload["conclusion"] = conclusion
	}
	if detailsURL := strings.TrimSpace(req.DetailsURL); detailsURL != "" {
		payload["details_url"] = detailsURL
	}
	if externalID := strings.TrimSpace(req.ExternalID); externalID != "" {
		payload["external_id"] = externalID
	}
	title := strings.TrimSpace(req.Output.Title)
	summary := strings.TrimSpace(req.Output.Summary)
	if title != "" || summary != "" {
		payload["output"] = map[string]any{
			"title":   title,
			"summary": summary,
		}
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to encode github check run payload")
		return
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/check-runs"
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(rawPayload))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to build github api request")
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Accept", "application/vnd.github+json")
	upstreamReq.Header.Set("Authorization", "Bearer "+token)
	upstreamReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	upstreamResp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "integration_failed", "failed to call github api")
		return
	}
	defer upstreamResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(upstreamResp.Body, s.config.MaxBodyBytes))
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "integration_failed", fmt.Sprintf("github api returned status %d", upstreamResp.StatusCode))
		return
	}

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "github_check_published",
		ProjectID: owner + "/" + repo,
		ScanID:    headSHA,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":        true,
		"provider":        "github",
		"repository":      owner + "/" + repo,
		"head_sha":        headSHA,
		"upstream_status": upstreamResp.StatusCode,
	})
}

func (s *Server) handleGitLabStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.requestBodyAllowed(w, r) {
		return
	}
	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if role == RoleViewer {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	if !s.enforceSessionCSRF(w, r, authSource) {
		return
	}

	token := strings.TrimSpace(s.config.GitLabAPIToken)
	baseURL := strings.TrimSpace(s.config.GitLabAPIBaseURL)
	if token == "" || baseURL == "" {
		writeError(w, http.StatusForbidden, "integration_disabled", "gitlab status publishing is disabled")
		return
	}

	var req struct {
		ProjectID   string `json:"project_id"`
		SHA         string `json:"sha"`
		State       string `json:"state"`
		Name        string `json:"name"`
		TargetURL   string `json:"target_url"`
		Description string `json:"description"`
		Ref         string `json:"ref"`
	}
	if !s.decodeJSONBody(w, r, &req) {
		return
	}
	projectID := strings.TrimSpace(req.ProjectID)
	sha := strings.TrimSpace(req.SHA)
	state := strings.ToLower(strings.TrimSpace(req.State))
	if projectID == "" || sha == "" || state == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "project_id, sha, and state are required")
		return
	}
	switch state {
	case "pending", "running", "success", "failed", "canceled", "skipped":
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "state must be one of pending|running|success|failed|canceled|skipped")
		return
	}

	params := url.Values{}
	params.Set("state", state)
	if value := strings.TrimSpace(req.Name); value != "" {
		params.Set("name", value)
	}
	if value := strings.TrimSpace(req.TargetURL); value != "" {
		params.Set("target_url", value)
	}
	if value := strings.TrimSpace(req.Description); value != "" {
		params.Set("description", value)
	}
	if value := strings.TrimSpace(req.Ref); value != "" {
		params.Set("ref", value)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/projects/" + url.PathEscape(projectID) + "/statuses/" + url.PathEscape(sha) + "?" + params.Encode()
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to build gitlab api request")
		return
	}
	upstreamReq.Header.Set("Accept", "application/json")
	upstreamReq.Header.Set("PRIVATE-TOKEN", token)

	upstreamResp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "integration_failed", "failed to call gitlab api")
		return
	}
	defer upstreamResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(upstreamResp.Body, s.config.MaxBodyBytes))
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "integration_failed", fmt.Sprintf("gitlab api returned status %d", upstreamResp.StatusCode))
		return
	}

	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "gitlab_status_published",
		ProjectID: projectID,
		ScanID:    sha,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":        true,
		"provider":        "gitlab",
		"project_id":      projectID,
		"sha":             sha,
		"upstream_status": upstreamResp.StatusCode,
	})
}
