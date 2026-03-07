package api

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleIntegrationJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role == RoleViewer {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive integer")
			return
		}
		if parsed > 100 {
			parsed = 100
		}
		limit = parsed
	}

	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	if provider != "" && provider != "github" && provider != "gitlab" {
		writeError(w, http.StatusBadRequest, "bad_request", "provider must be one of github|gitlab")
		return
	}

	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" &&
		status != IntegrationJobPending &&
		status != IntegrationJobRunning &&
		status != IntegrationJobSucceeded &&
		status != IntegrationJobFailed {
		writeError(w, http.StatusBadRequest, "bad_request", "status must be one of pending|running|succeeded|failed")
		return
	}

	if s.store == nil {
		writeJSON(w, http.StatusOK, IntegrationJobsResponse{Jobs: []IntegrationJobSummary{}})
		return
	}

	queryLimit := limit
	if provider != "" || status != "" {
		queryLimit = 100
	}

	jobs, err := s.store.ListIntegrationJobs(queryLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "failed to load integration jobs")
		return
	}

	out := make([]IntegrationJobSummary, 0, limit)
	for _, job := range jobs {
		if provider != "" && strings.ToLower(strings.TrimSpace(job.Provider)) != provider {
			continue
		}
		if status != "" && strings.ToLower(strings.TrimSpace(job.Status)) != status {
			continue
		}
		out = append(out, IntegrationJobSummary{
			ID:            strings.TrimSpace(job.ID),
			Provider:      strings.TrimSpace(job.Provider),
			JobType:       strings.TrimSpace(job.JobType),
			ProjectRef:    strings.TrimSpace(job.ProjectRef),
			ExternalRef:   strings.TrimSpace(job.ExternalRef),
			Status:        strings.TrimSpace(job.Status),
			AttemptCount:  job.AttemptCount,
			MaxAttempts:   job.MaxAttempts,
			LastError:     strings.TrimSpace(job.LastError),
			NextAttemptAt: job.NextAttemptAt,
			CreatedAt:     job.CreatedAt,
			UpdatedAt:     job.UpdatedAt,
		})
		if len(out) >= limit {
			break
		}
	}

	writeJSON(w, http.StatusOK, IntegrationJobsResponse{Jobs: out})
}
