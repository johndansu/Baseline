package api

import (
	"net/http"
	"strings"
)

func (s *Server) allowMutationByRollout(w http.ResponseWriter, r *http.Request) bool {
	group := rolloutMutationGroup(r.Method, r.URL.Path)
	if group == "" {
		return true
	}
	if rolloutStageAllowsGroup(s.config.DashboardRolloutStage, group) {
		return true
	}
	writeError(w, http.StatusServiceUnavailable, "rollout_blocked", "mutation endpoint disabled by dashboard rollout stage")
	return false
}

func rolloutMutationGroup(method, path string) string {
	if !isMutationMethod(method) {
		return ""
	}

	switch {
	case strings.HasPrefix(path, "/v1/integrations/"):
		return "integrations"
	case method == http.MethodPost && path == "/v1/projects":
		return "core"
	case method == http.MethodPut && strings.HasPrefix(path, "/v1/projects/"):
		return "core"
	case method == http.MethodPost && path == "/v1/scans":
		return "core"
	case method == http.MethodPost && path == "/v1/api-keys":
		return "core"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/api-keys/"):
		return "core"
	case method == http.MethodPost && path == "/v1/me/api-keys":
		return "core"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/me/api-keys/"):
		return "core"
	case method == http.MethodPatch && strings.HasPrefix(path, "/v1/users/"):
		return "core"
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/users/") && strings.Contains(path, "/api-keys"):
		return "core"
	case method == http.MethodDelete && strings.HasPrefix(path, "/v1/users/") && strings.Contains(path, "/api-keys/"):
		return "core"
	case method == http.MethodPost && strings.HasPrefix(path, "/v1/policies/") && strings.HasSuffix(path, "/versions"):
		return "core"
	case method == http.MethodPost && path == "/v1/rulesets":
		return "core"
	default:
		return ""
	}
}

func rolloutStageAllowsGroup(stage DashboardRolloutStage, group string) bool {
	switch stage {
	case DashboardRolloutStageReadOnly:
		return false
	case DashboardRolloutStageMutations:
		return group == "core"
	case DashboardRolloutStageIntegrations, DashboardRolloutStageFull:
		return true
	default:
		return true
	}
}

func isMutationMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
