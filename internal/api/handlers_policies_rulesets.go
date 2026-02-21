package api

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/policies")
	pathSuffix = strings.Trim(pathSuffix, "/")

	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	if pathSuffix == "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		s.dataMu.RLock()
		policies := clonePoliciesLocked(s.policies)
		s.dataMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"policies": summarizePolicies(policies)})
		return
	}

	parts := strings.Split(pathSuffix, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	policyName := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	if policyName == "" {
		writeError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}

	switch action {
	case "versions":
		switch r.Method {
		case http.MethodGet:
			s.dataMu.RLock()
			versions := append([]PolicyVersion(nil), s.policies[policyName]...)
			s.dataMu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{"name": policyName, "versions": versions})
		case http.MethodPost:
			if role != RoleAdmin {
				writeError(w, http.StatusForbidden, "forbidden", "admin role required")
				return
			}
			if !s.requestBodyAllowed(w, r) {
				return
			}
			if !s.enforceSessionCSRF(w, r, authSource) {
				return
			}
			var req struct {
				Version     string                 `json:"version"`
				Description string                 `json:"description"`
				Content     map[string]any         `json:"content"`
				Metadata    map[string]interface{} `json:"metadata"`
			}
			if !s.decodeJSONBody(w, r, &req) {
				return
			}
			version := strings.TrimSpace(req.Version)
			if version == "" {
				version = "v" + time.Now().UTC().Format("20060102150405")
			}

			s.dataMu.Lock()
			existing := s.policies[policyName]
			for _, item := range existing {
				if item.Version == version {
					s.dataMu.Unlock()
					writeError(w, http.StatusConflict, "conflict", "policy version already exists")
					return
				}
			}
			item := PolicyVersion{
				Name:        policyName,
				Version:     version,
				Description: strings.TrimSpace(req.Description),
				Content:     req.Content,
				Metadata:    req.Metadata,
				PublishedAt: time.Now().UTC(),
				PublishedBy: "api",
			}
			s.policies[policyName] = append(existing, item)
			s.appendEventLocked(AuditEvent{
				EventType: "policy_updated",
				CreatedAt: time.Now().UTC(),
			})
			s.dataMu.Unlock()
			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}
	case "latest":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		s.dataMu.RLock()
		versions := append([]PolicyVersion(nil), s.policies[policyName]...)
		s.dataMu.RUnlock()
		if len(versions) == 0 {
			writeError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		writeJSON(w, http.StatusOK, versions[len(versions)-1])
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleRulesets(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/rulesets")
	pathSuffix = strings.Trim(pathSuffix, "/")

	role, authSource, err := s.authenticateWithSource(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}

	if pathSuffix == "" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if role != RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, authSource) {
			return
		}
		var req struct {
			Version     string   `json:"version"`
			Description string   `json:"description"`
			PolicyNames []string `json:"policy_names"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		version := strings.TrimSpace(req.Version)
		if version == "" {
			version = "v" + time.Now().UTC().Format("20060102150405")
		}

		s.dataMu.Lock()
		for _, existing := range s.rulesets {
			if existing.Version == version {
				s.dataMu.Unlock()
				writeError(w, http.StatusConflict, "conflict", "ruleset version already exists")
				return
			}
		}
		item := RulesetVersion{
			Version:     version,
			Description: strings.TrimSpace(req.Description),
			PolicyNames: dedupeNonEmpty(req.PolicyNames),
			CreatedAt:   time.Now().UTC(),
			CreatedBy:   "api",
		}
		s.rulesets = append(s.rulesets, item)
		s.appendEventLocked(AuditEvent{
			EventType: "ruleset_updated",
			CreatedAt: time.Now().UTC(),
		})
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, item)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	s.dataMu.RLock()
	rulesets := append([]RulesetVersion(nil), s.rulesets...)
	s.dataMu.RUnlock()

	if pathSuffix == "latest" {
		if len(rulesets) == 0 {
			writeError(w, http.StatusNotFound, "not_found", "ruleset not found")
			return
		}
		writeJSON(w, http.StatusOK, rulesets[len(rulesets)-1])
		return
	}

	for _, item := range rulesets {
		if item.Version == pathSuffix {
			writeJSON(w, http.StatusOK, item)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "ruleset not found")
}
