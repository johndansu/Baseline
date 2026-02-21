package api

import (
	"net/http"
	"sort"
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
	if !isValidPolicyName(policyName) {
		writeError(w, http.StatusBadRequest, "invalid_policy_name", "invalid policy name")
		return
	}

	switch action {
	case "versions":
		switch r.Method {
		case http.MethodGet:
			s.dataMu.RLock()
			versions := append([]PolicyVersion(nil), s.policies[policyName]...)
			s.dataMu.RUnlock()
			sort.Slice(versions, func(i, j int) bool {
				if versions[i].PublishedAt.Equal(versions[j].PublishedAt) {
					return versions[i].Version < versions[j].Version
				}
				return versions[i].PublishedAt.Before(versions[j].PublishedAt)
			})
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
			var req CreatePolicyVersionRequest
			if !s.decodeJSONBody(w, r, &req) {
				return
			}
			validated, ok := validateCreatePolicyVersionRequest(req)
			if !ok {
				writeError(w, http.StatusBadRequest, "invalid_policy_payload", "invalid policy payload")
				return
			}
			version := validated.Version
			if version == "" {
				version = "v" + time.Now().UTC().Format("20060102150405")
			}
			if !isValidVersionToken(version) {
				writeError(w, http.StatusBadRequest, "invalid_policy_version", "policy version format is invalid")
				return
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
				Description: validated.Description,
				Content:     validated.Content,
				Metadata:    validated.Metadata,
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
		sort.Slice(versions, func(i, j int) bool {
			if versions[i].PublishedAt.Equal(versions[j].PublishedAt) {
				return versions[i].Version < versions[j].Version
			}
			return versions[i].PublishedAt.Before(versions[j].PublishedAt)
		})
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
		var req CreateRulesetRequest
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		validated, ok := validateCreateRulesetRequest(req)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_ruleset_payload", "invalid ruleset payload")
			return
		}
		version := validated.Version
		if version == "" {
			version = "v" + time.Now().UTC().Format("20060102150405")
		}
		if !isValidVersionToken(version) {
			writeError(w, http.StatusBadRequest, "invalid_ruleset_version", "ruleset version format is invalid")
			return
		}

		s.dataMu.Lock()
		for _, policyName := range validated.PolicyNames {
			if len(s.policies[policyName]) == 0 {
				s.dataMu.Unlock()
				writeError(w, http.StatusBadRequest, "invalid_ruleset_payload", "ruleset references unknown policy")
				return
			}
		}
		for _, existing := range s.rulesets {
			if existing.Version == version {
				s.dataMu.Unlock()
				writeError(w, http.StatusConflict, "conflict", "ruleset version already exists")
				return
			}
		}
		item := RulesetVersion{
			Version:     version,
			Description: validated.Description,
			PolicyNames: validated.PolicyNames,
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
	sort.Slice(rulesets, func(i, j int) bool {
		if rulesets[i].CreatedAt.Equal(rulesets[j].CreatedAt) {
			return rulesets[i].Version < rulesets[j].Version
		}
		return rulesets[i].CreatedAt.Before(rulesets[j].CreatedAt)
	})

	if pathSuffix == "latest" {
		if len(rulesets) == 0 {
			writeError(w, http.StatusNotFound, "not_found", "ruleset not found")
			return
		}
		writeJSON(w, http.StatusOK, rulesets[len(rulesets)-1])
		return
	}
	if !isValidVersionToken(pathSuffix) {
		writeError(w, http.StatusBadRequest, "invalid_ruleset_version", "ruleset version format is invalid")
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

func validateCreatePolicyVersionRequest(req CreatePolicyVersionRequest) (CreatePolicyVersionRequest, bool) {
	description := strings.TrimSpace(req.Description)
	if len(description) > 1024 {
		return CreatePolicyVersionRequest{}, false
	}
	version := strings.TrimSpace(req.Version)
	if len(version) > 128 {
		return CreatePolicyVersionRequest{}, false
	}
	if len(req.Content) == 0 {
		return CreatePolicyVersionRequest{}, false
	}
	if len(req.Content) > 256 {
		return CreatePolicyVersionRequest{}, false
	}
	metadata := map[string]interface{}{}
	for key, value := range req.Metadata {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" || len(trimmedKey) > 128 {
			return CreatePolicyVersionRequest{}, false
		}
		metadata[trimmedKey] = value
	}
	return CreatePolicyVersionRequest{
		Version:     version,
		Description: description,
		Content:     req.Content,
		Metadata:    metadata,
	}, true
}

func validateCreateRulesetRequest(req CreateRulesetRequest) (CreateRulesetRequest, bool) {
	version := strings.TrimSpace(req.Version)
	if len(version) > 128 {
		return CreateRulesetRequest{}, false
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > 1024 {
		return CreateRulesetRequest{}, false
	}
	policyNames := dedupeNonEmpty(req.PolicyNames)
	if len(policyNames) == 0 || len(policyNames) > 128 {
		return CreateRulesetRequest{}, false
	}
	for _, name := range policyNames {
		if !isValidPolicyName(name) {
			return CreateRulesetRequest{}, false
		}
	}
	return CreateRulesetRequest{
		Version:     version,
		Description: description,
		PolicyNames: policyNames,
	}, true
}

func isValidPolicyName(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 128 {
		return false
	}
	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_' || ch == '.' || ch == ':':
		default:
			return false
		}
	}
	return true
}

func isValidVersionToken(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 128 {
		return false
	}
	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_' || ch == '.' || ch == ':':
		default:
			return false
		}
	}
	return true
}
