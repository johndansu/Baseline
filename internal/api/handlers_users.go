package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	if principal.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	if s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "persistence_required", "endpoint requires persistent store")
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/users")
	pathSuffix = strings.Trim(pathSuffix, "/")
	segments := []string{}
	if pathSuffix != "" {
		segments = strings.Split(pathSuffix, "/")
	}

	switch {
	case len(segments) == 0:
		s.handleUsersCollection(w, r)
		return
	case len(segments) == 1:
		s.handleUserByID(w, r, principal, segments[0])
		return
	case len(segments) == 2 && segments[1] == "activity":
		s.handleUserActivity(w, r, segments[0])
		return
	case len(segments) == 2 && segments[1] == "api-keys":
		s.handleUserAPIKeysCollection(w, r, principal, segments[0])
		return
	case len(segments) == 3 && segments[1] == "api-keys":
		s.handleUserAPIKeyByID(w, r, principal, segments[0], segments[2])
		return
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
}

func (s *Server) handleUserActivity(w http.ResponseWriter, r *http.Request, userID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id := strings.TrimSpace(userID)
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "user id is required")
		return
	}

	user, found, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load user")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	limit := parsePositiveIntQueryWithDefault(r.URL.Query().Get("limit"), 50, 200)
	offset := parseNonNegativeIntQueryWithDefault(r.URL.Query().Get("offset"), 0, 1000000)
	eventType, err := parseUserActivityEventTypeQuery(r.URL.Query().Get("event_type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	from, to, err := parseUserActivityTimeRangeQuery(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	actors := auditActorsForUserActivity(user)
	meta, events, err := s.store.ListAuditEventsByActors(actors, limit, offset, eventType, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to list user activity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":  id,
		"events":   events,
		"total":    meta.Total,
		"limit":    meta.Limit,
		"offset":   meta.Offset,
		"has_more": meta.HasMore,
	})
}

func auditActorsForUserActivity(user UserRecord) []string {
	id := strings.TrimSpace(user.ID)
	email := strings.TrimSpace(strings.ToLower(user.Email))
	values := []string{}
	seen := map[string]struct{}{}
	add := func(v string) {
		clean := strings.TrimSpace(v)
		if clean == "" {
			return
		}
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		values = append(values, clean)
	}

	add(id)
	add(strings.ToLower(id))
	add("session_user:" + strings.ToLower(id))
	if email != "" {
		add("session_email:" + email)
	}
	return values
}

func (s *Server) handleMeAPIKeys(w http.ResponseWriter, r *http.Request) {
	principal, err := s.requestPrincipal(r)
	if err != nil {
		writeUnauthorized(w, err.Error())
		return
	}
	ownerUserID := strings.TrimSpace(principal.UserID)
	if ownerUserID == "" {
		writeError(w, http.StatusForbidden, "forbidden", "authenticated user identity is required")
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, "/v1/me/api-keys")
	pathSuffix = strings.Trim(pathSuffix, "/")
	switch r.Method {
	case http.MethodGet:
		if pathSuffix != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		limit := parsePositiveIntQueryWithDefault(r.URL.Query().Get("limit"), 100, 200)
		includeRevoked := parseBoolQuery(r.URL.Query().Get("include_revoked"))
		keys, err := s.listAPIKeysByOwner(ownerUserID, includeRevoked, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to list api keys")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
	case http.MethodPost:
		if pathSuffix != "" {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		targetRole := Role(strings.ToLower(strings.TrimSpace(req.Role)))
		if targetRole == "" {
			targetRole = principal.Role
		}
		if !isValidRole(targetRole) {
			writeError(w, http.StatusBadRequest, "bad_request", "role must be one of viewer|operator|admin")
			return
		}
		if roleRank(targetRole) > roleRank(principal.Role) {
			writeError(w, http.StatusForbidden, "forbidden", "cannot create api key with higher role")
			return
		}
		key, metadata, err := s.issueAPIKey(
			targetRole,
			strings.TrimSpace(req.Name),
			"self_service",
			string(principal.Role),
			&issueAPIKeyOptions{
				OwnerUserID:     ownerUserID,
				OwnerSubject:    principal.Subject,
				OwnerEmail:      principal.Email,
				CreatedByUserID: ownerUserID,
			},
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to generate API key")
			return
		}
		s.dataMu.Lock()
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "api_key_issued", "", metadata.ID))
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         metadata.ID,
			"name":       metadata.Name,
			"role":       metadata.Role,
			"prefix":     metadata.Prefix,
			"source":     metadata.Source,
			"created_at": metadata.CreatedAt,
			"api_key":    key,
		})
	case http.MethodDelete:
		if pathSuffix == "" {
			writeError(w, http.StatusNotFound, "not_found", "api key id is required")
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		if !s.requireSensitiveActionReauth(w, r, principal) {
			return
		}
		confirmationReason, ok := s.requireSensitiveActionConfirmation(w, r, sensitiveActionRevokeAPIKey)
		if !ok {
			return
		}

		s.authMu.Lock()
		metadata, exists := s.keysByID[pathSuffix]
		if !exists {
			s.authMu.Unlock()
			writeError(w, http.StatusNotFound, "not_found", "api key not found")
			return
		}
		if metadata.Source == "bootstrap" {
			s.authMu.Unlock()
			writeError(w, http.StatusConflict, "conflict", "bootstrap API key must be removed from environment and server restarted")
			return
		}
		if strings.TrimSpace(metadata.OwnerUserID) != ownerUserID {
			s.authMu.Unlock()
			writeError(w, http.StatusForbidden, "forbidden", "cannot revoke api key owned by another user")
			return
		}
		if metadata.Revoked {
			s.authMu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      metadata.ID,
				"revoked": true,
			})
			return
		}

		now := time.Now().UTC()
		if s.store != nil {
			if err := s.store.RevokeAPIKeyWithContext(metadata.ID, now, ownerUserID, confirmationReason); err != nil {
				s.authMu.Unlock()
				writeError(w, http.StatusInternalServerError, "system_error", "unable to persist API key revocation")
				return
			}
		}
		metadata.Revoked = true
		metadata.RevokedAt = &now
		metadata.RevokedByUserID = ownerUserID
		metadata.RevocationReason = confirmationReason
		s.keysByID[pathSuffix] = metadata
		for keyHash, id := range s.keyHashes {
			if id == pathSuffix {
				delete(s.keyHashes, keyHash)
				break
			}
		}
		for key, id := range s.keyIndex {
			if id != pathSuffix {
				continue
			}
			delete(s.keyIndex, key)
			delete(s.config.APIKeys, key)
			break
		}
		s.authMu.Unlock()

		s.dataMu.Lock()
		event := s.newRequestAuditEvent(r, principal.AuthSource, "api_key_revoked", "", metadata.ID)
		event.CreatedAt = now
		s.appendEventLocked(event)
		s.dataMu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"id":      metadata.ID,
			"revoked": true,
			"reason":  confirmationReason,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	filter := UserListFilter{
		Limit:  parsePositiveIntQueryWithDefault(r.URL.Query().Get("limit"), 50, 200),
		Offset: parseNonNegativeIntQueryWithDefault(r.URL.Query().Get("offset"), 0, 1000000),
		Query:  strings.TrimSpace(r.URL.Query().Get("q")),
	}
	sortBy, err := parseUserSortByQuery(r.URL.Query().Get("sort_by"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	sortDir, err := parseUserSortDirQuery(r.URL.Query().Get("sort_dir"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	filter.SortBy = sortBy
	filter.SortDir = sortDir
	if roleRaw := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("role"))); roleRaw != "" {
		role := Role(roleRaw)
		if !isValidRole(role) {
			writeError(w, http.StatusBadRequest, "bad_request", "role must be one of viewer|operator|admin")
			return
		}
		filter.Role = role
	}
	if statusRaw := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); statusRaw != "" {
		status := UserStatus(statusRaw)
		if !isValidUserStatus(status) {
			writeError(w, http.StatusBadRequest, "bad_request", "status must be one of active|suspended")
			return
		}
		filter.Status = status
	}

	result, err := s.store.ListUsersPage(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":    result.Users,
		"total":    result.Total,
		"limit":    result.Limit,
		"offset":   result.Offset,
		"has_more": result.HasMore,
	})
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request, principal authPrincipal, userID string) {
	id := strings.TrimSpace(userID)
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "user id is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		user, found, err := s.store.GetUserByID(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to load user")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		writeJSON(w, http.StatusOK, user)
	case http.MethodPatch:
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		var req struct {
			Role   string `json:"role"`
			Status string `json:"status"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}

		current, found, err := s.store.GetUserByID(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to load user")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		targetRole := current.Role
		if roleRaw := strings.TrimSpace(strings.ToLower(req.Role)); roleRaw != "" {
			targetRole = Role(roleRaw)
			if !isValidRole(targetRole) {
				writeError(w, http.StatusBadRequest, "bad_request", "role must be one of viewer|operator|admin")
				return
			}
		}
		targetStatus := current.Status
		if statusRaw := strings.TrimSpace(strings.ToLower(req.Status)); statusRaw != "" {
			targetStatus = UserStatus(statusRaw)
			if !isValidUserStatus(targetStatus) {
				writeError(w, http.StatusBadRequest, "bad_request", "status must be one of active|suspended")
				return
			}
		}

		updated, err := s.store.UpdateUserRoleAndStatus(id, targetRole, targetStatus, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to update user")
			return
		}
		s.dataMu.Lock()
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "user_updated", "", updated.ID))
		s.dataMu.Unlock()
		writeJSON(w, http.StatusOK, updated)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleUserAPIKeysCollection(w http.ResponseWriter, r *http.Request, principal authPrincipal, userID string) {
	id := strings.TrimSpace(userID)
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "user id is required")
		return
	}
	user, found, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system_error", "unable to load user")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := parsePositiveIntQueryWithDefault(r.URL.Query().Get("limit"), 100, 500)
		includeRevoked := parseBoolQuery(r.URL.Query().Get("include_revoked"))
		keys, err := s.listAPIKeysByOwner(user.ID, includeRevoked, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to list api keys")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
	case http.MethodPost:
		if !s.requestBodyAllowed(w, r) {
			return
		}
		if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
			return
		}
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if !s.decodeJSONBody(w, r, &req) {
			return
		}
		targetRole := Role(strings.ToLower(strings.TrimSpace(req.Role)))
		if targetRole == "" {
			targetRole = user.Role
		}
		if !isValidRole(targetRole) {
			writeError(w, http.StatusBadRequest, "bad_request", "role must be one of viewer|operator|admin")
			return
		}
		if user.Status == UserStatusSuspended {
			writeError(w, http.StatusForbidden, "forbidden", "cannot create api keys for suspended user")
			return
		}
		key, metadata, err := s.issueAPIKey(
			targetRole,
			strings.TrimSpace(req.Name),
			"managed",
			"admin",
			&issueAPIKeyOptions{
				OwnerUserID:     user.ID,
				OwnerEmail:      user.Email,
				CreatedByUserID: strings.TrimSpace(principal.UserID),
			},
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "system_error", "unable to generate API key")
			return
		}
		s.dataMu.Lock()
		s.appendEventLocked(s.newRequestAuditEvent(r, principal.AuthSource, "api_key_issued", "", metadata.ID))
		s.dataMu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         metadata.ID,
			"name":       metadata.Name,
			"role":       metadata.Role,
			"prefix":     metadata.Prefix,
			"source":     metadata.Source,
			"created_at": metadata.CreatedAt,
			"api_key":    key,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleUserAPIKeyByID(w http.ResponseWriter, r *http.Request, principal authPrincipal, userID, keyID string) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !s.enforceSessionCSRF(w, r, principal.AuthSource) {
		return
	}
	if !s.requireSensitiveActionReauth(w, r, principal) {
		return
	}
	confirmationReason, ok := s.requireSensitiveActionConfirmation(w, r, sensitiveActionRevokeAPIKey)
	if !ok {
		return
	}

	targetUserID := strings.TrimSpace(userID)
	targetKeyID := strings.TrimSpace(keyID)
	if targetUserID == "" || targetKeyID == "" {
		writeError(w, http.StatusNotFound, "not_found", "user id and api key id are required")
		return
	}

	s.authMu.Lock()
	metadata, exists := s.keysByID[targetKeyID]
	if !exists {
		s.authMu.Unlock()
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	if metadata.Source == "bootstrap" {
		s.authMu.Unlock()
		writeError(w, http.StatusConflict, "conflict", "bootstrap API key must be removed from environment and server restarted")
		return
	}
	if strings.TrimSpace(metadata.OwnerUserID) != targetUserID {
		s.authMu.Unlock()
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	if metadata.Revoked {
		s.authMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      metadata.ID,
			"revoked": true,
		})
		return
	}

	now := time.Now().UTC()
	if s.store != nil {
		if err := s.store.RevokeAPIKeyWithContext(metadata.ID, now, strings.TrimSpace(principal.UserID), confirmationReason); err != nil {
			s.authMu.Unlock()
			writeError(w, http.StatusInternalServerError, "system_error", "unable to persist API key revocation")
			return
		}
	}
	metadata.Revoked = true
	metadata.RevokedAt = &now
	metadata.RevokedByUserID = strings.TrimSpace(principal.UserID)
	metadata.RevocationReason = confirmationReason
	s.keysByID[targetKeyID] = metadata
	for keyHash, id := range s.keyHashes {
		if id == targetKeyID {
			delete(s.keyHashes, keyHash)
			break
		}
	}
	for key, id := range s.keyIndex {
		if id != targetKeyID {
			continue
		}
		delete(s.keyIndex, key)
		delete(s.config.APIKeys, key)
		break
	}
	s.authMu.Unlock()

	s.dataMu.Lock()
	event := s.newRequestAuditEvent(r, principal.AuthSource, "api_key_revoked", "", metadata.ID)
	event.CreatedAt = now
	s.appendEventLocked(event)
	s.dataMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      metadata.ID,
		"revoked": true,
		"reason":  confirmationReason,
	})
}

func (s *Server) listAPIKeysByOwner(ownerUserID string, includeRevoked bool, limit int) ([]APIKeyMetadata, error) {
	if s.store != nil {
		return s.store.ListAPIKeysByOwnerUserID(ownerUserID, includeRevoked, limit)
	}

	ownerID := strings.TrimSpace(ownerUserID)
	if ownerID == "" {
		return []APIKeyMetadata{}, nil
	}
	maxRows := limit
	if maxRows <= 0 || maxRows > 500 {
		maxRows = 100
	}
	s.authMu.RLock()
	keys := make([]APIKeyMetadata, 0, len(s.keysByID))
	for _, item := range s.keysByID {
		if strings.TrimSpace(item.OwnerUserID) != ownerID {
			continue
		}
		if !includeRevoked && item.Revoked {
			continue
		}
		keys = append(keys, item)
	}
	s.authMu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].CreatedAt.After(keys[j].CreatedAt)
	})
	if len(keys) > maxRows {
		keys = keys[:maxRows]
	}
	return keys, nil
}

func parsePositiveIntQueryWithDefault(raw string, fallback, max int) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if max > 0 && parsed > max {
		return max
	}
	return parsed
}

func parseNonNegativeIntQueryWithDefault(raw string, fallback, max int) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	if max > 0 && parsed > max {
		return max
	}
	return parsed
}

func parseUserSortByQuery(raw string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return "updated_at", nil
	}
	switch value {
	case "user", "role", "status", "last_login_at", "created_at", "updated_at":
		return value, nil
	default:
		return "", errors.New("sort_by must be one of user|role|status|last_login_at|created_at|updated_at")
	}
}

func parseUserSortDirQuery(raw string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return "desc", nil
	}
	switch value {
	case "asc", "desc":
		return value, nil
	default:
		return "", errors.New("sort_dir must be one of asc|desc")
	}
}

func parseBoolQuery(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parseUserActivityEventTypeQuery(raw string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return "", nil
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		isLower := ch >= 'a' && ch <= 'z'
		isDigit := ch >= '0' && ch <= '9'
		if isLower || isDigit || ch == '_' || ch == '-' || ch == ':' || ch == '.' {
			continue
		}
		return "", errors.New("event_type must contain only lowercase letters, numbers, underscore, hyphen, colon, or dot")
	}
	return value, nil
}

func parseUserActivityTimeRangeQuery(fromRaw, toRaw string) (*time.Time, *time.Time, error) {
	var fromPtr *time.Time
	var toPtr *time.Time

	fromValue := strings.TrimSpace(fromRaw)
	if fromValue != "" {
		parsed, err := time.Parse(time.RFC3339, fromValue)
		if err != nil {
			return nil, nil, errors.New("from must be RFC3339")
		}
		utc := parsed.UTC()
		fromPtr = &utc
	}

	toValue := strings.TrimSpace(toRaw)
	if toValue != "" {
		parsed, err := time.Parse(time.RFC3339, toValue)
		if err != nil {
			return nil, nil, errors.New("to must be RFC3339")
		}
		utc := parsed.UTC()
		toPtr = &utc
	}

	if fromPtr != nil && toPtr != nil && fromPtr.After(*toPtr) {
		return nil, nil, errors.New("from must be before or equal to to")
	}
	return fromPtr, toPtr, nil
}

func roleRank(role Role) int {
	switch role {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}
