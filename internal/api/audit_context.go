package api

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) newRequestAuditEvent(r *http.Request, authSource, eventType, projectID, scanID string) AuditEvent {
	event := AuditEvent{
		EventType: strings.TrimSpace(eventType),
		ProjectID: strings.TrimSpace(projectID),
		ScanID:    strings.TrimSpace(scanID),
		CreatedAt: time.Now().UTC(),
	}
	event.Actor = s.auditActorFromRequest(r, authSource)
	event.RequestID = requestIDFromContext(r.Context())
	return event
}

func (s *Server) auditActorFromRequest(r *http.Request, authSource string) string {
	source := strings.TrimSpace(strings.ToLower(authSource))
	switch source {
	case "session":
		session, err := s.getDashboardSession(r)
		if err == nil {
			if value := strings.TrimSpace(session.UserID); value != "" {
				return "session_user:" + strings.ToLower(value)
			}
			if value := strings.TrimSpace(session.Subject); value != "" {
				return "session_subject:" + strings.ToLower(value)
			}
			if value := strings.TrimSpace(session.Email); value != "" {
				return "session_email:" + strings.ToLower(value)
			}
			if value := strings.TrimSpace(session.User); value != "" {
				return "session_user:" + strings.ToLower(value)
			}
		}
		return "session:unknown"
	case "api_key":
		if ownerID := strings.TrimSpace(s.apiKeyOwnerIDFromRequest(r)); ownerID != "" {
			return ownerID
		}
		return "api_key:unknown"
	default:
		if source == "" {
			return "system"
		}
		return source + ":unknown"
	}
}
