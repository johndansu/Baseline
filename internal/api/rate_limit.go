package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type rateWindowCounter struct {
	windowStart time.Time
	count       int
}

const (
	rateScopeGeneral = "general"
	rateScopeAuth    = "auth"
	rateScopeUnauth  = "unauth"
)

func (s *Server) allowRequestByRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || !s.config.RateLimitEnabled {
		return true
	}
	if r == nil || r.Method == http.MethodOptions {
		return true
	}
	if !strings.HasPrefix(strings.TrimSpace(r.URL.Path), "/v1/") {
		return true
	}

	scope, limit, window := s.rateLimitPolicyForRequest(r)
	if limit <= 0 || window <= 0 {
		return true
	}

	clientKey := s.clientAddressForRateLimit(r)
	if strings.TrimSpace(clientKey) == "" {
		clientKey = "unknown"
	}
	key := scope + "|" + clientKey

	allowed, remaining, resetAt := s.consumeRateWindow(key, limit, window)
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(maxInt(remaining, 0)))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))

	if allowed {
		return true
	}

	retryAfter := int(time.Until(resetAt).Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
	return false
}

func (s *Server) rateLimitPolicyForRequest(r *http.Request) (string, int, time.Duration) {
	path := strings.TrimSpace(r.URL.Path)
	if strings.HasPrefix(path, "/v1/auth/") || strings.HasPrefix(path, "/v1/api-keys") {
		return rateScopeAuth, s.config.AuthRateLimitRequests, s.config.AuthRateLimitWindow
	}
	if !s.requestHasCredentials(r) {
		return rateScopeUnauth, s.config.UnauthRateLimitRequests, s.config.UnauthRateLimitWindow
	}
	return rateScopeGeneral, s.config.RateLimitRequests, s.config.RateLimitWindow
}

func (s *Server) requestHasCredentials(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return true
	}
	cookie, err := r.Cookie(dashboardSessionCookieName)
	if err == nil && cookie != nil && strings.TrimSpace(cookie.Value) != "" {
		return true
	}
	return false
}

func (s *Server) clientAddressForRateLimit(r *http.Request) string {
	if r == nil {
		return ""
	}
	if s.config.TrustProxyHeaders {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if first != "" {
				return first
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (s *Server) consumeRateWindow(key string, limit int, window time.Duration) (bool, int, time.Time) {
	now := time.Now().UTC()

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	if s.rateState == nil {
		s.rateState = map[string]rateWindowCounter{}
	}
	s.cleanupRateWindowsLocked(now)

	entry, exists := s.rateState[key]
	if !exists || entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= window {
		entry = rateWindowCounter{
			windowStart: now,
			count:       0,
		}
	}

	resetAt := entry.windowStart.Add(window)
	if entry.count >= limit {
		return false, 0, resetAt
	}

	entry.count++
	s.rateState[key] = entry
	remaining := limit - entry.count
	return true, remaining, resetAt
}

func (s *Server) cleanupRateWindowsLocked(now time.Time) {
	if now.Sub(s.rateSweep) < 15*time.Second {
		return
	}
	retention := maxDuration(
		s.config.RateLimitWindow,
		s.config.AuthRateLimitWindow,
		s.config.UnauthRateLimitWindow,
	) * 2
	if retention <= 0 {
		retention = 2 * time.Minute
	}
	for key, entry := range s.rateState {
		if entry.windowStart.IsZero() || now.Sub(entry.windowStart) > retention {
			delete(s.rateState, key)
		}
	}
	s.rateSweep = now
}

func maxDuration(values ...time.Duration) time.Duration {
	maxValue := time.Duration(0)
	for _, value := range values {
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
