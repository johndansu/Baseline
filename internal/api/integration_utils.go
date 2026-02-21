package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func validGitHubSignature(body []byte, secret, signature string) bool {
	sig := strings.TrimSpace(signature)
	if !strings.HasPrefix(strings.ToLower(sig), "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
	return secureEquals(sig, expected)
}

func secureEquals(a, b string) bool {
	left := []byte(strings.TrimSpace(a))
	right := []byte(strings.TrimSpace(b))
	return hmac.Equal(left, right)
}

func sanitizeEventToken(raw, fallback string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return fallback
	}
	out := strings.Builder{}
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			out.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			out.WriteRune(ch)
		case ch == '_' || ch == '-' || ch == ':':
			out.WriteRune(ch)
		}
	}
	sanitized := strings.TrimSpace(out.String())
	if sanitized == "" {
		return fallback
	}
	return sanitized
}

func integrationRef(number int) string {
	if number <= 0 {
		return ""
	}
	return strconv.Itoa(number)
}

type integrationRetryableError struct {
	msg string
}

func (e *integrationRetryableError) Error() string {
	return strings.TrimSpace(e.msg)
}

func isRetryableIntegrationError(err error) bool {
	var target *integrationRetryableError
	return errors.As(err, &target)
}
