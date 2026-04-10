package api

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var errUserEmailAlreadyExists = errors.New("user email already exists")

func normalizeUserEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func newUserID(now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	userID := "usr_" + randomToken(12)
	if strings.TrimSpace(userID) == "usr_" {
		userID = fmt.Sprintf("usr_%d", now.UTC().UnixNano())
	}
	return userID
}
