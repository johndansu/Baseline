package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

func (s *Server) issueAPIKey(role Role, name, source, createdBy string) (string, APIKeyMetadata, error) {
	if !isValidRole(role) {
		return "", APIKeyMetadata{}, errors.New("invalid role")
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.config.APIKeys == nil {
		s.config.APIKeys = map[string]Role{}
	}
	if s.keyIndex == nil {
		s.keyIndex = map[string]string{}
	}
	if s.keyHashes == nil {
		s.keyHashes = map[string]string{}
	}
	if s.keysByID == nil {
		s.keysByID = map[string]APIKeyMetadata{}
	}

	key := ""
	for attempts := 0; attempts < 10; attempts++ {
		candidate := randomToken(32)
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, exists := s.config.APIKeys[candidate]; exists {
			continue
		}
		if s.hasTokenHashCollisionLocked(candidate) {
			continue
		}
		key = candidate
		break
	}
	if key == "" {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key")
	}
	keyHash := hashAPIKey(key, s.config.APIKeyHashSecret)
	if keyHash == "" {
		return "", APIKeyMetadata{}, errors.New("unable to hash generated API key")
	}
	if s.hasTokenHashCollisionLocked(key) {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key hash")
	}

	id := ""
	for attempts := 0; attempts < 10; attempts++ {
		candidate := nextKeyID()
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, exists := s.keysByID[candidate]; exists {
			continue
		}
		id = candidate
		break
	}
	if id == "" {
		return "", APIKeyMetadata{}, errors.New("unable to create unique key id")
	}

	now := time.Now().UTC()
	metadata := APIKeyMetadata{
		ID:        id,
		Name:      strings.TrimSpace(name),
		Role:      role,
		Prefix:    keyPrefix(key),
		Source:    strings.TrimSpace(source),
		CreatedAt: now,
		CreatedBy: strings.TrimSpace(createdBy),
		Revoked:   false,
	}
	s.config.APIKeys[key] = role
	s.keyIndex[key] = id
	s.keyHashes[keyHash] = id
	s.keysByID[id] = metadata
	if s.store != nil {
		if err := s.store.UpsertAPIKey(key, metadata); err != nil {
			delete(s.config.APIKeys, key)
			delete(s.keyIndex, key)
			delete(s.keyHashes, keyHash)
			delete(s.keysByID, id)
			return "", APIKeyMetadata{}, err
		}
	}
	return key, metadata, nil
}

func (s *Server) findKeyIDByTokenLocked(token string) (string, bool) {
	candidates := apiKeyHashCandidates(token, s.config.APIKeyHashSecret)
	if len(candidates) == 0 {
		return "", false
	}
	for storedHash, keyID := range s.keyHashes {
		for _, candidate := range candidates {
			if constantTimeAPIKeyHashEqual(storedHash, candidate) {
				return keyID, true
			}
		}
	}
	return "", false
}

func (s *Server) hasTokenHashCollisionLocked(token string) bool {
	_, exists := s.findKeyIDByTokenLocked(token)
	return exists
}

func nextKeyID() string {
	fragment := randomToken(6)
	if strings.TrimSpace(fragment) == "" {
		return ""
	}
	return "key_" + fragment
}

func bootstrapKeyID(keyHash string) string {
	trimmed := strings.TrimSpace(keyHash)
	if len(trimmed) < 12 {
		return "key_bootstrap"
	}
	return "key_bootstrap_" + trimmed[:12]
}

func keyPrefix(key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	if len(k) <= 6 {
		return k
	}
	return k[:6] + "..."
}

func randomToken(size int) string {
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
