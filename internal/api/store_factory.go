package api

import (
	"errors"
	"fmt"
	"strings"
)

const (
	DBDriverSQLite   = "sqlite"
	DBDriverPostgres = "postgres"
)

func normalizeDBDriver(driver string) string {
	normalized := strings.ToLower(strings.TrimSpace(driver))
	if normalized == "" {
		return DBDriverSQLite
	}
	switch normalized {
	case DBDriverSQLite:
		return DBDriverSQLite
	case DBDriverPostgres, "postgresql":
		return DBDriverPostgres
	default:
		return normalized
	}
}

// NormalizeDBDriverForConfig exposes the normalized driver name for config validation.
func NormalizeDBDriverForConfig(driver string) string {
	return normalizeDBDriver(driver)
}

// NewPersistentStoreFromConfig selects the configured backing store.
// SQLite remains the active implementation; Postgres is reserved for a future implementation pass.
func NewPersistentStoreFromConfig(cfg Config) (PersistentStore, error) {
	switch normalizeDBDriver(cfg.DBDriver) {
	case DBDriverSQLite:
		return NewStore(cfg.DBPath)
	case DBDriverPostgres:
		if strings.TrimSpace(cfg.DatabaseURL) == "" {
			return nil, errors.New("postgres database URL is required")
		}
		store, err := NewPostgresStore(cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		return store, nil
	default:
		return nil, fmt.Errorf("unsupported database driver %q", strings.TrimSpace(cfg.DBDriver))
	}
}
