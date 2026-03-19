package api

import (
	"strings"
	"testing"
)

func TestNewPersistentStoreFromConfigSQLite(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DBPath = t.TempDir() + "/baseline.db"

	store, err := NewPersistentStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("expected sqlite store to initialize, got error: %v", err)
	}
	if store == nil {
		t.Fatal("expected sqlite store, got nil")
	}
	defer store.Close()
}

func TestNewPersistentStoreFromConfigPostgresRequiresURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DBDriver = DBDriverPostgres
	cfg.DatabaseURL = ""

	store, err := NewPersistentStoreFromConfig(cfg)
	if err == nil {
		t.Fatal("expected postgres config without URL to fail")
	}
	if store != nil {
		t.Fatal("expected nil store for invalid postgres config")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "database url") {
		t.Fatalf("expected database URL error, got %v", err)
	}
}

func TestNewPersistentStoreFromConfigPostgresRejectsInvalidURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DBDriver = DBDriverPostgres
	cfg.DatabaseURL = "not-a-postgres-url"

	store, err := NewPersistentStoreFromConfig(cfg)
	if err == nil {
		t.Fatal("expected invalid postgres URL to fail")
	}
	if store != nil {
		t.Fatal("expected nil store for invalid postgres URL")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "invalid postgres") {
		t.Fatalf("expected invalid postgres url error, got %v", err)
	}
}
