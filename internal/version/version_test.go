package version

import (
	"testing"
)

func TestString(t *testing.T) {
	version := String()
	
	// Should contain "baseline"
	if !contains(version, "baseline") {
		t.Error("Version string should contain 'baseline'")
	}
	
	// Should contain version info
	if !contains(version, "dev") && !contains(version, "commit") {
		t.Error("Version string should contain version or commit info")
	}
}

func TestShort(t *testing.T) {
	short := Short()
	
	// Should not be empty
	if short == "" {
		t.Error("Short version should not be empty")
	}
}

func TestBuildInfo(t *testing.T) {
	info := BuildInfo()
	
	// Should be a map
	if info == nil {
		t.Error("BuildInfo should return a map")
	}
	
	// Should contain expected keys
	expectedKeys := []string{"version", "commit", "built", "go_version"}
	for _, key := range expectedKeys {
		if _, exists := info[key]; !exists {
			t.Errorf("BuildInfo should contain key '%s'", key)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && 
		(len(substr) == 0 || s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()))
}
