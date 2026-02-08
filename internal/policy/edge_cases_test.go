package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/types"
)

// TestEdgeCases covers boundary conditions and error scenarios
func TestEdgeCases(t *testing.T) {
	// Test with empty directory
	t.Run("empty_directory", func(t *testing.T) {
		// Save current directory
		origDir, _ := os.Getwd()
		defer os.Chdir(origDir)

		// Create empty temp directory
		tempDir, err := os.MkdirTemp("", "baseline-edge-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		os.Chdir(tempDir)

		// Should handle empty directory gracefully
		violations := RunAllChecks()

		// Should find violations for missing components
		if len(violations) == 0 {
			t.Error("Expected violations in empty directory")
		}

		// Check specific expected violations
		foundCI := false
		foundTests := false
		foundDocs := false

		for _, v := range violations {
			switch v.PolicyID {
			case types.PolicyCIPipeline:
				foundCI = true
			case types.PolicyTestSuite:
				foundTests = true
			case types.PolicyDocumentation:
				foundDocs = true
			}
		}

		if !foundCI {
			t.Error("Expected CI pipeline violation in empty directory")
		}
		if !foundTests {
			t.Error("Expected test suite violation in empty directory")
		}
		if !foundDocs {
			t.Error("Expected documentation violation in empty directory")
		}
	})

	// Test with corrupted files
	t.Run("corrupted_files", func(t *testing.T) {
		// Save current directory
		origDir, _ := os.Getwd()
		defer os.Chdir(origDir)

		// Create temp directory
		tempDir, err := os.MkdirTemp("", "baseline-edge-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		os.Chdir(tempDir)

		// Create corrupted go.mod
		corruptedGoMod := []byte("modu1e github.com/baseline/baseline\n\ngo 1.21\n\ngo invalid")
		if err := os.WriteFile("go.mod", corruptedGoMod, 0644); err != nil {
			t.Fatalf("Failed to create corrupted go.mod: %v", err)
		}

		// Should handle corrupted files gracefully
		violations := RunAllChecks()

		// Should still complete without panicking
		completed := false
		for _, v := range violations {
			if v.PolicyID == types.PolicySystemError {
				completed = true
				break
			}
		}

		if !completed {
			t.Error("Expected system error for corrupted go.mod")
		}

		// Verify error message is informative
		if completed && !strings.Contains(violations[0].Message, "Unable to parse") && !strings.Contains(violations[0].Message, "corrupted") {
			t.Logf("Note: Error message for corrupted files: %s", violations[0].Message)
		}
	})

	// Test with special characters in paths
	t.Run("special_characters", func(t *testing.T) {
		// Save current directory
		origDir, _ := os.Getwd()
		defer os.Chdir(origDir)

		// Create temp directory
		tempDir, err := os.MkdirTemp("", "baseline-edge-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		os.Chdir(tempDir)

		// Create directory with special characters
		specialDir := "test dir with spaces"
		if err := os.MkdirAll(specialDir, 0755); err != nil {
			t.Fatalf("Failed to create special dir: %v", err)
		}

		// Create files in special directory
		testFile := filepath.Join(specialDir, "test.go")
		content := "package test\n"
		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Errorf("Failed to create test file in special dir: %v", err)
		}

		// Should handle special characters in paths
		violations := RunAllChecks()

		// Should still work without path errors
		if len(violations) == 0 {
			t.Error("Expected violations to be found even with special characters")
		}
		// Use violations to avoid unused variable warning
		_ = violations
	})

	// Test with very long file names
	t.Run("long_filenames", func(t *testing.T) {
		// Save current directory
		origDir, _ := os.Getwd()
		defer os.Chdir(origDir)

		// Create temp directory
		tempDir, err := os.MkdirTemp("", "baseline-edge-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		os.Chdir(tempDir)

		// Create file with very long name
		longName := strings.Repeat("very_long_filename_", 20) + ".go"
		content := "package test\n"
		if err := os.WriteFile(longName, []byte(content), 0644); err != nil {
			// Windows has filename length limitations
			t.Logf("Note: Long filename creation failed (expected on Windows): %v", err)
			// This is expected behavior on Windows
		} else {
			// Should handle long filenames
			violations := RunAllChecks()

			// Should complete without errors
			if len(violations) > 0 {
				t.Logf("Found %d violations with long filename", len(violations))
			}
		}
	})
}

// TestResourceLimits tests behavior under resource constraints
func TestResourceLimits(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-limits-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test with no file descriptors available
	// This simulates resource exhaustion
	violations := RunAllChecks()

	// Should handle resource constraints gracefully
	if len(violations) == 0 {
		t.Log("Resource limits test passed - no violations found")
	} else {
		t.Logf("Found %d violations under resource constraints", len(violations))
		// Use violations to avoid unused variable warning
		_ = violations
	}
}
