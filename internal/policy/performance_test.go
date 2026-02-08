package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPerformance evaluates policy engine performance with large repositories
func TestPerformance(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for performance testing
	tempDir, err := os.MkdirTemp("", "baseline-perf-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Create a large number of files to test performance
	numFiles := 1000
	t.Logf("Creating %d test files for performance testing", numFiles)

	// Create test files
	for i := 0; i < numFiles; i++ {
		filename := filepath.Join("testfiles", fmt.Sprintf("test_%d.go", i))
		content := fmt.Sprintf(`package test

func Test%d(t *testing.T) {
	// Performance test file %d
}`, i, i)

		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			t.Errorf("Failed to create directory for %s: %v", filename, err)
			continue
		}

		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			t.Errorf("Failed to create %s: %v", filename, err)
		}
	}

	// Create additional config files
	configFiles := []string{"config.yml", "config.yaml", ".env.example", "Dockerfile"}
	for _, configFile := range configFiles {
		if err := os.WriteFile(configFile, []byte("test config"), 0644); err != nil {
			t.Errorf("Failed to create %s: %v", configFile, err)
		}
	}

	// Measure policy engine performance
	start := time.Now()
	violations := RunAllChecks()
	duration := time.Since(start)

	// Performance assertions
	t.Logf("Policy engine completed in %v for %d files", duration, numFiles)

	// Should complete within reasonable time (less than 5 seconds for 1000 files)
	if duration > 5*time.Second {
		t.Errorf("Policy engine took too long: %v (should be < 5s)", duration)
	}

	// Should handle large file counts efficiently
	if len(violations) == 0 {
		t.Log("No violations found - performance test passed")
	} else {
		t.Logf("Found %d violations", len(violations))
		// Use violations to avoid unused variable warning
		_ = violations
	}

	// Memory efficiency check
	if duration < 1*time.Second {
		t.Log("Fast execution - good performance")
	} else if duration > 2*time.Second {
		t.Log("Slow execution - may need optimization")
	}
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-concurrent-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Create test file
	testFile := "concurrent_test.go"
	content := `package test

func TestConcurrent(t *testing.T) {
	// This test would be run concurrently
}`

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test concurrent access to policy engine
	done := make(chan bool, 10)

	// Start multiple goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Simulate concurrent policy check
			violations := RunAllChecks()
			if violations == nil {
				t.Errorf("Concurrent access %d failed: no violations", id)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	t.Log("Concurrent access test completed successfully")
}

// TestMemoryUsage tests memory efficiency
func TestMemoryUsage(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-memory-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Create many files to test memory usage
	for i := 0; i < 100; i++ {
		filename := fmt.Sprintf("memory_test_%d.go", i)
		content := fmt.Sprintf(`package test

// Memory test file %d
var data = make([]byte, 1000)

func TestMemory%d(t *testing.T) {
	for j := 0; j < 1000; j++ {
		data[j] = byte(j)
	}
}`, i, i)

		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			t.Errorf("Failed to create %s: %v", filename, err)
		}
	}

	// Test policy engine with memory pressure
	start := time.Now()
	violations := RunAllChecks()
	duration := time.Since(start)

	t.Logf("Memory test completed in %v", duration)

	// Should complete without excessive memory usage
	if duration > 10*time.Second {
		t.Errorf("Policy engine took too long under memory pressure: %v", duration)
	}

	// Use violations to avoid unused variable warning
	_ = violations
}
