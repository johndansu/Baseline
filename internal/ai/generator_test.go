package ai

import (
	"os"
	"testing"

	"github.com/baseline/baseline/internal/types"
)

func TestDefaultConfig(t *testing.T) {
	// Clear env vars for test
	originalURL := os.Getenv("OLLAMA_URL")
	originalModel := os.Getenv("OLLAMA_MODEL")
	defer func() {
		if originalURL != "" {
			os.Setenv("OLLAMA_URL", originalURL)
		} else {
			os.Unsetenv("OLLAMA_URL")
		}
		if originalModel != "" {
			os.Setenv("OLLAMA_MODEL", originalModel)
		} else {
			os.Unsetenv("OLLAMA_MODEL")
		}
	}()

	os.Unsetenv("OLLAMA_URL")
	os.Unsetenv("OLLAMA_MODEL")

	config := DefaultConfig()

	if config.OllamaURL != "http://localhost:11434" {
		t.Errorf("Expected default OllamaURL 'http://localhost:11434', got '%s'", config.OllamaURL)
	}

	if config.Model != "tinyllama:latest" {
		t.Errorf("Expected default Model 'tinyllama:latest', got '%s'", config.Model)
	}
}

func TestDefaultConfigWithEnvVars(t *testing.T) {
	// Set custom env vars
	os.Setenv("OLLAMA_URL", "http://custom:8080")
	os.Setenv("OLLAMA_MODEL", "llama2:7b")
	defer func() {
		os.Unsetenv("OLLAMA_URL")
		os.Unsetenv("OLLAMA_MODEL")
	}()

	config := DefaultConfig()

	if config.OllamaURL != "http://custom:8080" {
		t.Errorf("Expected custom OllamaURL 'http://custom:8080', got '%s'", config.OllamaURL)
	}

	if config.Model != "llama2:7b" {
		t.Errorf("Expected custom Model 'llama2:7b', got '%s'", config.Model)
	}
}

func TestNewGenerator(t *testing.T) {
	config := Config{
		OllamaURL: "http://test:1234",
		Model:     "test-model",
	}

	gen := NewGenerator(config)

	if gen.config.OllamaURL != config.OllamaURL {
		t.Error("Generator config URL mismatch")
	}
	if gen.config.Model != config.Model {
		t.Error("Generator config Model mismatch")
	}
	if gen.client == nil {
		t.Error("Generator HTTP client is nil")
	}
}

func TestGenerateCIConfigNoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

	// No CI violation in list
	violations := []types.PolicyViolation{
		{PolicyID: types.PolicyTestSuite, Message: "No tests", Severity: types.SeverityBlock},
	}

	_, err := gen.GenerateCIConfig(violations)
	if err == nil {
		t.Error("Expected error when no CI violation exists")
	}
}

func TestGenerateTestScaffoldNoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

	// No test violation in list
	violations := []types.PolicyViolation{
		{PolicyID: types.PolicyCIPipeline, Message: "No CI", Severity: types.SeverityBlock},
	}

	_, err := gen.GenerateTestScaffold(violations)
	if err == nil {
		t.Error("Expected error when no test violation exists")
	}
}

func TestGenerateREADMENoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

	violations := []types.PolicyViolation{}

	_, err := gen.GenerateREADME(violations)
	if err == nil {
		t.Error("Expected error when no documentation violation exists")
	}
}

func TestGenerateDockerfileNoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

	violations := []types.PolicyViolation{}

	_, err := gen.GenerateDockerfile(violations)
	if err == nil {
		t.Error("Expected error when no deployment violation exists")
	}
}

func TestGenerateEnvExampleNoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

	violations := []types.PolicyViolation{}

	_, err := gen.GenerateEnvExample(violations)
	if err == nil {
		t.Error("Expected error when no env violation exists")
	}
}

func TestWriteGeneratedFile(t *testing.T) {
	gen := NewDefaultGenerator()

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test writing file
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tempDir)

	testContent := "test content"
	err = gen.WriteGeneratedFile("test.txt", testContent)
	if err != nil {
		t.Fatalf("WriteGeneratedFile failed: %v", err)
	}

	// Verify file exists and has correct content
	content, err := os.ReadFile("test.txt")
	if err != nil {
		t.Fatalf("Failed to read generated file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("File content mismatch: got '%s', want '%s'", string(content), testContent)
	}
}

func TestWriteGeneratedFileWithSubdirectory(t *testing.T) {
	gen := NewDefaultGenerator()

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test writing file in subdirectory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tempDir)

	err = gen.WriteGeneratedFile("subdir/nested/test.txt", "content")
	if err != nil {
		t.Fatalf("WriteGeneratedFile with subdirectory failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat("subdir/nested/test.txt"); os.IsNotExist(err) {
		t.Error("Generated file with subdirectory does not exist")
	}
}

func TestHasViolation(t *testing.T) {
	violations := []types.PolicyViolation{
		{PolicyID: types.PolicyCIPipeline, Message: "No CI", Severity: types.SeverityBlock},
		{PolicyID: types.PolicyTestSuite, Message: "No tests", Severity: types.SeverityWarn},
	}

	if !hasViolation(violations, types.PolicyCIPipeline) {
		t.Error("Expected to find CI pipeline violation")
	}

	if !hasViolation(violations, types.PolicyTestSuite) {
		t.Error("Expected to find test suite violation")
	}

	if hasViolation(violations, types.PolicyDocumentation) {
		t.Error("Should not find documentation violation")
	}

	if hasViolation([]types.PolicyViolation{}, types.PolicyCIPipeline) {
		t.Error("Should not find violation in empty list")
	}
}
