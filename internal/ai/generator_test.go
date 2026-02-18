package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/types"
)

func TestDefaultConfig(t *testing.T) {
	originalProvider := os.Getenv("AI_PROVIDER")
	originalOpenRouterKey := os.Getenv("OPENROUTER_API_KEY")
	originalOpenRouterModel := os.Getenv("OPENROUTER_MODEL")
	originalOpenRouterURL := os.Getenv("OPENROUTER_URL")
	originalOllamaURL := os.Getenv("OLLAMA_URL")
	originalOllamaModel := os.Getenv("OLLAMA_MODEL")
	defer func() {
		restoreEnv("AI_PROVIDER", originalProvider)
		restoreEnv("OPENROUTER_API_KEY", originalOpenRouterKey)
		restoreEnv("OPENROUTER_MODEL", originalOpenRouterModel)
		restoreEnv("OPENROUTER_URL", originalOpenRouterURL)
		restoreEnv("OLLAMA_URL", originalOllamaURL)
		restoreEnv("OLLAMA_MODEL", originalOllamaModel)
	}()

	os.Unsetenv("AI_PROVIDER")
	os.Unsetenv("OPENROUTER_API_KEY")
	os.Unsetenv("OPENROUTER_MODEL")
	os.Unsetenv("OPENROUTER_URL")
	os.Unsetenv("OLLAMA_URL")
	os.Unsetenv("OLLAMA_MODEL")

	config := DefaultConfig()

	if config.Provider != "ollama" {
		t.Errorf("Expected default provider 'ollama', got '%s'", config.Provider)
	}
	if config.OllamaURL != "http://localhost:11434" {
		t.Errorf("Expected default OllamaURL 'http://localhost:11434', got '%s'", config.OllamaURL)
	}
	if config.OpenRouterURL != "https://openrouter.ai/api/v1" {
		t.Errorf("Expected default OpenRouterURL 'https://openrouter.ai/api/v1', got '%s'", config.OpenRouterURL)
	}
	if config.Model != "tinyllama:latest" {
		t.Errorf("Expected default Model 'tinyllama:latest', got '%s'", config.Model)
	}
	if config.OllamaModel != "tinyllama:latest" {
		t.Errorf("Expected default OllamaModel 'tinyllama:latest', got '%s'", config.OllamaModel)
	}
	if config.OpenRouterModel != "openai/gpt-4o-mini" {
		t.Errorf("Expected default OpenRouterModel 'openai/gpt-4o-mini', got '%s'", config.OpenRouterModel)
	}
}

func TestDefaultConfigWithOpenRouterEnv(t *testing.T) {
	os.Setenv("OPENROUTER_API_KEY", "test-key")
	os.Setenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
	defer func() {
		os.Unsetenv("OPENROUTER_API_KEY")
		os.Unsetenv("OPENROUTER_MODEL")
	}()

	config := DefaultConfig()

	if config.Provider != "openrouter" {
		t.Errorf("Expected provider 'openrouter', got '%s'", config.Provider)
	}
	if config.Model != "openai/gpt-4o-mini" {
		t.Errorf("Expected OpenRouter model 'openai/gpt-4o-mini', got '%s'", config.Model)
	}
	if config.OpenRouterAPIKey != "test-key" {
		t.Errorf("Expected OpenRouter API key to be loaded")
	}
	if config.OllamaModel != "tinyllama:latest" {
		t.Errorf("Expected OllamaModel default to remain 'tinyllama:latest', got '%s'", config.OllamaModel)
	}
}

func TestDefaultConfigWithProviderOverride(t *testing.T) {
	os.Setenv("AI_PROVIDER", "ollama")
	os.Setenv("OPENROUTER_API_KEY", "test-key")
	defer func() {
		os.Unsetenv("AI_PROVIDER")
		os.Unsetenv("OPENROUTER_API_KEY")
	}()

	config := DefaultConfig()
	if config.Provider != "ollama" {
		t.Errorf("Expected provider override to use 'ollama', got '%s'", config.Provider)
	}
}

func TestNewGenerator(t *testing.T) {
	config := Config{
		Provider:  "ollama",
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

func TestCheckAvailabilityOpenRouterMissingAPIKey(t *testing.T) {
	gen := NewGenerator(Config{
		Provider:      "openrouter",
		OpenRouterURL: "https://openrouter.ai/api/v1",
		Model:         "openai/gpt-4o-mini",
	})

	err := gen.CheckAvailability()
	if err == nil {
		t.Fatal("expected error when OpenRouter API key is missing")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "openrouter api key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckAvailabilityOpenRouterSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	gen := NewGenerator(Config{
		Provider:         "openrouter",
		OpenRouterURL:    server.URL,
		OpenRouterAPIKey: "test-key",
		Model:            "openai/gpt-4o-mini",
	})

	if err := gen.CheckAvailability(); err != nil {
		t.Fatalf("expected OpenRouter availability check to pass, got: %v", err)
	}
}

func TestCheckAvailabilityOllamaFallbackToOpenRouter(t *testing.T) {
	openRouterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer openRouterServer.Close()

	gen := NewGenerator(Config{
		Provider:         "ollama",
		OllamaURL:        "http://127.0.0.1:1",
		OllamaModel:      "tinyllama:latest",
		OpenRouterURL:    openRouterServer.URL,
		OpenRouterModel:  "openai/gpt-4o-mini",
		OpenRouterAPIKey: "test-key",
	})

	if err := gen.CheckAvailability(); err != nil {
		t.Fatalf("expected fallback availability check to pass, got: %v", err)
	}
	if gen.Provider() != "openrouter" {
		t.Fatalf("expected active provider to switch to openrouter, got: %s", gen.Provider())
	}
}

func TestCallOpenRouterSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"generated content"}}]}`))
	}))
	defer server.Close()

	gen := NewGenerator(Config{
		Provider:         "openrouter",
		OpenRouterURL:    server.URL,
		OpenRouterAPIKey: "test-key",
		Model:            "openai/gpt-4o-mini",
	})

	got, err := gen.callOpenRouter("test prompt")
	if err != nil {
		t.Fatalf("expected callOpenRouter to succeed, got: %v", err)
	}
	if got != "generated content" {
		t.Fatalf("unexpected generated content: %s", got)
	}
}

func TestCallModelFallsBackFromOllamaToOpenRouter(t *testing.T) {
	openRouterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %s", got)
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if model, _ := payload["model"].(string); model != "openai/gpt-4o-mini" {
			t.Fatalf("expected OpenRouter model in fallback request, got: %v", payload["model"])
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"fallback content"}}]}`))
	}))
	defer openRouterServer.Close()

	gen := NewGenerator(Config{
		Provider:         "ollama",
		OllamaURL:        "http://127.0.0.1:1",
		OllamaModel:      "tinyllama:latest",
		OpenRouterURL:    openRouterServer.URL,
		OpenRouterModel:  "openai/gpt-4o-mini",
		OpenRouterAPIKey: "test-key",
	})

	got, err := gen.callModel("test prompt")
	if err != nil {
		t.Fatalf("expected callModel fallback to succeed, got: %v", err)
	}
	if got != "fallback content" {
		t.Fatalf("unexpected fallback content: %s", got)
	}
	if gen.Provider() != "openrouter" {
		t.Fatalf("expected provider to switch to openrouter after fallback, got: %s", gen.Provider())
	}
}

func TestGenerateCIConfigNoViolation(t *testing.T) {
	gen := NewDefaultGenerator()

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

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tempDir)

	testContent := "test content"
	err = gen.WriteGeneratedFile("test.txt", testContent)
	if err != nil {
		t.Fatalf("WriteGeneratedFile failed: %v", err)
	}

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

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tempDir)

	err = gen.WriteGeneratedFile("subdir/nested/test.txt", "content")
	if err != nil {
		t.Fatalf("WriteGeneratedFile with subdirectory failed: %v", err)
	}

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

func restoreEnv(key, value string) {
	if value == "" {
		os.Unsetenv(key)
		return
	}
	os.Setenv(key, value)
}
