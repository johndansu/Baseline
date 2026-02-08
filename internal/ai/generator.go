// Package ai provides AI-assisted scaffolding generation.
// AI is used ONLY for scaffolding, never for enforcement decisions.
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baseline/baseline/internal/types"
)

// Config holds AI generator configuration.
type Config struct {
	OllamaURL string
	Model     string
	Timeout   time.Duration
}

// DefaultConfig returns the default AI configuration.
// Values can be overridden via environment variables.
func DefaultConfig() Config {
	url := os.Getenv("OLLAMA_URL")
	if url == "" {
		url = "http://localhost:11434"
	}

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "tinyllama:latest"
	}

	return Config{
		OllamaURL: url,
		Model:     model,
		Timeout:   30 * time.Second,
	}
}

// Generator handles AI-assisted scaffold generation.
type Generator struct {
	config Config
	client *http.Client
}

// NewGenerator creates a new AI generator with the given configuration.
func NewGenerator(config Config) *Generator {
	return &Generator{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// NewDefaultGenerator creates a generator with default configuration.
func NewDefaultGenerator() *Generator {
	return NewGenerator(DefaultConfig())
}

// OllamaRequest represents a request to the Ollama API.
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents a response from the Ollama API.
type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// CheckAvailability verifies the Ollama service is running.
func (g *Generator) CheckAvailability() error {
	resp, err := g.client.Get(g.config.OllamaURL + "/api/tags")
	if err != nil {
		return fmt.Errorf("Ollama not available at %s: %w", g.config.OllamaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// GenerateCIConfig generates a GitHub Actions CI configuration.
func (g *Generator) GenerateCIConfig(violations []types.PolicyViolation) (string, error) {
	if !hasViolation(violations, types.PolicyCIPipeline) {
		return "", fmt.Errorf("no CI violation found")
	}

	prompt := `Generate a GitHub Actions CI/CD workflow file for a Go project.
Requirements:
- Use Go 1.21 or later
- Run tests with go test
- Build the application
- Check for security issues with go vet
- Format code with go fmt
- Generate coverage report
- Name the file .github/workflows/ci.yml
- Use modern GitHub Actions syntax
- Include proper permissions
- Add caching for Go modules

Only return the YAML content, no explanations.`

	return g.callOllama(prompt)
}

// GenerateTestScaffold generates test file scaffolding.
func (g *Generator) GenerateTestScaffold(violations []types.PolicyViolation) (string, error) {
	if !hasViolation(violations, types.PolicyTestSuite) {
		return "", fmt.Errorf("no test violation found")
	}

	prompt := `Generate basic Go test files for a CLI application.
Requirements:
- Create main_test.go for the main package
- Test the main function and CLI commands
- Use table-driven tests
- Include setup and teardown
- Test error cases
- Use testing.T standard library
- Follow Go testing conventions
- Include example test cases for version, check, enforce commands

Only return the Go test code, no explanations.`

	return g.callOllama(prompt)
}

// GenerateREADME generates README documentation.
func (g *Generator) GenerateREADME(violations []types.PolicyViolation) (string, error) {
	if !hasViolation(violations, types.PolicyDocumentation) {
		return "", fmt.Errorf("no documentation violation found")
	}

	prompt := `Generate a comprehensive README.md for a CLI tool called Baseline.
Requirements:
- Baseline is a Production Policy & Enforcement Engine
- It enforces software fundamentals before code reaches production
- Include installation instructions
- Include usage examples for all commands: version, check, enforce, scan, init, report
- Include policy rules explanation
- Include exit codes (0, 20, 50)
- Include contributing guidelines
- Use proper markdown formatting
- Include badges for build status and version

Only return the markdown content, no explanations.`

	return g.callOllama(prompt)
}

// GenerateDockerfile generates a secure Dockerfile.
func (g *Generator) GenerateDockerfile(violations []types.PolicyViolation) (string, error) {
	if !hasViolation(violations, types.PolicyDeploymentConfig) {
		return "", fmt.Errorf("no deployment violation found")
	}

	prompt := `Generate a secure Dockerfile for a Go CLI application called Baseline.
Requirements:
- Use multi-stage build
- Use specific Go version (not latest)
- Create non-root user
- Set working directory
- Copy go.mod and go.sum first
- Build the application
- Use minimal final image
- Set proper permissions
- Include health check if applicable
- Follow Docker best practices

Only return the Dockerfile content, no explanations.`

	return g.callOllama(prompt)
}

// GenerateEnvExample generates environment variable documentation.
func (g *Generator) GenerateEnvExample(violations []types.PolicyViolation) (string, error) {
	if !hasViolation(violations, types.PolicyEnvVariables) {
		return "", fmt.Errorf("no environment violation found")
	}

	prompt := `Generate a .env.example file for a Go CLI application.
Requirements:
- Include common environment variables
- Add database configuration examples
- Add API key examples with placeholder values
- Add logging level configuration
- Add development/production environment settings
- Include comments explaining each variable
- Use secure placeholder values (changeme, placeholder, etc.)
- Follow environment variable naming conventions

Only return the .env.example content, no explanations.`

	return g.callOllama(prompt)
}

// WriteGeneratedFile writes content to the specified file path.
func (g *Generator) WriteGeneratedFile(filename, content string) error {
	// Create directory if needed
	if dir := filepath.Dir(filename); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}

// callOllama makes a request to the Ollama API.
func (g *Generator) callOllama(prompt string) (string, error) {
	request := OllamaRequest{
		Model:  g.config.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := g.client.Post(
		g.config.OllamaURL+"/api/generate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to call Ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

// hasViolation checks if a specific policy violation exists.
func hasViolation(violations []types.PolicyViolation, policyID string) bool {
	for _, v := range violations {
		if v.PolicyID == policyID {
			return true
		}
	}
	return false
}
