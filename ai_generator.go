package main

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
)

type PolicyViolation struct {
	policyID string
	message  string
	severity string
}

type AIGenerator struct {
	ollamaURL string
	model     string
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func NewAIGenerator() *AIGenerator {
	return &AIGenerator{
		ollamaURL: "http://localhost:11434",
		model:     "tinyllama:latest",
	}
}

func (ai *AIGenerator) GenerateCIConfig(violations []PolicyViolation) (string, error) {
	if len(violations) == 0 {
		return "", fmt.Errorf("no violations to fix")
	}

	// Check if CI violation exists
	hasCIViolation := false
	for _, v := range violations {
		if v.policyID == "B1" {
			hasCIViolation = true
			break
		}
	}

	if !hasCIViolation {
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

	return ai.callOllama(prompt)
}

func (ai *AIGenerator) GenerateTestScaffold(violations []PolicyViolation) (string, error) {
	if len(violations) == 0 {
		return "", fmt.Errorf("no violations to fix")
	}

	// Check if test violation exists
	hasTestViolation := false
	for _, v := range violations {
		if v.policyID == "C1" {
			hasTestViolation = true
			break
		}
	}

	if !hasTestViolation {
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

	return ai.callOllama(prompt)
}

func (ai *AIGenerator) GenerateREADME(violations []PolicyViolation) (string, error) {
	if len(violations) == 0 {
		return "", fmt.Errorf("no violations to fix")
	}

	// Check if documentation violation exists
	hasDocViolation := false
	for _, v := range violations {
		if v.policyID == "F1" {
			hasDocViolation = true
			break
		}
	}

	if !hasDocViolation {
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

	return ai.callOllama(prompt)
}

func (ai *AIGenerator) GenerateDockerfile(violations []PolicyViolation) (string, error) {
	if len(violations) == 0 {
		return "", fmt.Errorf("no violations to fix")
	}

	// Check if deployment violation exists
	hasDeployViolation := false
	for _, v := range violations {
		if v.policyID == "H1" {
			hasDeployViolation = true
			break
		}
	}

	if !hasDeployViolation {
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

	return ai.callOllama(prompt)
}

func (ai *AIGenerator) GenerateEnvExample(violations []PolicyViolation) (string, error) {
	if len(violations) == 0 {
		return "", fmt.Errorf("no violations to fix")
	}

	// Check if environment violation exists
	hasEnvViolation := false
	for _, v := range violations {
		if v.policyID == "J1" {
			hasEnvViolation = true
			break
		}
	}

	if !hasEnvViolation {
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

	return ai.callOllama(prompt)
}

func (ai *AIGenerator) callOllama(prompt string) (string, error) {
	request := OllamaRequest{
		Model:  ai.model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(ai.ollamaURL+"/api/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to call Ollama: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

func (ai *AIGenerator) CheckOllamaAvailability() error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(ai.ollamaURL + "/api/tags")
	if err != nil {
		return fmt.Errorf("Ollama not available at %s: %v", ai.ollamaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama returned status %d", resp.StatusCode)
	}

	return nil
}

func (ai *AIGenerator) WriteGeneratedFile(filename, content string) error {
	// Create directory if it doesn't exist
	if strings.Contains(filename, "/") {
		dir := filepath.Dir(filename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", filename, err)
	}

	return nil
}
