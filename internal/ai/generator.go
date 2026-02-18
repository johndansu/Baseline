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
	Provider          string
	OllamaURL         string
	OllamaModel       string
	OpenRouterURL     string
	OpenRouterModel   string
	OpenRouterAPIKey  string
	OpenRouterReferer string
	OpenRouterTitle   string
	Model             string
	Timeout           time.Duration
}

// DefaultConfig returns the default AI configuration.
// Values can be overridden via environment variables.
func DefaultConfig() Config {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("AI_PROVIDER")))
	openRouterAPIKey := strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	if provider == "" {
		if openRouterAPIKey != "" {
			provider = "openrouter"
		} else {
			provider = "ollama"
		}
	}

	ollamaURL := strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	openRouterURL := strings.TrimSpace(os.Getenv("OPENROUTER_URL"))
	if openRouterURL == "" {
		openRouterURL = "https://openrouter.ai/api/v1"
	}

	ollamaModel := strings.TrimSpace(os.Getenv("OLLAMA_MODEL"))
	if ollamaModel == "" {
		ollamaModel = "tinyllama:latest"
	}

	openRouterModel := strings.TrimSpace(os.Getenv("OPENROUTER_MODEL"))
	if openRouterModel == "" {
		openRouterModel = "openai/gpt-4o-mini"
	}

	model := ollamaModel
	if provider == "openrouter" {
		model = openRouterModel
	}

	return Config{
		Provider:          provider,
		OllamaURL:         ollamaURL,
		OllamaModel:       ollamaModel,
		OpenRouterURL:     openRouterURL,
		OpenRouterModel:   openRouterModel,
		OpenRouterAPIKey:  openRouterAPIKey,
		OpenRouterReferer: strings.TrimSpace(os.Getenv("OPENROUTER_HTTP_REFERER")),
		OpenRouterTitle:   strings.TrimSpace(os.Getenv("OPENROUTER_APP_TITLE")),
		Model:             model,
		Timeout:           30 * time.Second,
	}
}

// Generator handles AI-assisted scaffold generation.
type Generator struct {
	config         Config
	client         *http.Client
	activeProvider string
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

// Provider returns the configured AI provider.
func (g *Generator) Provider() string {
	provider := strings.ToLower(strings.TrimSpace(g.activeProvider))
	if provider != "" {
		return provider
	}

	provider = g.configuredProvider()
	if provider == "" {
		return "ollama"
	}
	return provider
}

func (g *Generator) configuredProvider() string {
	provider := strings.ToLower(strings.TrimSpace(g.config.Provider))
	if provider == "" {
		return "ollama"
	}
	return provider
}

func (g *Generator) canFallbackToOpenRouter() bool {
	return strings.TrimSpace(g.config.OpenRouterAPIKey) != ""
}

func (g *Generator) setActiveProvider(provider string) {
	g.activeProvider = strings.ToLower(strings.TrimSpace(provider))
}

func (g *Generator) ollamaModel() string {
	if model := strings.TrimSpace(g.config.OllamaModel); model != "" {
		return model
	}
	if g.configuredProvider() == "ollama" {
		if model := strings.TrimSpace(g.config.Model); model != "" {
			return model
		}
	}
	return "tinyllama:latest"
}

func (g *Generator) openRouterModel() string {
	if model := strings.TrimSpace(g.config.OpenRouterModel); model != "" {
		return model
	}
	if g.configuredProvider() == "openrouter" {
		if model := strings.TrimSpace(g.config.Model); model != "" {
			return model
		}
	}
	return "openai/gpt-4o-mini"
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

type openRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openRouterRequest struct {
	Model    string              `json:"model"`
	Messages []openRouterMessage `json:"messages"`
	Stream   bool                `json:"stream"`
}

type openRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// CheckAvailability verifies the configured AI provider is reachable.
func (g *Generator) CheckAvailability() error {
	switch g.configuredProvider() {
	case "openrouter":
		if err := g.checkOpenRouterAvailability(); err != nil {
			return err
		}
		g.setActiveProvider("openrouter")
		return nil
	case "ollama":
		ollamaErr := g.checkOllamaAvailability()
		if ollamaErr == nil {
			g.setActiveProvider("ollama")
			return nil
		}

		if g.canFallbackToOpenRouter() {
			if openRouterErr := g.checkOpenRouterAvailability(); openRouterErr == nil {
				g.setActiveProvider("openrouter")
				return nil
			} else {
				return fmt.Errorf("Ollama unavailable and OpenRouter fallback failed: %v | %v", ollamaErr, openRouterErr)
			}
		}
		return ollamaErr
	default:
		return fmt.Errorf("unsupported AI provider %q; use ollama or openrouter", g.config.Provider)
	}
}

func (g *Generator) checkOllamaAvailability() error {
	resp, err := g.client.Get(strings.TrimRight(g.config.OllamaURL, "/") + "/api/tags")
	if err != nil {
		return fmt.Errorf("Ollama not available at %s: %w", g.config.OllamaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama returned status %d", resp.StatusCode)
	}
	return nil
}

func (g *Generator) checkOpenRouterAvailability() error {
	if strings.TrimSpace(g.config.OpenRouterAPIKey) == "" {
		return fmt.Errorf("OpenRouter API key is missing; set OPENROUTER_API_KEY")
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(g.config.OpenRouterURL, "/")+"/models", nil)
	if err != nil {
		return fmt.Errorf("failed to build OpenRouter availability request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.config.OpenRouterAPIKey)
	if g.config.OpenRouterReferer != "" {
		req.Header.Set("HTTP-Referer", g.config.OpenRouterReferer)
	}
	if g.config.OpenRouterTitle != "" {
		req.Header.Set("X-Title", g.config.OpenRouterTitle)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("OpenRouter not available at %s: %w", g.config.OpenRouterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OpenRouter returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

	return g.callModel(prompt)
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

	return g.callModel(prompt)
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

	return g.callModel(prompt)
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

	return g.callModel(prompt)
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

	return g.callModel(prompt)
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

func (g *Generator) callModel(prompt string) (string, error) {
	switch g.Provider() {
	case "openrouter":
		return g.callOpenRouter(prompt)
	case "ollama":
		result, err := g.callOllama(prompt)
		if err == nil {
			g.setActiveProvider("ollama")
			return result, nil
		}

		if g.canFallbackToOpenRouter() {
			fallbackResult, fallbackErr := g.callOpenRouter(prompt)
			if fallbackErr == nil {
				g.setActiveProvider("openrouter")
				return fallbackResult, nil
			}
			return "", fmt.Errorf("Ollama request failed and OpenRouter fallback failed: %v | %v", err, fallbackErr)
		}
		return "", err
	default:
		return "", fmt.Errorf("unsupported AI provider %q; use ollama or openrouter", g.config.Provider)
	}
}

// callOllama makes a request to the Ollama API.
func (g *Generator) callOllama(prompt string) (string, error) {
	request := OllamaRequest{
		Model:  g.ollamaModel(),
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := g.client.Post(
		strings.TrimRight(g.config.OllamaURL, "/")+"/api/generate",
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

func (g *Generator) callOpenRouter(prompt string) (string, error) {
	apiKey := strings.TrimSpace(g.config.OpenRouterAPIKey)
	if apiKey == "" {
		return "", fmt.Errorf("OpenRouter API key is missing; set OPENROUTER_API_KEY")
	}

	request := openRouterRequest{
		Model: g.openRouterModel(),
		Messages: []openRouterMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Stream: false,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OpenRouter request: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		strings.TrimRight(g.config.OpenRouterURL, "/")+"/chat/completions",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to build OpenRouter request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	if g.config.OpenRouterReferer != "" {
		req.Header.Set("HTTP-Referer", g.config.OpenRouterReferer)
	}
	if g.config.OpenRouterTitle != "" {
		req.Header.Set("X-Title", g.config.OpenRouterTitle)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call OpenRouter: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OpenRouter response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OpenRouter returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var openRouterResp openRouterResponse
	if err := json.Unmarshal(body, &openRouterResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal OpenRouter response: %w", err)
	}
	if len(openRouterResp.Choices) == 0 {
		return "", fmt.Errorf("OpenRouter response did not include choices")
	}

	content := strings.TrimSpace(openRouterResp.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("OpenRouter response content is empty")
	}

	return content, nil
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
