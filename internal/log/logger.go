// Package log provides structured logging for Baseline.
package log

import (
	"log/slog"
	"os"
	"regexp"
	"strings"
)

var (
	// Logger is the global logger instance
	Logger *slog.Logger
)

func init() {
	// Initialize structured logger with text handler for CLI output
	Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// SetLevel sets the logging level
func SetLevel(level slog.Level) {
	Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// Info logs an info message
func Info(msg string, args ...any) {
	Logger.Info(msg, sanitizeArgs(args...)...)
}

// Error logs an error message
func Error(msg string, args ...any) {
	Logger.Error(msg, sanitizeArgs(args...)...)
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	Logger.Warn(msg, sanitizeArgs(args...)...)
}

// Debug logs a debug message
func Debug(msg string, args ...any) {
	Logger.Debug(msg, sanitizeArgs(args...)...)
}

// With returns a logger with additional attributes
func With(args ...any) *slog.Logger {
	return Logger.With(sanitizeArgs(args...)...)
}

const redactedValue = "<redacted>"

var bearerTokenPattern = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9\-._~+/]+=*\b`)

func sanitizeArgs(args ...any) []any {
	if len(args) == 0 {
		return args
	}

	sanitized := make([]any, 0, len(args))
	i := 0
	for i < len(args) {
		if key, ok := args[i].(string); ok && i+1 < len(args) {
			value := args[i+1]
			if isSensitiveKey(key) {
				sanitized = append(sanitized, key, redactedValue)
			} else {
				sanitized = append(sanitized, key, sanitizeValue(value))
			}
			i += 2
			continue
		}
		sanitized = append(sanitized, sanitizeValue(args[i]))
		i++
	}
	return sanitized
}

func sanitizeValue(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return sanitizeString(v)
	case []byte:
		return sanitizeString(string(v))
	case error:
		return sanitizeString(v.Error())
	case map[string]string:
		out := make(map[string]string, len(v))
		for key, val := range v {
			if isSensitiveKey(key) {
				out[key] = redactedValue
				continue
			}
			out[key] = sanitizeString(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			if isSensitiveKey(key) {
				out[key] = redactedValue
				continue
			}
			out[key] = sanitizeValue(val)
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, val := range v {
			out = append(out, sanitizeString(val))
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, val := range v {
			out = append(out, sanitizeValue(val))
		}
		return out
	case interface{ String() string }:
		return sanitizeString(v.String())
	default:
		return value
	}
}

func sanitizeString(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	s = bearerTokenPattern.ReplaceAllString(s, "Bearer "+redactedValue)
	return s
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	return strings.Contains(k, "authorization") ||
		strings.Contains(k, "cookie") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "api_key") ||
		strings.Contains(k, "apikey") ||
		strings.Contains(k, "password")
}
