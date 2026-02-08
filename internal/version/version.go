// Package version provides version information for Baseline.
package version

import (
	"fmt"
	"runtime"
)

// Build information populated at build time.
var (
	// Version is the semantic version.
	Version = "dev"
	// GitCommit is the git commit hash.
	GitCommit = "unknown"
	// BuildDate is the build timestamp.
	BuildDate = "unknown"
	// GoVersion is the Go runtime version.
	GoVersion = runtime.Version()
)

// String returns the full version string.
func String() string {
	if Version == "dev" {
		return "baseline version dev (development build)"
	}
	return fmt.Sprintf("baseline version %s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
}

// Short returns the short version string.
func Short() string {
	return Version
}

// BuildInfo returns detailed build information.
func BuildInfo() map[string]string {
	return map[string]string{
		"version":   Version,
		"commit":    GitCommit,
		"built":     BuildDate,
		"go_version": GoVersion,
	}
}
