package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
	"github.com/baseline/baseline/internal/version"
)

type tracedCommandResult struct {
	ExitCode     int
	TraceStatus  string
	TraceMessage string
	Attributes   map[string]string
}

func runTracedCommand(command string, connection dashboardConnectionConfig, fn func(*clitrace.Context) tracedCommandResult) (exitCode int) {
	traceCtx := clitrace.Start(command)
	traceCtx.SetMetadata("command", command)
	traceCtx.SetMetadata("version", versionShort())
	exitCode = types.ExitSystemError

	defer func() {
		if recovered := recover(); recovered != nil {
			traceCtx.Error("cli", command, fmt.Errorf("panic: %v", recovered), nil)
			traceCtx.Complete("panic", "command panicked", map[string]string{
				"duration_ms": strconv.FormatInt(traceCtxElapsedMilliseconds(traceCtx), 10),
			})
			eventsPosted := emitCLITraceEvents(connection, command, traceCtx.Metadata(), traceCtx.Events())
			tracePosted := emitCLITrace(connection, buildCLITracePayload(command, traceCtx))
			warnIfTraceUploadSkipped(command, connection, eventsPosted || tracePosted)
			panic(recovered)
		}
		if !traceCtx.Completed() {
			traceCtx.Complete("unknown", "command completed without explicit trace result", map[string]string{
				"duration_ms": strconv.FormatInt(traceCtxElapsedMilliseconds(traceCtx), 10),
			})
		}
		eventsPosted := emitCLITraceEvents(connection, command, traceCtx.Metadata(), traceCtx.Events())
		tracePosted := emitCLITrace(connection, buildCLITracePayload(command, traceCtx))
		warnIfTraceUploadSkipped(command, connection, eventsPosted || tracePosted)
	}()

	result := fn(traceCtx)
	exitCode = result.ExitCode
	attrs := cloneStringMap(result.Attributes)
	attrs["duration_ms"] = strconv.FormatInt(traceCtxElapsedMilliseconds(traceCtx), 10)
	traceCtx.Complete(result.TraceStatus, result.TraceMessage, attrs)
	return exitCode
}

func warnIfTraceUploadSkipped(command string, connection dashboardConnectionConfig, uploaded bool) {
	if uploaded || !shouldWarnForSkippedTraceUpload(connection) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "Trace upload skipped for %q: no active dashboard session/config for this repository. Run `baseline dashboard login --api <your-api-url>`.\n", command)
}

func shouldWarnForSkippedTraceUpload(connection dashboardConnectionConfig) bool {
	if strings.TrimSpace(connection.APIBaseURL) != "" {
		return true
	}
	if strings.TrimSpace(connection.APIKey) != "" || strings.TrimSpace(connection.AccessToken) != "" || strings.TrimSpace(connection.RefreshToken) != "" {
		return true
	}
	return connection.Enabled || connection.Prompted
}

func traceCtxElapsedMilliseconds(ctx *clitrace.Context) int64 {
	startedAt := ctx.StartedAt()
	if startedAt.IsZero() {
		return 0
	}
	return time.Since(startedAt).Milliseconds()
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func versionShort() string {
	return strings.TrimSpace(version.Short())
}
