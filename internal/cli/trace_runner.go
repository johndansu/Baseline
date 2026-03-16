package cli

import (
	"fmt"
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
			emitCLITraceEvents(connection, command, traceCtx.Metadata(), traceCtx.Events())
			emitCLITrace(connection, buildCLITracePayload(command, traceCtx))
			panic(recovered)
		}
		if !traceCtx.Completed() {
			traceCtx.Complete("unknown", "command completed without explicit trace result", map[string]string{
				"duration_ms": strconv.FormatInt(traceCtxElapsedMilliseconds(traceCtx), 10),
			})
		}
		emitCLITraceEvents(connection, command, traceCtx.Metadata(), traceCtx.Events())
		emitCLITrace(connection, buildCLITracePayload(command, traceCtx))
	}()

	result := fn(traceCtx)
	exitCode = result.ExitCode
	attrs := cloneStringMap(result.Attributes)
	attrs["duration_ms"] = strconv.FormatInt(traceCtxElapsedMilliseconds(traceCtx), 10)
	traceCtx.Complete(result.TraceStatus, result.TraceMessage, attrs)
	return exitCode
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
