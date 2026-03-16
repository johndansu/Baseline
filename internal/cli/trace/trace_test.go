package trace

import "testing"

func TestContextRecordsLifecycleEvents(t *testing.T) {
	ctx := Start("check")
	ctx.SetMetadata("repository", "Baseline")
	span := ctx.HelperEnter("cli", "requireGitRepo", "checking git repository", nil)
	ctx.HelperExit(span, "cli", "requireGitRepo", "ok", "git repository check passed", nil)
	ctx.Branch("cli", "HandleCheck", "clean_exit", nil)
	ctx.Complete("ok", "repository check completed", map[string]string{"violation_count": "0"})

	events := ctx.Events()
	if len(events) < 4 {
		t.Fatalf("expected at least 4 events, got %d", len(events))
	}
	if events[0].Type != "cli_command_started" {
		t.Fatalf("expected first event to be cli_command_started, got %s", events[0].Type)
	}
	if events[len(events)-1].Type != "cli_command_completed" {
		t.Fatalf("expected last event to be cli_command_completed, got %s", events[len(events)-1].Type)
	}
	if ctx.TraceID() == "" {
		t.Fatal("expected trace ID to be set")
	}
	if ctx.Metadata()["repository"] != "Baseline" {
		t.Fatalf("expected repository metadata to be preserved, got %#v", ctx.Metadata())
	}
}
