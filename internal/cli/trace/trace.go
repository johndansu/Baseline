package trace

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Timestamp    time.Time
	TraceID      string
	SpanID       string
	ParentSpanID string
	Type         string
	Component    string
	Function     string
	Branch       string
	Status       string
	Message      string
	Attributes   map[string]string
}

type Context struct {
	mu        sync.Mutex
	traceID   string
	rootSpan  string
	command   string
	startedAt time.Time
	sequence  uint64
	metadata  map[string]string
	events    []Event
	completed bool
}

func Start(command string) *Context {
	ctx := &Context{
		traceID:   newID("trc"),
		rootSpan:  newID("spn"),
		command:   strings.TrimSpace(command),
		startedAt: time.Now().UTC(),
		metadata:  map[string]string{},
		events:    make([]Event, 0, 8),
	}
	ctx.recordLocked(Event{
		Timestamp:    ctx.startedAt,
		TraceID:      ctx.traceID,
		SpanID:       ctx.rootSpan,
		Type:         "cli_command_started",
		Component:    "cli",
		Function:     ctx.command,
		Status:       "started",
		Message:      "command invoked",
		Attributes:   map[string]string{},
		ParentSpanID: "",
	})
	return ctx
}

func (c *Context) TraceID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.traceID
}

func (c *Context) Command() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.command
}

func (c *Context) StartedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.startedAt
}

func (c *Context) SetMetadata(key, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if value == "" {
		delete(c.metadata, key)
		return
	}
	c.metadata[key] = value
}

func (c *Context) Metadata() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	metadata := make(map[string]string, len(c.metadata))
	for key, value := range c.metadata {
		metadata[key] = value
	}
	return metadata
}

func (c *Context) HelperEnter(component, function, message string, attrs map[string]string) string {
	return c.record("cli_helper_entered", component, function, "", "started", message, attrs)
}

func (c *Context) HelperExit(parentSpanID, component, function, status, message string, attrs map[string]string) string {
	return c.recordWithParent("cli_helper_exited", parentSpanID, component, function, "", status, message, attrs)
}

func (c *Context) Branch(component, function, branch string, attrs map[string]string) string {
	return c.record("cli_branch_taken", component, function, branch, "ok", "branch selected", attrs)
}

func (c *Context) Error(component, function string, err error, attrs map[string]string) string {
	message := ""
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	return c.record("cli_error", component, function, "", "error", message, attrs)
}

func (c *Context) Complete(status, message string, attrs map[string]string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.completed {
		return c.rootSpan
	}
	c.completed = true
	return c.recordLocked(Event{
		Timestamp:    time.Now().UTC(),
		TraceID:      c.traceID,
		SpanID:       c.nextSpanIDLocked(),
		ParentSpanID: c.rootSpan,
		Type:         "cli_command_completed",
		Component:    "cli",
		Function:     c.command,
		Status:       strings.TrimSpace(status),
		Message:      strings.TrimSpace(message),
		Attributes:   cloneMap(attrs),
	})
}

func (c *Context) Completed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.completed
}

func (c *Context) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := make([]Event, 0, len(c.events))
	for _, event := range c.events {
		copied := event
		copied.Attributes = cloneMap(event.Attributes)
		events = append(events, copied)
	}
	return events
}

func (c *Context) record(eventType, component, function, branch, status, message string, attrs map[string]string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recordLocked(Event{
		Timestamp:    time.Now().UTC(),
		TraceID:      c.traceID,
		SpanID:       c.nextSpanIDLocked(),
		ParentSpanID: c.rootSpan,
		Type:         strings.TrimSpace(eventType),
		Component:    strings.TrimSpace(component),
		Function:     strings.TrimSpace(function),
		Branch:       strings.TrimSpace(branch),
		Status:       strings.TrimSpace(status),
		Message:      strings.TrimSpace(message),
		Attributes:   cloneMap(attrs),
	})
}

func (c *Context) recordWithParent(eventType, parentSpanID, component, function, branch, status, message string, attrs map[string]string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	parent := strings.TrimSpace(parentSpanID)
	if parent == "" {
		parent = c.rootSpan
	}
	return c.recordLocked(Event{
		Timestamp:    time.Now().UTC(),
		TraceID:      c.traceID,
		SpanID:       c.nextSpanIDLocked(),
		ParentSpanID: parent,
		Type:         strings.TrimSpace(eventType),
		Component:    strings.TrimSpace(component),
		Function:     strings.TrimSpace(function),
		Branch:       strings.TrimSpace(branch),
		Status:       strings.TrimSpace(status),
		Message:      strings.TrimSpace(message),
		Attributes:   cloneMap(attrs),
	})
}

func (c *Context) recordLocked(event Event) string {
	if event.TraceID == "" {
		event.TraceID = c.traceID
	}
	if event.SpanID == "" {
		event.SpanID = c.nextSpanIDLocked()
	}
	c.events = append(c.events, event)
	return event.SpanID
}

func (c *Context) nextSpanIDLocked() string {
	c.sequence++
	return "spn_" + strings.TrimPrefix(newID(""), "_") + "_" + hex.EncodeToString([]byte{byte(c.sequence % 256)})
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return cloned
}

func newID(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		now := time.Now().UnixNano()
		return strings.Trim(prefix+"_"+hex.EncodeToString([]byte{
			byte(now >> 56), byte(now >> 48), byte(now >> 40), byte(now >> 32),
			byte(now >> 24), byte(now >> 16), byte(now >> 8), byte(now),
		}), "_")
	}
	id := hex.EncodeToString(buf)
	if strings.TrimSpace(prefix) == "" {
		return "_" + id
	}
	return prefix + "_" + id
}
