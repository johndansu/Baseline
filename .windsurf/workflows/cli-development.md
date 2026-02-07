---
description: CLI development workflow for Baseline
---

# CLI Development Workflow

This workflow defines the process for developing Baseline's deterministic, trustworthy CLI interface.

## When to Use This Workflow

Use this workflow for:
- Implementing new CLI commands
- Modifying existing command behavior
- Adding command-line flags or options
- Updating output formats
- Integrating with external systems

## CLI Philosophy

The Baseline CLI is **not a chatbot**. It is:
- Predictable and deterministic
- Scriptable and non-interactive by default
- Safe to run in CI/CD environments
- Fails loudly with clear explanations

## Core Commands

### Primary Commands
- `baseline check` - Run all applicable rules against repository
- `baseline enforce` - Enforce rules and block on violations
- `baseline scan` - Deep static scan of repository state
- `baseline report` - Output results in machine-readable formats
- `baseline init` - Initialize Baseline configuration

### Policy Commands
- `baseline policy list` - List all active policies
- `baseline policy validate` - Validate policy definitions
- `baseline update-rules` - Update non-AI security rules

### Utility Commands
- `baseline version` - Output version information

## Command Development Process

### 1. Command Definition
Before implementing:
- Define clear command purpose
- Specify exact behavior and inputs/outputs
- Determine AI usage restrictions (advisory only vs no AI)
- Plan exit codes and error handling

### 2. Interface Design
Follow CLI contract:
- Short, memorable command names
- Non-interactive by default
- Consistent flag patterns
- Machine-readable output options

### 3. Implementation Rules
- Deterministic behavior guaranteed
- No prompts in CI/CD environments
- All failures explain what, why, and how to fix
- No hidden behavior or silent fixes

## Command Behavior Specifications

### baseline check
**Purpose**: Analyze repository and pipeline state
**Behavior**: Read-only, no filesystem mutation
**AI Role**: Advisory only for explaining violations
**Exit Codes**: 0 (no violations), 10 (warnings), 20 (blocking violations)

### baseline enforce
**Purpose**: Act as gate in CI/CD
**Behavior**: Non-interactive, fast-fail
**AI Role**: No AI allowed
**Exit Codes**: 0 (passed), 50 (failed - block)

### baseline scan
**Purpose**: Deep static scan of repository
**Behavior**: Comprehensive analysis including security, secrets, CI
**AI Role**: Advisory only for summarizing findings
**Exit Codes**: 0 (success), 20 (blocking issues found)

### baseline report
**Purpose**: Output scan results in machine-readable formats
**Behavior**: Transform data to requested format (json, sarif, text)
**AI Role**: Advisory only for summarization
**Exit Codes**: 0 (report generated), 40 (report failed)

### baseline init
**Purpose**: Initialize Baseline configuration
**Behavior**: Create config files, setup basic structure
**AI Role**: Advisory only for config suggestions
**Exit Codes**: 0 (initialized), 30 (initialization failed)

## Output Format Rules

### Default Output
- Plain text format
- Clear, structured information
- Policy IDs for every violation
- Actionable next steps

### Machine-Readable Output
- `--json` flag for strict JSON schema
- `--sarif` flag for security analysis results
- Consistent field names and types
- No emojis or decorative elements

### Error Messages
Every message must include:
- Policy ID that triggered the error
- Severity level (block/warn)
- Specific action required
- Clear explanation of why

## Global Flags

### Standard Flags
- `--json` - Output in JSON format
- `--strict` - Enable strict enforcement mode
- `--policy <name>` - Use specific policy set
- `--offline` - Run without network access
- `--debug` - Show internal decision steps

### Flag Behavior
- Consistent across all commands
- Clear help text and examples
- No conflicting flag combinations
- Backward compatibility maintained

## AI Usage Rules

### Advisory Only (Allowed Commands)
- `baseline check` - AI may explain violations
- `baseline scan` - AI may summarize findings
- `baseline report` - AI may summarize results
- `baseline init` - AI may suggest configs
- `baseline policy list/validate` - AI may explain policies

### No AI (Forbidden Commands)
- `baseline enforce` - Never uses AI
- Security rule evaluation - Never uses AI
- Policy decisions - Never uses AI
- Enforcement logic - Never uses AI

### AI Output Requirements
- Clearly labeled as advisory
- Schema-validated and human-reviewed
- No persistent memory or authority
- Tied to specific policy violations

## Testing Strategy

### Unit Testing
- Test each command independently
- Verify exit codes and output formats
- Test flag combinations and edge cases
- Ensure deterministic behavior

### Integration Testing
- Test commands on real repositories
- Verify interaction with policy engine
- Test GitHub integration workflows
- Validate CI/CD compatibility

### Security Testing
- Test with malicious inputs
- Verify no credential leakage
- Test debug output safety
- Validate sandbox isolation

## Performance Requirements

### Speed
- Fast startup for CI/CD use
- Minimal memory footprint
- Efficient repository scanning
- Responsive command execution

### Scalability
- Handle large repositories
- Process multiple policy rules
- Generate reports efficiently
- Maintain responsiveness

## Error Handling

### Failure Experience
When CLI fails:
- Explains **what** failed
- References **which policy** failed
- Suggests **how to fix**
- Never suggests bypassing rules

### Error Categories
- Usage errors (invalid flags, missing arguments)
- Policy violations (rule failures)
- System errors (network, filesystem)
- Configuration errors (invalid policies)

## Backward Compatibility

### Version Management
- CLI flags are versioned
- Breaking changes require major version bump
- Deprecated behavior emits warnings
- Migration guides provided

### Compatibility Testing
- Test with previous command formats
- Verify flag behavior consistency
- Validate output format stability
- Ensure script compatibility

## Documentation Requirements

### Command Documentation
- Clear purpose and usage examples
- Complete flag reference
- Exit code explanations
- Real-world usage scenarios

### Help System
- Comprehensive help text
- Usage examples for each command
- Troubleshooting guide
- FAQ for common issues

## Success Criteria

CLI development succeeds when:
- Commands are predictable and deterministic
- Output is clear and actionable
- Teams trust it in production CI/CD
- Integration is seamless and reliable
- Documentation is comprehensive

Remember: **If a developer cannot trust the CLI output at 2am during an incident, the CLI has failed.**
