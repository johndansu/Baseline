---
description: AI integration workflow for Baseline - restricted, deterministic AI usage
---

# AI Integration Workflow

This workflow defines the strict, controlled process for integrating AI capabilities into Baseline.

## When to Use This Workflow

Use this workflow for:
- Implementing AI-assisted code generation
- Adding AI-powered explanations or summaries
- Integrating with external AI services
- Developing AI prompt templates
- Validating AI output schemas

## Core AI Philosophy

**AI is a generator only, never a decision-maker.**

### AI MAY Do:
- Generate YAML configurations
- Scaffold test files
- Propose compliant infrastructure
- Explain policy violations
- Summarize scan results

### AI MAY NEVER Do:
- Decide policies
- Execute deployments
- Modify production directly
- Bypass validation
- Make autonomous decisions
- Have memory or authority

## Anti-Hallucination Rules (STRICT)

### Rule 1: No Free-Form Prompts
- All AI calls must use structured templates
- No conversational or open-ended prompts
- Fixed input schemas only
- Deterministic prompt construction

### Rule 2: Deterministic Inputs Only
AI receives only:
- Repository structure
- Policy constraints
- Explicit file targets
- Violation context

No vague context or assumptions allowed.

### Rule 3: Output Schema Enforcement
- AI output must conform to predefined schemas
- Invalid output is discarded immediately
- Schema validation before any use
- No partial or malformed outputs accepted

### Rule 4: No Hidden Reasoning
- AI must not invent assumptions
- Every change must reference a policy
- Every change must reference a detected violation
- No creative or interpretive outputs

### Rule 5: Diff-Only Acceptance
- Only diffs are accepted from AI
- No prose-only responses for changes
- All changes must be reviewable
- No direct file modifications

### Rule 6: Human Approval Mandatory
- No AI output reaches main without review
- All AI-generated changes require PR
- Human validation before merge
- No auto-acceptance or bypass

### Rule 7: Zero Memory Authority
- AI has no memory of past decisions
- State managed by system, not model
- No learning or adaptation
- Fresh context for each request

## AI Integration Architecture

### Generation Layer
- Restricted to template-based generation
- Schema validation on input and output
- Policy-linked prompts only
- No autonomous execution

### Validation Layer
- All AI output validated by Policy Engine
- Schema enforcement before acceptance
- Security scanning of generated content
- Deterministic verification of changes

### Approval Layer
- Human review required for all changes
- PR-based workflow for AI suggestions
- Clear attribution of AI-generated content
- Rollback capability for AI changes

## AI Usage by Command

### Advisory AI Commands
- `baseline check` - Explain violations only
- `baseline scan` - Summarize findings only
- `baseline report` - Summarize results only
- `baseline init` - Suggest configs only
- `baseline policy list/validate` - Explain policies only

### No AI Commands
- `baseline enforce` - Never uses AI
- All security rule evaluation
- All policy decisions
- All enforcement logic

## AI Generation Process

### 1. Trigger Detection
AI generation only triggers when:
- Policy Engine detects specific violation
- Template exists for violation type
- Human has requested generation
- Pre-conditions are met

### 2. Context Preparation
Prepare deterministic context:
- Repository structure analysis
- Policy violation details
- Template selection criteria
- Generation constraints

### 3. Template-Based Generation
- Use predefined prompt templates
- Fill template with deterministic context
- No free-form or creative prompts
- Structured input only

### 4. Output Validation
- Schema validation of AI response
- Policy compliance verification
- Security scanning of generated content
- Diff creation and review preparation

### 5. Human Review
- Present changes as pull request
- Clear AI attribution
- Policy violation mapping
- Rollback instructions

## Prompt Template Development

### Template Structure
```yaml
template_name: "ci_pipeline_generation"
description: "Generate GitHub Actions CI for missing pipeline"
required_context:
  - repository_structure
  - language_detected
  - framework_detected
  - policy_violations
output_schema: "github_actions_workflow"
ai_model: "gpt-4"
temperature: 0.1
max_tokens: 2000
```

### Template Rules
- Fixed structure and variables
- No conditional or dynamic prompts
- Explicit context requirements
- Defined output schemas

### Context Variables
Only allowed context variables:
- `repository_structure` - File tree analysis
- `policy_violations` - Specific rule failures
- `language_detected` - Programming language
- `framework_detected` - Framework identification
- `existing_configs` - Current configuration files

## Output Schemas

### CI Generation Schema
```yaml
github_actions_workflow:
  type: object
  properties:
    name: {type: string}
    on: {type: object}
    jobs: {type: object}
    required: [name, on, jobs]
```

### Test Generation Schema
```yaml
test_file:
  type: object
  properties:
    filename: {type: string}
    content: {type: string}
    test_type: {type: string}
    required: [filename, content, test_type]
```

### Config Generation Schema
```yaml
config_file:
  type: object
  properties:
    path: {type: string}
    content: {type: string}
    format: {type: string}
    required: [path, content, format]
```

## Security Controls

### Input Sanitization
- Remove sensitive data from context
- Sanitize repository structure
- Filter out secrets and credentials
- Validate all input parameters

### Output Scanning
- Security scan of generated code
- Dependency vulnerability check
- Secret detection in output
- Policy compliance validation

### Access Controls
- AI service access limited and scoped
- API keys stored securely
- Rate limiting and quota management
- Audit logging for all AI calls

## Testing Strategy

### Unit Testing
- Test prompt templates with mock data
- Validate output schemas
- Test error handling and edge cases
- Verify deterministic behavior

### Integration Testing
- Test AI integration with real repositories
- Validate end-to-end generation workflow
- Test policy violation mapping
- Verify human review process

### Security Testing
- Test with malicious inputs
- Verify no prompt injection
- Test output sanitization
- Validate access controls

## Monitoring and Observability

### AI Usage Metrics
- Number of AI calls per command
- Success/failure rates
- Output validation rates
- Human approval rates

### Quality Metrics
- AI output accuracy
- Policy compliance rates
- User satisfaction scores
- Incident reports related to AI

### Security Monitoring
- AI service access logs
- Anomaly detection in usage
- Prompt injection attempts
- Data leakage prevention

## Error Handling

### AI Service Errors
- Graceful degradation when AI unavailable
- Clear error messages to users
- Retry logic with exponential backoff
- Fallback to non-AI behavior

### Validation Errors
- Reject invalid AI output immediately
- Log validation failures for analysis
- Provide feedback to improve templates
- Never accept malformed output

### Context Errors
- Validate context before AI calls
- Handle incomplete or missing data
- Provide clear error messages
- Fallback to manual intervention

## Success Criteria

AI integration succeeds when:
- Zero hallucinated changes reach production
- All AI output is tied to policy violations
- Human approval workflow is reliable
- Teams trust AI-assisted generation
- Security controls are effective

## Anti-Patterns to Avoid

### Never Do
- Use AI for policy decisions
- Allow autonomous AI actions
- Store AI conversation history
- Use AI for security rule evaluation
- Allow AI to bypass validation

### Always Do
- Use structured templates only
- Validate all AI output
- Require human approval
- Maintain deterministic behavior
- Log all AI interactions

Remember: **AI in Baseline is a tool, not an authority. It assists with speed, never with decisions.**
