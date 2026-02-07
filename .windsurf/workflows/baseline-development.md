---
description: Baseline development workflow following incremental, production-safe methodology
---

# Baseline Development Workflow

This workflow defines the step-by-step process for building Baseline following the senior Go engineer methodology.

## When to Use This Workflow

Use this workflow when:
- Implementing any new feature in Baseline
- Adding new policy rules or enforcement logic
- Modifying the CLI interface
- Integrating with external systems (GitHub, AI services)

## Prerequisites

- Read and understand the project spine memories
- Review the agent.md development methodology
- Ensure security checklist compliance
- Have clear understanding of current system state

## Development Steps

### 1. Context Grounding
Before writing any code:
- State the step intent (1-2 lines)
- List current assumptions (≤3 bullets)
- Identify any real risks
- Confirm alignment with project spine decisions

### 2. Incremental Implementation
- Implement **one file, package, or concern** only
- Keep changes small and testable
- Prefer under-building to over-building
- Use idiomatic Go with explicit error handling

### 3. Anti-Abstraction Check
Before creating new packages:
- Verify there is clear pressure (repeated logic, multiple consumers)
- Avoid `config`, `utils`, `helpers`, `common` packages without demonstrated need
- Start with inline, explicit logic
- Refactor only when forced by pressure, not anticipation

### 4. Context Safety Validation
Monitor for context breakdown signs:
- Suggesting abstractions "for cleanliness"
- Contradicting earlier decisions
- Responses becoming larger than requested
- Using vague language ("typically", "generally", "you could")

If any signs appear, stop and re-ground.

### 5. Step Completion
- End every step with a proposed next safe step
- Do not implement the next step yet
- Ensure current step is independently correct
- Verify compliance with security checklist

## Re-Grounding Procedure

If context feels shaky or uncertain:

1. **Pause implementation immediately**
2. **Summarize current state** (≤10 lines):
   - What exists
   - What is stable
   - What decisions are locked
3. **Restate project goal**
4. **List unresolved questions or risks**
5. **Propose single safest next step**
6. **Do not write code yet**

## Deliberate Research Mode

If uncertainty remains after re-grounding:

1. **Pause all implementation**
2. **Perform research**:
   - Re-evaluate assumptions
   - Check Go best practices
   - Validate architectural direction
3. **Resume only when next step is obvious and safe**

## Response Format

Every development response must follow exactly:

1. **Step Intent** (1-2 lines)
2. **Key Decisions** (≤3 bullets)
3. **Code** (if applicable)
4. **Next Safe Step**

No extra sections, no fluff, no motivational tone.

## Architecture Discipline

- Maintain flat structure initially
- No frameworks unless unavoidable
- No abstractions without demonstrated pressure
- Refactor deliberately, not preemptively

## Security Compliance

- Follow SECURITY_CHECKLIST.md for all changes
- Never commit secrets or sensitive data
- Use environment variables for configuration
- Validate all inputs and sanitize outputs

## Success Criteria

A step is complete when:
- Code is boring, obvious, and correct
- No clever or overly complex solutions
- Aligns with project spine decisions
- Passes security checklist validation
- Can be safely built upon

Remember: **Baseline code should be boring, obvious, and correct. If something feels clever, it is likely wrong.**
