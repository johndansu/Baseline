---
description: Policy engine development workflow for Baseline
---

# Policy Engine Development Workflow

This workflow defines the process for developing and maintaining Baseline's deterministic policy engine.

## When to Use This Workflow

Use this workflow for:
- Creating new policy rules
- Modifying existing policy logic
- Adding new policy evaluation capabilities
- Updating policy DSL specifications
- Testing policy enforcement

## Core Principles

### Deterministic Enforcement
- All policies must have binary PASS/FAIL outcomes
- No probabilistic or AI-driven decision making
- Every failure must trace to specific rule
- No overrides or bypasses in MVP

### Non-Negotiable Rules
- Security rules never use AI
- All policies are code, not prompts
- Human approval required for all changes
- Zero tolerance for ambiguity

## Policy Development Steps

### 1. Policy Definition
Before implementing:
- Define clear policy objective
- Specify exact violation conditions
- Determine severity level (block/warn)
- Identify target scope (repository, branch, deployment)

### 2. Policy Structure Design
Follow Baseline Policy Language (PRPL) structure:
```
policy "policy_name" {
  applies_to = "target_scope"
  severity   = "block|warn"
  
  require {
    // conditions that must be true
  }
  
  forbid {
    // conditions that must be false
  }
  
  message = "Human-readable explanation"
}
```

### 3. Implementation Rules
- Use only supported operators: ==, !=, exists, count >= n, contains
- No loops, recursion, or dynamic execution
- All rules evaluable from repo or pipeline state
- No external network calls in policy evaluation

### 4. Security Validation
- Security policies must be deterministic
- No AI involvement in security rule decisions
- Clear failure semantics for every policy
- Migration guidance for new policies

## Policy Categories

### Category A: Source Control & Review
- A1: Protected main branch
- A2: Mandatory pull requests
- A3: Status checks required

### Category B: CI/CD Fundamentals
- B1: CI pipeline required
- B2: CI must run on PR
- B3: Build must be reproducible

### Category C: Testing
- C1: Test suite exists
- C2: Tests run in CI
- C3: Prod branch requires tests

### Category D: Secrets & Security
- D1: No plaintext secrets
- D2: Secrets via secure store
- D3: No secrets in CI logs

### Category E: Deployment Safety
- E1: Rollback strategy required
- E2: Environment separation
- E3: Manual prod approval

### Category F: Observability
- F1: Health check defined
- F2: Failure visibility

## Policy Testing Strategy

### Unit Testing
- Test each policy rule individually
- Verify PASS/FAIL outcomes
- Test edge cases and boundary conditions
- Ensure deterministic behavior

### Integration Testing
- Test policy evaluation on real repositories
- Verify interaction between multiple policies
- Test enforcement blocking behavior
- Validate error messages and reporting

### Security Testing
- Verify no AI in security policies
- Test policy bypass attempts
- Validate deterministic execution
- Test with malicious inputs

## Policy Evolution Process

### Rule Updates
1. **Continuous Review**
   - Security rules evaluated regularly
   - CVE databases monitored
   - Industry standards tracked

2. **Versioned Releases**
   - Ruleset changes versioned
   - Backward-compatible enforcement
   - Transparent changelog

3. **Migration Path**
   - New rules introduced as `warn` first
   - Clear compliance documentation
   - No silent rule changes

### Policy Sources
- CVE databases
- OWASP Top 10
- Cloud provider advisories
- Industry incident postmortems

## Implementation Guidelines

### Code Structure
- Policies as declarative configurations
- Evaluation engine in Go
- Clear separation of policy and execution
- Schema validation for policy definitions

### Error Handling
- Clear, actionable error messages
- Policy ID references for all failures
- No silent failures or partial enforcement
- Consistent exit codes and status reporting

### Performance
- Fast evaluation for CI/CD integration
- Minimal memory footprint
- Efficient repository scanning
- Caching where appropriate

## Quality Assurance

### Review Process
- Senior engineer review for all policies
- Security team approval for security rules
- Documentation review for clarity
- Testing validation for coverage

### Validation Criteria
- Policy enforces intended rule
- No false positives or negatives
- Clear violation explanations
- Deterministic behavior confirmed

## Documentation Requirements

### Policy Documentation
- Clear purpose statement
- Exact violation conditions
- Compliance instructions
- Example violations and fixes

### Change Documentation
- Reason for policy addition/change
- Impact assessment
- Migration guidance
- Version history

## Success Metrics

### Policy Effectiveness
- Violation detection accuracy
- False positive/negative rates
- Team compliance rates
- Production incident reduction

### Developer Experience
- Clear violation explanations
- Easy compliance paths
- Minimal false alarms
- Trust in enforcement

## Anti-Patterns to Avoid

### Never Do
- Use AI for policy decisions
- Create ambiguous or interpretable rules
- Allow policy overrides in MVP
- Implement probabilistic enforcement
- Hide policy logic or reasoning

### Always Do
- Make policies explicit and deterministic
- Provide clear violation explanations
- Test policies thoroughly
- Document policy rationale
- Maintain backward compatibility

## Success Criteria

Policy development is successful when:
- All policies are deterministic and testable
- Security rules have zero AI involvement
- Every violation maps to specific policy
- Teams understand and trust enforcement
- Production incidents decrease

Remember: **Policies are the foundation of Baseline's trust model - they must be perfect, deterministic, and unquestionable.**
