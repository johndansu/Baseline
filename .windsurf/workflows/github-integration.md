---
description: GitHub integration workflow for Baseline
---

# GitHub Integration Workflow

This workflow defines the process for integrating Baseline with GitHub repositories and workflows.

## When to Use This Workflow

Use this workflow for:
- Setting up GitHub App integration
- Implementing PR-based workflows
- Creating GitHub Actions for Baseline
- Managing repository scanning and enforcement
- Handling webhook events and status checks

## Integration Architecture

### GitHub App Model
- GitHub App for repository access
- Fine-grained permissions (read-only by default)
- Webhook event processing
- Status check integration

### Permission Model
- **Read permissions**: Repository metadata, files, pull requests
- **Write permissions**: Pull requests (create/update), Status checks
- **No access**: Issues, projects, settings, deployments
- **Principle of least privilege**

## Core Integration Features

### Repository Scanning
- Trigger on push events
- Scan new commits for policy violations
- Analyze pull request changes
- Generate status check results

### Pull Request Workflow
- Create PRs for generated fixes
- Comment on policy violations
- Update PR status based on policy compliance
- Block merges on policy violations

### Status Check Integration
- Report Baseline check results
- Block merges on enforcement failures
- Provide detailed violation information
- Link to remediation PRs

## Implementation Process

### 1. GitHub App Setup
- Create GitHub App with appropriate permissions
- Configure webhook events
- Generate and secure app credentials
- Test app installation and authentication

### 2. Webhook Processing
- Process push events for repository scanning
- Handle pull request events for PR workflows
- Parse and validate webhook payloads
- Implement retry logic for failed deliveries

### 3. API Integration
- Repository content access
- Pull request creation and management
- Status check creation and updates
- Commit and file operations

### 4. Authentication & Security
- JWT token generation for app authentication
- Installation access tokens for repositories
- Secure credential storage
- Rate limiting and quota management

## Webhook Event Handling

### Push Events
```go
func handlePushEvent(event *github.PushEvent) {
    // Scan repository for policy violations
    // Update status checks
    // Generate remediation PRs if needed
}
```

### Pull Request Events
```go
func handlePullRequestEvent(event *github.PullRequestEvent) {
    // Analyze PR changes
    // Run policy checks on PR
    // Update PR status and comments
    // Block merge if violations found
}
```

### Check Suite Events
```go
func handleCheckSuiteEvent(event *github.CheckSuiteEvent) {
    // Run comprehensive Baseline checks
    // Create detailed check runs
    // Report results back to GitHub
}
```

## Status Check Implementation

### Check Run Creation
- Create check runs for each policy category
- Report detailed violation information
- Provide actionable remediation steps
- Link to generated fix PRs

### Status Updates
- Update commit status based on policy results
- Use appropriate status icons (success, failure, pending)
- Include summary and detailed information
- Handle concurrent check runs

### Enforcement Blocking
- Set status to "failure" for blocking violations
- Prevent merge through branch protection
- Provide clear violation explanations
- Link to remediation guidance

## Pull Request Management

### Remediation PR Creation
- Generate compliant configurations
- Create PRs with clear descriptions
- Link to original policy violations
- Include testing and validation

### PR Comments and Updates
- Comment on policy violations in PRs
- Update comments as violations are resolved
- Provide step-by-step remediation guidance
- Track PR lifecycle and status

### Merge Protection
- Integrate with GitHub branch protection
- Require Baseline status checks to pass
- Block merges on policy violations
- Allow manual override with justification

## GitHub Actions Integration

### Baseline Action
```yaml
name: Baseline Check
on: [push, pull_request]
jobs:
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: baseline-dev/baseline-action@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          policy-set: baseline:prod
```

### Action Features
- Repository scanning and policy checking
- SARIF output for security findings
- Status check reporting
- Artifact generation and upload

## Security Considerations

### Permission Management
- Minimum required permissions only
- Regular permission audits
- Secure credential storage
- Access logging and monitoring

### Data Handling
- No sensitive data in webhooks
- Sanitize repository content
- Secure API communication
- Data retention policies

### Rate Limiting
- Respect GitHub API rate limits
- Implement intelligent caching
- Batch operations where possible
- Handle rate limit gracefully

## Error Handling

### Webhook Failures
- Retry failed webhook deliveries
- Log webhook processing errors
- Handle malformed webhook payloads
- Implement circuit breaker pattern

### API Failures
- Handle GitHub API errors gracefully
- Implement exponential backoff
- Cache responses to reduce API calls
- Provide fallback behavior

### Authentication Errors
- Handle token expiration gracefully
- Implement token refresh logic
- Log authentication failures
- Provide clear error messages

## Testing Strategy

### Unit Testing
- Test webhook event handlers
- Mock GitHub API responses
- Test authentication flows
- Validate error handling

### Integration Testing
- Test with real GitHub repositories
- Validate end-to-end workflows
- Test rate limiting behavior
- Verify security controls

### Performance Testing
- Test with large repositories
- Validate webhook processing speed
- Test concurrent request handling
- Optimize API usage patterns

## Monitoring and Observability

### Metrics Collection
- Webhook processing success rates
- API response times and errors
- Policy violation detection rates
- PR creation and merge rates

### Logging
- Detailed webhook processing logs
- API request/response logging
- Error and exception tracking
- Security event logging

### Alerting
- Webhook processing failures
- High error rates in API calls
- Authentication failures
- Unusual usage patterns

## Configuration Management

### App Configuration
- GitHub App settings and permissions
- Webhook event subscriptions
- Rate limiting configuration
- Security settings

### Repository Configuration
- Baseline installation settings
- Policy set selection
- Branch protection rules
- Notification preferences

## Success Criteria

GitHub integration succeeds when:
- Webhooks are processed reliably
- Status checks are accurate and timely
- PR workflows are seamless
- Security controls are effective
- Teams trust the integration

## Troubleshooting Guide

### Common Issues
- Webhook delivery failures
- Authentication token problems
- Rate limiting issues
- Permission denied errors

### Debugging Steps
- Check webhook delivery logs
- Verify app permissions
- Validate API credentials
- Test with manual API calls

Remember: **GitHub integration is the primary interface for most users - it must be reliable, secure, and seamless.**
