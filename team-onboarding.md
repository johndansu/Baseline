# Baseline Team Onboarding Guide

## Overview
Baseline is a Production Policy & Enforcement Engine that blocks unsafe code from reaching production.

## Quick Start

### 1. Installation
```cmd
# Download Baseline
curl -L -o baseline.exe https://github.com/johndansu/Baseline/releases/download/v1.0.0/baseline-windows-amd64.exe

# Add to PATH (permanent)
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "User") + ";C:\baseline-production", "User")

# Verify installation
baseline version
```

### 2. Basic Usage
```cmd
# Check your repository for policy violations
baseline check

# Deep scan of repository
baseline scan

# Enforce policies (blocks on violations)
baseline enforce

# Get help
baseline --help
```

## Policy Rules

Baseline enforces 12 production safety rules:

### Security Rules
- **G1**: Protected main branch
- **G2**: No secrets in code
- **G3**: No hardcoded credentials

### Infrastructure Rules  
- **B1**: CI pipeline required
- **H1**: Deployment configuration required
- **I1**: Infrastructure as code required

### Quality Rules
- **C1**: Test suite required
- **F1**: Documentation required
- **E1**: Dependency management required

### Operations Rules
- **R1**: Rollback plan required
- **J1**: Environment configuration required
- **K1**: Backup procedures required
- **L1**: Logging and monitoring required

## Common Workflows

### Daily Development
```cmd
# Before committing
baseline check

# If violations found, fix them:
baseline explain [policy-id]  # Get explanation
baseline generate [policy-id]  # Generate fix
```

### Before Production Deploy
```cmd
# Full production scan
baseline scan --format json

# Enforce all policies
baseline enforce

# Verify no blocking violations
echo %ERRORLEVEL%
```

### CI/CD Integration
- Baseline automatically runs in GitHub Actions
- PRs are blocked if violations exist
- Main branch is protected from direct pushes

## Troubleshooting

### Common Issues
1. **"Not a git repository"**: Run from within git repository
2. **"Permission denied"**: Check file permissions
3. **"Baseline not found"**: Add to PATH or use full path

### Getting Help
```cmd
# Get policy explanation
baseline explain G1

# Get remediation advice
baseline generate B1

# Full help
baseline --help
```

## Best Practices

1. **Run checks daily**: `baseline check` before commits
2. **Fix violations immediately**: Don't let them accumulate
3. **Use CI/CD integration**: Automated enforcement
4. **Review scan results**: Understand what's being flagged
5. **Keep Baseline updated**: Use latest version

## Support

- Documentation: https://github.com/johndansu/Baseline/blob/main/README.md
- Issues: https://github.com/johndansu/Baseline/issues
- Security: dansu.jw@gmail.com

---
*Baseline enforces software fundamentals before code reaches production.*
