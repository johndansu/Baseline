# Baseline

A Production Policy & Enforcement Engine that enforces software fundamentals before code reaches production.

## Status

✅ **Production Ready - MVP Complete**
- All 6 CLI commands implemented and tested
- Full security compliance with 12 deterministic rules
- Comprehensive test coverage (unit + integration)
- AI-assisted scaffolding with human review workflow
- Automated CI/CD pipeline with security scanning
- GitHub integration with PR-based workflow
- Version management with build-time injection

## Installation

### From Source
```bash
go build -o baseline.exe ./cmd/baseline
```

### From Release
Download the latest release from [GitHub Releases](https://github.com/baseline/baseline/releases).

## Usage

### Commands

- `baseline version` - Show version information
- `baseline check` - Run repository policy checks
- `baseline enforce` - Enforce policies and block on violations  
- `baseline scan` - Deep scan of repository state
- `baseline init` - Initialize Baseline configuration
- `baseline report` - Output scan results in machine-readable formats
- `baseline generate` - Generate missing infrastructure using AI
- `baseline pr` - Create pull requests with AI-generated scaffolds
- `baseline explain` - Get explanation for policy violations

### Flags

- `--help, -h` - Show help message

### Exit Codes

- `0` - Success (no violations)
- `20` - Blocking violations found
- `50` - System error

## Policy Rules

Baseline enforces the following production safety rules:

### Security (D1, G1)
- No plaintext secrets in code
- No unsafe functions (exec, eval, system)
- SQL injection protection

### CI/CD (B1)
- CI pipeline required
- Tests must run in CI
- Automated builds

### Testing (C1)
- Unit tests required
- Integration tests recommended
- Coverage reporting

### Documentation (F1)
- README.md required
- License required
- Proper documentation

### Deployment (H1)
- Deployment configuration required
- Container security
- Non-root execution

### Infrastructure (I1)
- Infrastructure as code
- Security groups
- Version control

### Environment (J1)
- Environment variables documented
- No hardcoded secrets
- Example configurations

### Backup & Recovery (K1, R1)
- Backup procedures documented
- Rollback plans defined
- Recovery steps

### Monitoring (L1)
- Logging configuration
- Monitoring setup
- Security event tracking

## Security

Baseline follows security best practices:
- No secrets committed to repository
- Input validation and sanitization
- Minimal dependencies
- Regular security audits

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## AI Integration

Baseline uses AI **only for scaffolding**:
- Generates CI configuration templates
- Creates test file skeletons
- Produces documentation drafts
- **Never** makes enforcement decisions
- **Never** auto-applies fixes

All AI-generated content requires **human review** before use.

## CI/CD Pipeline

Baseline includes a comprehensive GitHub Actions workflow that:

- **Multi-platform builds** (Ubuntu, Windows, macOS)
- **Automated testing** with race condition detection
- **Security scanning** using Gosec static analysis
- **Code coverage** reporting via Codecov
- **Dependency updates** via Dependabot
- **Branch protection** requiring reviews and status checks

### Workflow Triggers
- Push to main/master branches
- Pull requests
- Release publications

### Code Style
- Follow Go idiomatic patterns
- Use structured logging with log/slog
- Handle errors explicitly
- No TODO comments in production code

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure all policies pass: `baseline check`
4. Add tests for new features
5. Submit a pull request

## License
This project is licensed under the MIT License.