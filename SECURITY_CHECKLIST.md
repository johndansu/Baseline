# Baseline Security Checklist

This checklist helps keep the project secure at all stages.

## Configuration / Secrets
- [ ] Use `.env` files for secrets
- [ ] Never commit secrets to repo
- [ ] Disable debug mode in production (`DEBUG=False`)

## Transport / Network
- [ ] Enforce HTTPS when live
- [ ] Use HSTS header
- [ ] Restrict CORS to trusted domains

## Authentication / Access
- [ ] Strong password policy
- [ ] Multi-factor authentication if possible
- [ ] Limit login attempts / rate limiting
- [ ] Proper session management

## Data / Input
- [ ] Validate all inputs
- [ ] Sanitize outputs
- [ ] Protect against SQL injection, XSS, CSRF

## Dependencies / Updates
- [ ] Keep dependencies up-to-date
- [ ] Monitor with Dependabot, Snyk, or GitHub security alerts

## Logging / Monitoring
- [ ] Log security events
- [ ] Monitor failed logins and errors
- [ ] Set up alerts for unusual activity

## Backups
- [ ] Regular backups
- [ ] Store securely (encrypted)
