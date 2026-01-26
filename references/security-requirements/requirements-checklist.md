# Security Requirements Checklist

Use this checklist when designing new features or reviewing existing functionality. Not all requirements apply to every project - select those relevant to your context.

## Authentication

### Password-Based Authentication
- [ ] Minimum password length of 12+ characters
- [ ] No maximum password length (up to 128 chars)
- [ ] Passwords hashed with Argon2id, bcrypt, or scrypt
- [ ] Unique salt per password
- [ ] Breached password checking (Have I Been Pwned API)
- [ ] Account lockout after failed attempts (with exponential backoff)
- [ ] Secure password reset flow with time-limited tokens
- [ ] No password hints or security questions

### Multi-Factor Authentication
- [ ] MFA available for all users
- [ ] MFA required for privileged operations
- [ ] Support for TOTP authenticator apps
- [ ] Support for WebAuthn/FIDO2 (hardware keys)
- [ ] Backup codes for account recovery
- [ ] MFA status visible to user

### Session Management
- [ ] Cryptographically random session IDs (128+ bits entropy)
- [ ] Session tokens regenerated on login
- [ ] Session tokens regenerated on privilege escalation
- [ ] Secure cookie attributes: HttpOnly, Secure, SameSite
- [ ] Session timeout (idle and absolute)
- [ ] Session invalidation on logout
- [ ] Concurrent session controls (optional)

### OAuth/OIDC (if applicable)
- [ ] State parameter used to prevent CSRF
- [ ] PKCE used for public clients
- [ ] Tokens validated (signature, issuer, audience, expiry)
- [ ] Refresh token rotation
- [ ] Minimal scopes requested

---

## Authorization

### Access Control
- [ ] Authorization checks on every request
- [ ] Server-side enforcement (not just client-side)
- [ ] Default deny policy
- [ ] Role-based access control (RBAC) implemented
- [ ] Principle of least privilege
- [ ] Object-level authorization (prevent IDOR)
- [ ] Function-level authorization (admin functions protected)

### API Security
- [ ] Authentication required for protected endpoints
- [ ] Rate limiting implemented
- [ ] API versioning strategy
- [ ] Input size limits
- [ ] Request timeout limits
- [ ] API keys rotatable (if used)

---

## Data Protection

### Encryption at Rest
- [ ] Sensitive data encrypted in database
- [ ] Encryption keys stored securely (not in code)
- [ ] Key rotation capability
- [ ] Backups encrypted
- [ ] Temporary files encrypted or avoided

### Encryption in Transit
- [ ] TLS 1.2+ required for all connections
- [ ] Valid certificates from trusted CA
- [ ] HSTS header configured
- [ ] Certificate pinning for mobile apps (optional)
- [ ] No HTTP fallback

### Data Classification
- [ ] Data classified by sensitivity
- [ ] PII handling procedures defined
- [ ] Data retention policy defined
- [ ] Data deletion capability (right to be forgotten)
- [ ] Data masking in non-production environments

### Secrets Management
- [ ] No secrets in source code
- [ ] No secrets in logs
- [ ] Secrets stored in vault/secrets manager
- [ ] Secrets rotatable without deployment
- [ ] Secrets scoped to minimum required access

---

## Input Validation

### General Validation
- [ ] All input validated on server-side
- [ ] Allowlist validation preferred over blocklist
- [ ] Input length limits enforced
- [ ] Input type validation (numbers, dates, etc.)
- [ ] Canonicalization before validation

### Injection Prevention
- [ ] Parameterized queries for SQL
- [ ] ORM/safe APIs used
- [ ] Output encoding for HTML context
- [ ] Command injection prevented (avoid shell)
- [ ] Path traversal prevented
- [ ] LDAP injection prevented (if applicable)
- [ ] XML/XPath injection prevented (if applicable)

### File Uploads (if applicable)
- [ ] File type validated (magic bytes, not just extension)
- [ ] File size limits enforced
- [ ] Filename sanitized
- [ ] Files stored outside web root
- [ ] Antivirus scanning (for high-risk environments)
- [ ] Content-Type header set correctly for downloads

---

## Output Encoding

### Cross-Site Scripting (XSS) Prevention
- [ ] HTML output encoded
- [ ] JavaScript output encoded
- [ ] URL output encoded
- [ ] CSS output encoded
- [ ] Content Security Policy header configured
- [ ] X-Content-Type-Options: nosniff header set
- [ ] Framework's built-in encoding used

### Content Security
- [ ] CSP header restricts script sources
- [ ] No inline scripts (if possible)
- [ ] No eval() or similar dynamic code execution
- [ ] Subresource Integrity for external scripts

---

## Error Handling

### Secure Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side only
- [ ] No stack traces in production responses
- [ ] No sensitive data in error messages
- [ ] Consistent error responses (prevent enumeration)
- [ ] Custom error pages configured

### Fail Secure
- [ ] Failures default to deny access
- [ ] Exception handling doesn't bypass security
- [ ] Partial failures handled gracefully

---

## Logging and Monitoring

### Security Logging
- [ ] Authentication events logged (success and failure)
- [ ] Authorization failures logged
- [ ] Input validation failures logged
- [ ] Administrative actions logged
- [ ] High-value transactions logged
- [ ] Security-relevant errors logged

### Log Protection
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Log integrity protected
- [ ] Log access restricted
- [ ] Log retention policy defined
- [ ] Logs monitored for anomalies

### Alerting
- [ ] Alerts on repeated authentication failures
- [ ] Alerts on unusual access patterns
- [ ] Alerts on administrative actions
- [ ] Incident response plan exists

---

## Cryptography

### General Cryptographic Requirements
- [ ] Standard algorithms used (no custom crypto)
- [ ] Sufficient key lengths (AES-256, RSA-2048+, ECDSA-256+)
- [ ] Cryptographically secure random number generator
- [ ] No deprecated algorithms (MD5, SHA1 for security, DES, RC4)
- [ ] Keys not hardcoded

### Specific Uses
- [ ] HMAC for message authentication
- [ ] Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- [ ] Proper IV/nonce handling (never reuse)
- [ ] Digital signatures for integrity-critical data

---

## Network Security

### Web Security Headers
- [ ] `Content-Security-Policy`
- [ ] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY` (or CSP frame-ancestors)
- [ ] `Referrer-Policy`
- [ ] `Permissions-Policy` (if applicable)

### Cross-Origin Security
- [ ] CORS configured restrictively
- [ ] CSRF protection implemented
- [ ] SameSite cookie attribute set

### Infrastructure
- [ ] Firewalls configured
- [ ] Internal services not exposed
- [ ] Admin interfaces restricted by IP (if applicable)
- [ ] DDoS protection (if applicable)

---

## Third-Party Components

### Dependencies
- [ ] Dependencies from trusted sources
- [ ] Dependencies pinned to specific versions
- [ ] Lock files committed
- [ ] Regular vulnerability scanning
- [ ] Automated dependency updates configured
- [ ] Unused dependencies removed

### External Services
- [ ] API keys stored securely
- [ ] Minimal permissions granted
- [ ] Failure handling for service outages
- [ ] Data shared with third parties documented

---

## Configuration

### Secure Defaults
- [ ] Security features enabled by default
- [ ] Debug/development features disabled in production
- [ ] Unnecessary features disabled
- [ ] Default credentials changed
- [ ] Sample/test data removed

### Environment Separation
- [ ] Separate configurations per environment
- [ ] Production data not in test environments
- [ ] Environment-specific secrets

---

## Deployment

### Build Security
- [ ] Build from controlled source
- [ ] Dependencies verified (checksums/signatures)
- [ ] Build artifacts signed (if applicable)
- [ ] SBOM generated

### Runtime Security
- [ ] Minimal container images
- [ ] Non-root execution
- [ ] Read-only filesystem where possible
- [ ] Resource limits configured
- [ ] Network policies defined

---

## Compliance Considerations

### Privacy
- [ ] Privacy policy exists
- [ ] Consent mechanisms implemented
- [ ] Data subject rights supported (access, deletion)
- [ ] Data processing records maintained
- [ ] Cross-border transfer controls (if applicable)

### Industry-Specific
- [ ] PCI DSS requirements (payment data)
- [ ] HIPAA requirements (health data)
- [ ] SOC 2 controls (service providers)
- [ ] FedRAMP requirements (US government)

---

## Quick Start Security Requirements

For new projects, start with these essential requirements:

### Minimum Viable Security
1. **Authentication**: Password hashing with bcrypt/Argon2, session management
2. **Authorization**: Server-side checks, default deny
3. **Input Validation**: Parameterized queries, output encoding
4. **HTTPS**: TLS for all traffic
5. **Secrets**: No hardcoded credentials, use environment variables
6. **Logging**: Authentication events, security errors
7. **Dependencies**: Lock files, vulnerability scanning
8. **Headers**: HSTS, CSP, X-Content-Type-Options

---

## References

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
