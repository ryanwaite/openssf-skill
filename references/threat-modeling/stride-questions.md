# STRIDE Questions Reference

Use these questions when analyzing each component and data flow in your system. Not all questions apply to every component - use judgment based on the component type.

---

## S - Spoofing (Authentication)

*Goal: Ensure entities are who/what they claim to be*

### For Users/External Entities
- [ ] How do users authenticate? (passwords, MFA, SSO, certificates)
- [ ] Can credentials be brute-forced? Are there lockout mechanisms?
- [ ] Are password requirements strong enough?
- [ ] Is MFA available/required for sensitive operations?
- [ ] Can session tokens be stolen and reused?
- [ ] Are API keys rotated regularly?
- [ ] Can one user impersonate another?

### For Services/Processes
- [ ] How do services authenticate to each other?
- [ ] Are service accounts used with minimal privileges?
- [ ] Is mutual TLS (mTLS) used for service-to-service communication?
- [ ] Can a rogue service join the network?
- [ ] Are webhooks/callbacks verified (signatures, shared secrets)?

### For Data Sources
- [ ] How do you verify data came from a legitimate source?
- [ ] Can an attacker substitute a malicious data source?
- [ ] Are external APIs authenticated and verified?
- [ ] Is DNS resolution trusted? (DNS spoofing risk)

---

## T - Tampering (Integrity)

*Goal: Ensure data hasn't been modified without authorization*

### For Data in Transit
- [ ] Is all network traffic encrypted (TLS 1.2+)?
- [ ] Are messages signed or MAC'd to detect tampering?
- [ ] Can an attacker perform man-in-the-middle attacks?
- [ ] Are certificate validation errors handled correctly?
- [ ] Is certificate pinning used for mobile apps?

### For Data at Rest
- [ ] Can database records be modified directly?
- [ ] Are file integrity checks in place (checksums, signatures)?
- [ ] Can configuration files be modified?
- [ ] Are backups protected from tampering?
- [ ] Can logs be modified to hide evidence?

### For Code/Binaries
- [ ] Are releases signed? Can signatures be verified?
- [ ] Are dependencies verified (lock files, checksums)?
- [ ] Can build artifacts be tampered with?
- [ ] Is there integrity checking for plugins/extensions?

### For User Input
- [ ] Is all user input validated and sanitized?
- [ ] Can SQL injection occur?
- [ ] Can command injection occur?
- [ ] Can LDAP/XML/XPath injection occur?
- [ ] Are file uploads validated (type, size, content)?

---

## R - Repudiation (Non-repudiation)

*Goal: Ensure actions can be traced and proven*

### For User Actions
- [ ] Are all user actions logged with timestamps?
- [ ] Is the user identity captured in audit logs?
- [ ] Can users deny performing actions?
- [ ] Are login/logout events logged?
- [ ] Are failed authentication attempts logged?

### For System Operations
- [ ] Are administrative actions logged?
- [ ] Are configuration changes tracked?
- [ ] Are deployments and releases logged?
- [ ] Is there a chain of custody for changes?

### For Log Integrity
- [ ] Are logs stored securely (separate system/account)?
- [ ] Can logs be tampered with or deleted?
- [ ] Are logs cryptographically protected?
- [ ] Is there log retention and rotation policy?
- [ ] Are logs monitored and alerted on?

### For Transactions
- [ ] Are financial/critical transactions logged?
- [ ] Is there an audit trail that can't be modified?
- [ ] Are transaction logs sufficient for legal evidence?
- [ ] Are digital signatures used for important actions?

---

## I - Information Disclosure (Confidentiality)

*Goal: Ensure data is only accessible to authorized parties*

### For Data Storage
- [ ] Is sensitive data encrypted at rest?
- [ ] Are encryption keys properly managed?
- [ ] Is PII/PHI properly protected?
- [ ] Are backups encrypted?
- [ ] Is data properly classified?

### For Data Transmission
- [ ] Is sensitive data encrypted in transit?
- [ ] Are there unencrypted fallbacks?
- [ ] Could data be intercepted on the network?
- [ ] Are cookies marked as Secure?

### For Error Handling
- [ ] Do error messages reveal sensitive information?
- [ ] Are stack traces exposed to users?
- [ ] Do error pages reveal software versions?
- [ ] Are database errors shown to users?

### For Logging
- [ ] Are passwords/tokens logged?
- [ ] Is PII logged unnecessarily?
- [ ] Are logs accessible to unauthorized users?
- [ ] Is sensitive data masked in logs?

### For Access Control
- [ ] Can users access other users' data?
- [ ] Are authorization checks consistent across endpoints?
- [ ] Is there broken object-level authorization (BOLA/IDOR)?
- [ ] Can metadata leak information?

### For Side Channels
- [ ] Do timing differences reveal information?
- [ ] Do error messages differ based on data existence?
- [ ] Can resource enumeration reveal valid IDs/usernames?
- [ ] Is sensitive data cached inappropriately?

---

## D - Denial of Service (Availability)

*Goal: Ensure the system remains available to legitimate users*

### For Network Resources
- [ ] Is there rate limiting on endpoints?
- [ ] Are there connection limits?
- [ ] Is there DDoS protection?
- [ ] Can a single user exhaust bandwidth?

### For Compute Resources
- [ ] Can CPU be exhausted (ReDoS, algorithmic complexity)?
- [ ] Are there memory limits?
- [ ] Can a single request consume excessive resources?
- [ ] Are there timeouts for long-running operations?

### For Storage Resources
- [ ] Can storage be exhausted (log flooding, uploads)?
- [ ] Are there quotas/limits?
- [ ] Can temporary files fill disk?
- [ ] Is there cleanup for expired data?

### For Dependencies
- [ ] What happens if a dependency is unavailable?
- [ ] Are there circuit breakers?
- [ ] Is there graceful degradation?
- [ ] Are timeouts configured for external calls?

### For Application Logic
- [ ] Can deadlocks occur?
- [ ] Can infinite loops be triggered?
- [ ] Are there race conditions that cause failures?
- [ ] Can queue backlogs cause outages?

---

## E - Elevation of Privilege (Authorization)

*Goal: Ensure users can only perform authorized actions*

### For User Privileges
- [ ] Can regular users access admin functions?
- [ ] Is role-based access control (RBAC) properly implemented?
- [ ] Can users modify their own roles/permissions?
- [ ] Are default accounts/passwords changed?
- [ ] Is privilege separation enforced?

### For API Access
- [ ] Are authorization checks on every endpoint?
- [ ] Can horizontal privilege escalation occur (access other users' resources)?
- [ ] Can vertical privilege escalation occur (gain higher privileges)?
- [ ] Are admin APIs properly protected?
- [ ] Is there broken function-level authorization?

### For Code Execution
- [ ] Can user input lead to code execution?
- [ ] Can file uploads lead to RCE?
- [ ] Are deserialization vulnerabilities present?
- [ ] Can template injection occur?
- [ ] Are OS commands properly escaped?

### For Container/Host
- [ ] Do containers run as root?
- [ ] Are container capabilities minimized?
- [ ] Is the container runtime patched?
- [ ] Can container escape occur?
- [ ] Is the host properly hardened?

### For Dependencies
- [ ] Are dependencies from trusted sources?
- [ ] Could a malicious dependency be introduced?
- [ ] Are transitive dependencies reviewed?
- [ ] Is there protection against dependency confusion?

---

## Quick Reference Card

### Must-Ask Questions for Any System

1. **Authentication**: How do we know who the user/system is?
2. **Authorization**: How do we control what they can do?
3. **Encryption**: Is data protected in transit and at rest?
4. **Input Validation**: Is all input treated as untrusted?
5. **Logging**: Are security-relevant events logged?
6. **Error Handling**: Do errors leak sensitive information?
7. **Dependencies**: Are all dependencies trusted and updated?
8. **Secrets**: How are secrets managed and protected?

### Red Flags to Watch For

- "We trust that input because it comes from our app"
- "That endpoint doesn't need authentication"
- "We'll add security later"
- "Only admins know about that URL"
- "The database is behind a firewall"
- "We use encryption" (without specifying what/where/how)
