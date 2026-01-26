# STRIDE Threat Modeling Guide

## What is STRIDE?

STRIDE is a threat modeling methodology developed by Microsoft that helps systematically identify security threats. Each letter represents a category of threat:

| Letter | Threat | Security Property Violated |
|--------|--------|---------------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

## When to Use Threat Modeling

- **New features**: Before implementing features that handle sensitive data or authentication
- **Architecture changes**: When modifying system boundaries or data flows
- **Security reviews**: Periodic assessment of existing systems
- **Incident response**: After security incidents to identify related threats
- **Compliance**: To document security considerations for audits

## The Threat Modeling Process

### Step 1: Define Scope

Clearly define what you're modeling:

- **System/Component**: What specific part of the system?
- **Trust boundaries**: Where does trusted/untrusted data cross?
- **Assumptions**: What are you assuming is already secure?
- **Out of scope**: What are you explicitly NOT modeling?

**Example Scope Statement**:
> "This threat model covers the user authentication flow, from login form submission through session establishment. It assumes TLS is correctly implemented for all connections. Third-party OAuth providers are out of scope."

### Step 2: Create a Data Flow Diagram (DFD)

A DFD visualizes how data moves through your system using these elements:

```
┌─────────────────────────────────────────────────────────────┐
│                     TRUST BOUNDARY                          │
│  ┌──────────┐                          ┌──────────────┐    │
│  │  Process │ ◄─────── data ──────────►│  Data Store  │    │
│  └──────────┘                          └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
       ▲
       │ data
       ▼
┌──────────────┐
│   External   │
│    Entity    │
└──────────────┘
```

**DFD Elements**:
- **External Entity** (rectangle): Users, external systems, third-party services
- **Process** (circle/rounded rectangle): Code that transforms data
- **Data Store** (parallel lines): Databases, files, caches
- **Data Flow** (arrow): Data moving between elements
- **Trust Boundary** (dashed line): Where trust level changes

### Step 3: Apply STRIDE to Each Element

For each element and data flow in your DFD, consider each STRIDE category:

#### Spoofing (Authentication)

*Can an attacker pretend to be something or someone else?*

| Element Type | Spoofing Questions |
|-------------|-------------------|
| External Entity | Can users be impersonated? Are credentials secure? |
| Process | Can processes be impersonated? Is service identity verified? |
| Data Store | Can the data store be replaced with a malicious one? |
| Data Flow | Can messages be forged? Is the sender authenticated? |

#### Tampering (Integrity)

*Can an attacker modify data?*

| Element Type | Tampering Questions |
|-------------|---------------------|
| Process | Can code be modified? Are updates verified? |
| Data Store | Can stored data be modified? Is integrity checked? |
| Data Flow | Can data in transit be modified? Is it signed? |

#### Repudiation (Non-repudiation)

*Can an attacker deny their actions?*

| Element Type | Repudiation Questions |
|-------------|----------------------|
| External Entity | Are actions logged with user identity? |
| Process | Are operations auditable? Are logs tamper-proof? |
| Data Store | Is access logged? Can audit trails be modified? |

#### Information Disclosure (Confidentiality)

*Can an attacker access data they shouldn't?*

| Element Type | Information Disclosure Questions |
|-------------|--------------------------------|
| Process | Are secrets exposed in logs? Memory? Error messages? |
| Data Store | Is data encrypted? Are backups protected? |
| Data Flow | Is data encrypted in transit? Can it be intercepted? |

#### Denial of Service (Availability)

*Can an attacker make the system unavailable?*

| Element Type | DoS Questions |
|-------------|---------------|
| Process | Can it be overwhelmed? Are there resource limits? |
| Data Store | Can storage be exhausted? Is there rate limiting? |
| Data Flow | Can connections be exhausted? Bandwidth? |

#### Elevation of Privilege (Authorization)

*Can an attacker gain unauthorized access?*

| Element Type | EoP Questions |
|-------------|--------------|
| External Entity | Can users access admin functions? |
| Process | Can code run with elevated privileges? |
| Data Store | Are permissions properly enforced? |
| Data Flow | Can authorization be bypassed? |

### Step 4: Document Threats

For each identified threat, document:

```markdown
## Threat: [T-001] Session Token Theft via XSS

**Category**: Information Disclosure
**Component**: Web Application / Session Management
**Description**: An attacker could inject malicious JavaScript that steals session tokens
**Attack Vector**: Stored or reflected XSS in user-generated content
**Impact**: HIGH - Full account compromise
**Likelihood**: MEDIUM - Requires finding XSS vulnerability
**Risk**: HIGH

### Mitigations
1. Set HttpOnly flag on session cookies
2. Implement Content Security Policy (CSP)
3. Sanitize all user input
4. Use framework's built-in XSS protections
```

### Step 5: Prioritize and Mitigate

#### Risk Assessment Matrix

| Likelihood ↓ / Impact → | Low | Medium | High |
|------------------------|-----|--------|------|
| High | Medium | High | Critical |
| Medium | Low | Medium | High |
| Low | Low | Low | Medium |

#### Mitigation Strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| **Eliminate** | Remove the threat source | Don't store sensitive data you don't need |
| **Mitigate** | Reduce impact or likelihood | Add encryption, input validation |
| **Transfer** | Move risk to another party | Use managed authentication service |
| **Accept** | Acknowledge and monitor | Document low-risk issues for future |

## STRIDE-per-Element

For efficiency, apply STRIDE based on element type (not all threats apply to all elements):

| Element | S | T | R | I | D | E |
|---------|---|---|---|---|---|---|
| External Entity | ✓ |   | ✓ |   |   |   |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow |   | ✓ |   | ✓ | ✓ |   |

## Common Threat Patterns

### Web Applications
- Session hijacking (S, I)
- SQL injection (T, I, E)
- XSS (S, T, I)
- CSRF (S, T)
- Insecure direct object references (I, E)

### APIs
- Broken authentication (S, E)
- Excessive data exposure (I)
- Lack of rate limiting (D)
- Mass assignment (T, E)
- Injection attacks (T, I, E)

### Microservices
- Service impersonation (S)
- Man-in-the-middle (T, I)
- Cascading failures (D)
- Privilege creep (E)
- Log injection (R, T)

## Tools for Threat Modeling

- **Microsoft Threat Modeling Tool**: Free, Windows-based, generates DFDs
- **OWASP Threat Dragon**: Open source, web-based
- **IriusRisk**: Commercial, automated threat library
- **draw.io/diagrams.net**: General diagramming (manual STRIDE application)

## References

- [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Adam Shostack's Threat Modeling Book](https://shostack.org/books/threat-modeling-book)
