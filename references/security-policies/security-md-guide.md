# SECURITY.md Creation Guide

A SECURITY.md file tells users and security researchers how to report vulnerabilities in your project. This is one of the most important security artifacts you can create.

## Why SECURITY.md Matters

1. **Enables responsible disclosure**: Researchers know how to report issues privately
2. **Protects users**: Vulnerabilities get fixed before public disclosure
3. **Shows professionalism**: Demonstrates security awareness
4. **Required for compliance**: OpenSSF Scorecard and OSPS Baseline check for this

## Location Options

SECURITY.md can be placed in:
- Repository root: `SECURITY.md`
- GitHub special folder: `.github/SECURITY.md`
- Docs folder: `docs/SECURITY.md`

GitHub will automatically link to SECURITY.md from the Security tab.

## Essential Sections

### 1. Supported Versions

Tell users which versions receive security updates:

```markdown
## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :white_check_mark: (until 2025-06-01) |
| < 1.0   | :x:                |
```

Guidelines:
- Support at least the current major version
- Consider LTS (Long Term Support) for older versions
- Be clear about end-of-life dates
- Update when releasing new versions

### 2. Reporting Methods

Provide clear ways to report vulnerabilities:

```markdown
## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Report via one of these methods:

### GitHub Security Advisories (Recommended)
1. Go to the Security tab
2. Click "Report a vulnerability"
3. Fill out the form

### Email
- Send to: security@example.com
- Encrypt using PGP key: [fingerprint or link]
```

Best practices:
- Always provide a private reporting method
- GitHub Security Advisories is easiest for most projects
- Provide PGP key for email encryption
- List multiple methods for accessibility

### 3. What to Include in Reports

Help reporters provide useful information:

```markdown
## What to Include

Please provide:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Affected versions
- Suggested fix (if any)
```

### 4. Response Timeline

Set expectations for communication:

```markdown
## Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Status update | Every 14 days |
| Resolution target | 90 days (severity dependent) |
```

Realistic timelines:
- Acknowledgment: 24-72 hours
- Assessment: 3-7 days
- Resolution: 30-90 days depending on severity
- Be honest about capacity (hobby project vs. company)

### 5. Disclosure Policy

Explain your disclosure approach:

```markdown
## Disclosure Policy

We follow coordinated disclosure:
1. You report privately
2. We confirm and fix
3. We release a patch
4. We publish an advisory
5. Public disclosure after fix is available

We aim to disclose within 90 days of report.
```

Common policies:
- **Coordinated disclosure**: Fix first, then disclose (most common)
- **Full disclosure**: Immediate public disclosure (rare)
- **Timed disclosure**: Disclose after X days regardless of fix

### 6. Safe Harbor (Optional but Recommended)

Protect good-faith researchers:

```markdown
## Safe Harbor

We support safe harbor for security researchers who:
- Act in good faith
- Avoid privacy violations and data destruction
- Report through designated channels
- Allow reasonable time for fixes

We will not pursue legal action against researchers following these guidelines.
```

## Example: Minimal SECURITY.md

For small projects, a simple file is better than nothing:

```markdown
# Security Policy

## Reporting a Vulnerability

Please report security issues to security@example.com.

Do NOT create public GitHub issues for security vulnerabilities.

We will respond within 48 hours and work on a fix.
```

## Example: Comprehensive SECURITY.md

See the full template at: `templates/SECURITY.md.template`

## GitHub Security Features

When you have SECURITY.md, GitHub enables:
- Security tab shows "Security policy"
- Issue/PR templates can reference it
- Dependabot can link to it in alerts

### Enable GitHub Security Advisories

1. Go to Settings → Security → Enable private vulnerability reporting
2. This allows anyone to report via GitHub's interface
3. You can draft advisories, request CVEs, and coordinate fixes

## Maintaining Your Security Policy

- **Review annually**: Update supported versions, contacts
- **Test the process**: Ensure you can receive and respond to reports
- **Update after incidents**: Improve based on experience
- **Track metrics**: Response times, resolution times

## Common Mistakes

1. **No SECURITY.md**: Researchers don't know how to report
2. **Only public issues**: Vulnerabilities get disclosed prematurely
3. **Unrealistic timelines**: Overpromising leads to frustration
4. **No response process**: Reports go unanswered
5. **Stale information**: Old contacts, unsupported versions listed

## References

- [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories)
- [OpenSSF Vulnerability Disclosure Guide](https://github.com/ossf/wg-vulnerability-disclosures)
- [CERT Guide to Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD)
