# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main branch | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously, even in documentation and skill files.

### Potential Security Concerns

This repository contains:
- Documentation and templates (low risk)
- A Python assessment script (`scripts/assess-project.py`) that runs locally
- GitHub Actions workflow templates

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities using one of these methods:

1. **GitHub Security Advisories** (Recommended)
   - Go to the [Security tab](https://github.com/ryanwaite/openssf-skill/security)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Private Disclosure**
   - Open a [private security advisory](https://github.com/ryanwaite/openssf-skill/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | Within 72 hours |
| Assessment | Within 7 days |
| Resolution | Within 30 days |

## Security Considerations

When using this skill:

1. **Review templates before use**: Templates are starting points - review and customize for your project
2. **Workflow templates**: Review GitHub Actions workflows before adding to your repository
3. **Assessment script**: The `assess-project.py` script only reads files locally and outputs JSON - it does not make network requests or modify files

## Acknowledgments

We appreciate responsible disclosure and will acknowledge reporters in our release notes (unless they prefer anonymity).

---

*This project follows the security practices it teaches - practicing what we preach!*
