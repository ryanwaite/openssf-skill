# OSPS Baseline Level 1 Checklist

The Open Source Project Security (OSPS) Baseline defines minimum security requirements for open source projects. Level 1 represents the **universal security floor** that all projects should meet.

## Overview

Level 1 focuses on foundational security controls that:
- Prevent common attack vectors
- Enable vulnerability reporting
- Establish basic governance
- Require minimal maintainer effort

---

## Access Control (AC)

### AC-01: Multi-Factor Authentication
**Requirement**: All users with the ability to make changes to the project software or infrastructure MUST use multi-factor authentication.

- [ ] All maintainers have MFA enabled on GitHub
- [ ] Repository settings require MFA for organization members
- [ ] Service accounts use secure authentication methods

**How to verify**:
```
Repository Settings → Access → Require 2FA for organization members
```

**How to remediate**:
1. Go to Organization Settings → Authentication security
2. Enable "Require two-factor authentication"
3. Give members time to enable 2FA before enforcement

---

### AC-02: Least Privilege Access
**Requirement**: New collaborators on the project MUST be assigned the lowest permissions consistent with their responsibilities.

- [ ] New contributors start with read/triage access
- [ ] Write access granted after establishing trust
- [ ] Admin access limited to core maintainers
- [ ] Permissions reviewed periodically

**Role guidelines**:
| Role | When to grant |
|------|--------------|
| Read | Default for new contributors |
| Triage | After first accepted contribution |
| Write | Regular, trusted contributors |
| Maintain | Long-term maintainers |
| Admin | Project leads only |

---

### AC-03: Branch Protection
**Requirement**: The project's primary branch MUST NOT allow any commits that haven't been reviewed prior to commit, except for the initial commit.

- [ ] Branch protection enabled on `main`/`master`
- [ ] Require pull request reviews before merging
- [ ] At least 1 approval required
- [ ] Dismiss stale reviews on new commits
- [ ] No direct pushes allowed

**How to configure**:
1. Settings → Branches → Add rule
2. Branch name pattern: `main`
3. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require approvals: 1
   - ✅ Dismiss stale pull request approvals

---

### AC-04: No Force Push/Delete
**Requirement**: The project's primary branch MUST NOT allow any commits that change history unless authorized by code review.

- [ ] Force pushes disabled on protected branches
- [ ] Branch deletion restricted
- [ ] Linear history enforced (optional but recommended)

**How to configure**:
Settings → Branches → (your branch rule)
- ✅ Do not allow force pushes
- ✅ Do not allow deletions

---

## Build & Release (BR)

### BR-01: CI/CD Sanitization
**Requirement**: The project's build pipelines MUST sanitize user input that might contain executable code or dangerous injection vectors.

- [ ] Environment variables sanitized in CI scripts
- [ ] No direct execution of user-provided input
- [ ] Script injection patterns avoided in workflows

**Dangerous pattern to avoid**:
```yaml
# DANGEROUS
- run: echo "${{ github.event.issue.title }}"  # Could contain malicious code
```

**Safe alternative**:
```yaml
# SAFE: Use environment variable
- run: echo "$TITLE"
  env:
    TITLE: ${{ github.event.issue.title }}
```

---

### BR-02: Encrypted Distribution
**Requirement**: Any release artifacts that are distributed MUST be available via TLS/HTTPS.

- [ ] All download links use HTTPS
- [ ] Package registry uses HTTPS
- [ ] No HTTP fallbacks for downloads
- [ ] CDN configured for HTTPS only

---

## Documentation (DC)

### DC-01: User Guide
**Requirement**: The project MUST provide a resource containing documentation for end users.

- [ ] README.md exists with basic usage
- [ ] Installation instructions provided
- [ ] Getting started guide available
- [ ] API documentation (if applicable)

**Minimum README sections**:
```markdown
# Project Name

Brief description

## Installation

## Quick Start

## Usage

## Contributing

## License
```

---

### DC-02: Defect Reporting
**Requirement**: The project MUST provide a resource containing instructions for reporting defects.

- [ ] Bug report template exists
- [ ] Issue tracker configured
- [ ] Clear instructions for bug reports
- [ ] Expected response time documented

**Create issue template** `.github/ISSUE_TEMPLATE/bug_report.md`:
```markdown
---
name: Bug Report
about: Report a bug
labels: bug
---

## Description
[Clear description of the bug]

## Steps to Reproduce
1.
2.
3.

## Expected Behavior

## Actual Behavior

## Environment
- OS:
- Version:
```

---

## Governance (GV)

### GV-01: Public Discussion
**Requirement**: The project MUST allow public discussion of the project with maintainers.

- [ ] GitHub Discussions enabled, OR
- [ ] Mailing list available, OR
- [ ] Discord/Slack/Matrix channel exists
- [ ] Discussion channels documented in README

---

### GV-02: Contribution Process
**Requirement**: The project MUST have a documented process for accepting contributions.

- [ ] CONTRIBUTING.md exists
- [ ] PR process documented
- [ ] Code style guidelines (if any)
- [ ] Testing requirements documented

**Minimum CONTRIBUTING.md**:
```markdown
# Contributing

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Code Review Process

All changes require review before merging.

## Code of Conduct

[Link to CODE_OF_CONDUCT.md or statement]
```

---

## Legal (LG)

### LG-01: OSI-Approved License
**Requirement**: The project MUST be available under a single license that is available under the Open Source Definition.

- [ ] Using OSI-approved license
- [ ] License clearly stated

**Common OSI-approved licenses**:
- MIT
- Apache-2.0
- GPL-3.0
- BSD-3-Clause
- ISC
- MPL-2.0

---

### LG-02: LICENSE File
**Requirement**: A LICENSE file MUST be present in the project's root directory.

- [ ] LICENSE or LICENSE.txt exists
- [ ] Contains full license text
- [ ] Matches license declared in package manifest

---

## Quality (QA)

### QA-01: Public Repository
**Requirement**: The project source code repository MUST be publicly available and allow examination of the repository's version history.

- [ ] Repository is public
- [ ] Full git history available
- [ ] No squashed imports that hide history

---

### QA-02: Commit History
**Requirement**: The project MUST maintain a documented history for changes to the project.

- [ ] Using version control (git)
- [ ] Meaningful commit messages
- [ ] History not rewritten on main branch

---

### QA-03: Dependencies Listed
**Requirement**: The project MUST publish a resource that lists all third-party components used by the project.

- [ ] Package manifest exists (package.json, requirements.txt, go.mod, etc.)
- [ ] All dependencies declared
- [ ] Lock file committed (package-lock.json, poetry.lock, go.sum, etc.)

---

## Vulnerability Management (VM)

### VM-01: Security Contact
**Requirement**: The project MUST clearly document where and how to contact maintainers to report a security vulnerability.

- [ ] SECURITY.md exists
- [ ] Contact method documented (email, GitHub Security Advisories)
- [ ] PGP key provided (optional but recommended)

**Minimum SECURITY.md**:
```markdown
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities via:
- GitHub Security Advisories (preferred)
- Email: security@example.com

Do NOT create public issues for security vulnerabilities.
```

---

### VM-02: Response Timeline
**Requirement**: The project SHOULD provide a reasonable timeline for responding to reported security vulnerabilities.

- [ ] Initial response timeline documented
- [ ] Status update frequency documented
- [ ] Resolution target documented

**Recommended timelines**:
| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Status updates | Every 14 days |
| Resolution | 90 days (severity dependent) |

---

## Quick Start Compliance

### Minimum Files Needed

1. **LICENSE** - Full license text
2. **README.md** - Basic documentation
3. **SECURITY.md** - Vulnerability reporting
4. **CONTRIBUTING.md** - Contribution process

### Repository Settings

1. Enable MFA requirement
2. Enable branch protection on `main`
3. Require PR reviews
4. Disable force push

### Workflows

1. Add basic CI testing
2. Enable Dependabot

---

## Compliance Verification

### Self-Assessment

Run through this checklist:
```
Access Control:
  [x] MFA enabled for all maintainers
  [x] Least privilege access configured
  [x] Branch protection enabled
  [ ] Force push disabled

Build & Release:
  [x] CI/CD scripts sanitized
  [x] HTTPS for all downloads

Documentation:
  [x] README with usage docs
  [x] Bug reporting instructions

Governance:
  [x] Public discussion available
  [x] CONTRIBUTING.md exists

Legal:
  [x] OSI-approved license
  [x] LICENSE file present

Quality:
  [x] Public repository
  [x] Commit history maintained
  [x] Dependencies listed

Vulnerability Management:
  [x] SECURITY.md exists
  [x] Response timeline documented
```

### Automated Checks

Use OpenSSF Scorecard to verify many of these requirements:
```bash
scorecard --repo=github.com/owner/repo
```

---

## Next Steps: Level 2

After achieving Level 1, consider advancing to Level 2:
- Unique version identifiers
- Signed releases
- Coordinated vulnerability disclosure
- Automated status checks
- Security assessment documentation

See: https://baseline.openssf.org/

---

## References

- [OSPS Baseline Specification](https://baseline.openssf.org/)
- [OpenSSF Best Practices](https://best.openssf.org/)
- [GitHub Security Features](https://docs.github.com/en/code-security)
