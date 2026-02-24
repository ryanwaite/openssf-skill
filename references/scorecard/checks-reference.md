# OpenSSF Scorecard Checks Reference

OpenSSF Scorecard automatically assesses open source projects for security risks. Each check returns a score from 0-10 (higher is better) and a risk level.

## Running Scorecard

```bash
# Install scorecard
go install github.com/ossf/scorecard/v5/cmd/scorecard@latest

# Run against a GitHub repository
scorecard --repo=github.com/owner/repo

# Run with detailed output
scorecard --repo=github.com/owner/repo --show-details

# Output as JSON
scorecard --repo=github.com/owner/repo --format=json > scorecard.json
```

---

## Check Categories

### Source Risk Assessment

| Check | Risk | Description |
|-------|------|-------------|
| [Branch-Protection](#branch-protection) | High | Protected branches and review requirements |
| [Code-Review](#code-review) | High | Code review before merge |
| [Contributors](#contributors) | Low | Project has multiple contributors |
| [Dangerous-Workflow](#dangerous-workflow) | Critical | Dangerous patterns in GitHub Actions |
| [License](#license) | Low | Published license file |
| [Maintained](#maintained) | High | Active project maintenance |
| [Signed-Releases](#signed-releases) | High | Cryptographically signed releases |

### Build Risk Assessment

| Check | Risk | Description |
|-------|------|-------------|
| [Binary-Artifacts](#binary-artifacts) | High | Checked-in binary files |
| [CI-Tests](#ci-tests) | Low | Tests run in CI |
| [OpenSSF-Best-Practices](#openssf-best-practices) | Low | OpenSSF Best Practices Badge |
| [Dependency-Update-Tool](#dependency-update-tool) | High | Automated dependency updates |
| [Fuzzing](#fuzzing) | Medium | Fuzz testing integration |
| [Packaging](#packaging) | Medium | Published as a package |
| [Pinned-Dependencies](#pinned-dependencies) | Medium | Dependencies pinned to hashes |
| [SAST](#sast) | Medium | Static analysis tools |
| [Security-Policy](#security-policy) | Medium | SECURITY.md file |
| [Token-Permissions](#token-permissions) | High | Minimal CI token permissions |
| [Vulnerabilities](#vulnerabilities) | High | Known vulnerabilities |
| [Webhooks](#webhooks) | High | Webhook security |

---

## Detailed Check Descriptions

### Binary-Artifacts

**Risk Level**: High
**What it checks**: Whether binary files are checked into the repository.

Binary files can hide malicious code and are difficult to audit. They should be built from source.

**Scoring**:
- 10: No binary artifacts found
- 0: Binary artifacts present in repository

**How to remediate**:
1. Remove binary files from the repository
2. Add binary extensions to `.gitignore`
3. Build binaries from source in CI/CD
4. Host pre-built binaries in releases, not in the repo

```gitignore
# Add to .gitignore
*.exe
*.dll
*.so
*.dylib
*.a
*.o
*.pyc
*.class
*.jar
```

---

### Branch-Protection

**Risk Level**: High
**What it checks**: Whether the default branch has protection rules enabled.

**Scoring criteria**:
- Admin enforcement
- Required reviews before merge
- Dismiss stale reviews
- Require code owner reviews
- Require status checks
- Require up-to-date branches
- Require signed commits

**How to remediate**:

1. Go to Repository Settings → Branches
2. Add branch protection rule for `main`/`master`
3. Enable:
   - [x] Require pull request reviews before merging
   - [x] Require status checks to pass before merging
   - [x] Require branches to be up to date before merging
   - [x] Include administrators (for full score)
   - [x] Require signed commits (optional but recommended)

**Example branch protection configuration**:
```yaml
# Via GitHub API or terraform
branch_protection:
  required_pull_request_reviews:
    required_approving_review_count: 1
    dismiss_stale_reviews: true
    require_code_owner_reviews: true
  required_status_checks:
    strict: true
    contexts:
      - "ci/tests"
  enforce_admins: true
  required_signatures: true
```

---

### CI-Tests

**Risk Level**: Low
**What it checks**: Whether the project runs tests in CI.

**Scoring**:
- 10: Evidence of CI test runs found
- 0: No CI test evidence

**How to remediate**:

Add a test workflow:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: |
          # Your test command
          npm test  # or pytest, go test, etc.
```

---

### OpenSSF-Best-Practices

**Risk Level**: Low
**What it checks**: Whether the project has an OpenSSF Best Practices Badge (formerly CII Best Practices).

See [Best Practices Badge Guide](../best-practices-badge/getting-started.md) for a detailed walkthrough.

**Scoring**:
- 10: Gold badge
- 7: Silver badge
- 5: Passing badge
- 0: No badge

**How to remediate**:

1. Go to https://www.bestpractices.dev/
2. Sign in with GitHub
3. Register your project
4. Answer the questionnaire (takes ~20 minutes)
5. Add badge to README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

---

### Code-Review

**Risk Level**: High
**What it checks**: Whether changes are reviewed before merge.

**Scoring**:
- Examines recent commits to see if they were reviewed
- Higher score = more consistent code review

**How to remediate**:

1. Enable branch protection requiring reviews
2. Establish code review culture
3. Never push directly to main branch
4. Use pull requests for all changes
5. Consider CODEOWNERS for critical paths:

```
# .github/CODEOWNERS
# Security-sensitive files require security team review
/auth/          @security-team
*.security.*    @security-team
SECURITY.md     @security-team
```

---

### Contributors

**Risk Level**: Low
**What it checks**: Whether the project has multiple contributors.

**Scoring**:
- Higher score with more unique contributors
- Recent contribution activity improves score

**How to remediate**:
- Encourage contributions from multiple maintainers
- Accept contributions from the community
- Document contribution process in CONTRIBUTING.md

---

### Dependency-Update-Tool

**Risk Level**: High
**What it checks**: Whether the project uses a dependency update tool (e.g., Dependabot, Renovate).

**Scoring**:
- Full score if Dependabot or Renovate is configured
- Checks for `.github/dependabot.yml`, `renovate.json`, `.renovaterc`, or similar config files

**How to remediate**:

1. Enable Dependabot:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"  # or pip, gomod, cargo, maven, etc.
    directory: "/"
    schedule:
      interval: "weekly"
```

2. Or configure Renovate:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"]
}
```

---

### Dangerous-Workflow

**Risk Level**: Critical
**What it checks**: Dangerous patterns in GitHub Actions workflows.

**Dangerous patterns**:
- `pull_request_target` with explicit checkout of PR head
- Untrusted code execution with elevated permissions
- Script injection via untrusted input

**Scoring**:
- 10: No dangerous patterns found
- 0: Dangerous patterns detected

**How to remediate**:

Avoid this dangerous pattern:
```yaml
# DANGEROUS - Don't do this!
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Dangerous!
      - run: npm install && npm test  # Executes untrusted code with write access
```

Safe alternatives:
```yaml
# Safe: Use pull_request (not pull_request_target) for untrusted code
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install && npm test

# If you need pull_request_target, don't checkout PR code
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v4  # Only uses metadata, not PR code
```

---

### Fuzzing

**Risk Level**: Medium
**What it checks**: Whether the project uses fuzzing for testing.

**Scoring**:
- Checks for OSS-Fuzz integration
- Checks for fuzzing configuration files

**How to remediate**:

1. Integrate with [OSS-Fuzz](https://github.com/google/oss-fuzz)
2. Or add local fuzzing:

```yaml
# For Go projects
name: Fuzz
on: [push, pull_request]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test -fuzz=FuzzParsing -fuzztime=30s ./...
```

---

### License

**Risk Level**: Low
**What it checks**: Whether the project has a license file.

**Scoring**:
- 10: OSI-approved license detected
- 0: No license file

**How to remediate**:

Add a LICENSE file with an OSI-approved license:
- MIT
- Apache-2.0
- GPL-3.0
- BSD-3-Clause

---

### Maintained

**Risk Level**: High
**What it checks**: Whether the project is actively maintained (commits in last 90 days).

**Scoring**:
- Based on recent commit activity
- Issue/PR response times

**How to remediate**:
- Make regular commits (even small updates)
- Respond to issues and PRs
- Mark project as unmaintained if abandoned
- Transfer ownership if unable to maintain

---

### Packaging

**Risk Level**: Medium
**What it checks**: Whether the project publishes packages.

**Scoring**:
- Checks for published packages on registries
- npm, PyPI, Maven, etc.

**How to remediate**:
- Publish releases to package registries
- Use GitHub Releases
- Automate publishing in CI/CD

---

### Pinned-Dependencies

**Risk Level**: Medium
**What it checks**: Whether dependencies are pinned to specific versions/hashes.

**Scoring**:
- Checks Dockerfiles, GitHub Actions, and other config files
- Higher score for hash-pinned dependencies

**How to remediate**:

In Dockerfiles:
```dockerfile
# Bad: unpinned
FROM node:18

# Better: version pinned
FROM node:18.19.0

# Best: hash pinned
FROM node:18.19.0@sha256:abc123...
```

In GitHub Actions:
```yaml
# Bad: unpinned
uses: actions/checkout@v4

# Best: hash pinned
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

Use tools like [pin-github-action](https://github.com/mheap/pin-github-action) to automate pinning.

---

### SAST

**Risk Level**: Medium
**What it checks**: Whether static analysis tools are used.

**Scoring**:
- Checks for CodeQL, Semgrep, SonarQube, etc.
- Looks at workflow files and tool configurations

**How to remediate**:

Enable CodeQL:
```yaml
# .github/workflows/codeql.yml
name: CodeQL
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript  # or python, go, java, etc.
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

---

### Security-Policy

**Risk Level**: Medium
**What it checks**: Whether the project has a SECURITY.md file.

**Scoring**:
- 10: SECURITY.md exists with content
- 0: No security policy

**How to remediate**:

Create `.github/SECURITY.md` or `SECURITY.md` in the root.

See the [SECURITY.md template](../../templates/SECURITY.md.template) provided by this skill.

---

### Signed-Releases

**Risk Level**: High
**What it checks**: Whether releases are cryptographically signed.

**Scoring**:
- Checks for GPG signatures
- Checks for Sigstore signatures (cosign)
- Checks for SLSA provenance

**How to remediate**:

Option 1: GPG signing
```bash
# Sign release artifacts
gpg --armor --detach-sign release.tar.gz
```

Option 2: Sigstore/cosign
```bash
# Sign with keyless signing
cosign sign-blob release.tar.gz --bundle release.tar.gz.bundle
```

Option 3: SLSA provenance (recommended)
See [SLSA workflow template](../../workflows/slsa-provenance.yml.template).

---

### Token-Permissions

**Risk Level**: High
**What it checks**: Whether GitHub Actions use minimal token permissions.

**Scoring**:
- Higher score for explicit, minimal permissions
- Lower score for default (write-all) permissions

**How to remediate**:

Set minimal permissions at workflow or job level:
```yaml
name: CI

# Set default to read-only
permissions: read-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  deploy:
    runs-on: ubuntu-latest
    # Only grant write where needed
    permissions:
      contents: write
      packages: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
```

---

### Vulnerabilities

**Risk Level**: High
**What it checks**: Whether the project has unfixed vulnerabilities (via OSV).

**Scoring**:
- 10: No known vulnerabilities
- Lower score based on number and severity of vulnerabilities

**How to remediate**:

1. Check vulnerabilities:
```bash
# Install osv-scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan project
osv-scanner -r .
```

2. Update vulnerable dependencies
3. If no fix available, document in security advisory
4. Enable Dependabot for automated updates

---

### Webhooks

**Risk Level**: High
**What it checks**: Whether webhooks use secrets for authentication.

**Scoring**:
- Checks if webhook configurations include secrets
- Cannot fully verify without admin access

**How to remediate**:

1. Configure webhook secrets in GitHub settings
2. Verify webhook signatures in your endpoint:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = 'sha256=' + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

---

## Quick Remediation Guide

### Highest Impact (Fix First)

| Check | Effort | Impact |
|-------|--------|--------|
| Security-Policy | 15 min | Medium |
| Token-Permissions | 15 min | High |
| Branch-Protection | 10 min | High |
| Pinned-Dependencies | 30 min | Medium |
| SAST (CodeQL) | 15 min | Medium |

### Automated Scanning Workflow

Add this workflow to run Scorecard automatically:

```yaml
# .github/workflows/scorecard.yml
name: Scorecard
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly
  push:
    branches: [main]

permissions: read-all

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## References

- [Scorecard GitHub Repository](https://github.com/ossf/scorecard)
- [Scorecard Checks Documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [Scorecard Action](https://github.com/ossf/scorecard-action)
- [Scorecard Visualizer](https://scorecard.dev/)
