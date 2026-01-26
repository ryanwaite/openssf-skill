# Scorecard Remediation Guide

This guide provides step-by-step remediation for common Scorecard issues, organized by effort and impact.

## Quick Wins (< 30 minutes each)

### 1. Add SECURITY.md

**Current Score Impact**: Security-Policy check
**Effort**: 15 minutes

```bash
# Create from template
cp ~/.claude/skills/openssf/templates/SECURITY.md.template SECURITY.md
# Or create in .github/
cp ~/.claude/skills/openssf/templates/SECURITY.md.template .github/SECURITY.md
```

Edit the template to add:
- Your security contact email
- Supported versions
- Disclosure timeline

### 2. Set Token Permissions

**Current Score Impact**: Token-Permissions check
**Effort**: 10 minutes

Add to all workflow files:
```yaml
# At the top level of workflow
permissions: read-all

# Or more granular per-job
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
```

### 3. Enable Branch Protection

**Current Score Impact**: Branch-Protection, Code-Review checks
**Effort**: 10 minutes

1. Go to Settings → Branches → Add rule
2. Branch name pattern: `main` (or your default branch)
3. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require approvals (1 minimum)
   - ✅ Dismiss stale pull request approvals when new commits are pushed
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Include administrators

### 4. Add CodeQL Analysis

**Current Score Impact**: SAST check
**Effort**: 15 minutes

Create `.github/workflows/codeql.yml`:
```yaml
name: CodeQL Analysis

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        language: ['javascript']  # Add your languages
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform Analysis
        uses: github/codeql-action/analyze@v3
```

### 5. Enable Dependabot

**Current Score Impact**: Dependency-Update-Tool, Vulnerabilities checks
**Effort**: 10 minutes

Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns:
          - "*"

  # npm (adjust for your package manager)
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      dependencies:
        patterns:
          - "*"

  # Python
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

  # Go
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## Medium Effort (30 min - 2 hours)

### 6. Pin Dependencies to Hashes

**Current Score Impact**: Pinned-Dependencies check
**Effort**: 30-60 minutes

#### GitHub Actions

Use [pin-github-action](https://github.com/mheap/pin-github-action):
```bash
# Install
npm install -g pin-github-action

# Pin all actions in a workflow
pin-github-action .github/workflows/ci.yml
```

Before:
```yaml
uses: actions/checkout@v4
```

After:
```yaml
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
```

#### Dockerfiles

```dockerfile
# Before
FROM node:18

# After (with digest)
FROM node:18@sha256:a7ff16657263663c1e92ba7fcfe4e8a3e5b0d1699b8c2e1e2f1ea2d8b1b3c4d5
```

Find digests:
```bash
docker pull node:18
docker inspect --format='{{index .RepoDigests 0}}' node:18
```

### 7. Add Signed Releases

**Current Score Impact**: Signed-Releases check
**Effort**: 1-2 hours

#### Option A: GPG Signing

```bash
# Generate GPG key if needed
gpg --full-generate-key

# Sign release artifact
gpg --armor --detach-sign my-release.tar.gz

# Verify
gpg --verify my-release.tar.gz.asc my-release.tar.gz
```

#### Option B: Sigstore (Recommended)

```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Sign (keyless - uses OIDC)
cosign sign-blob my-release.tar.gz --bundle my-release.tar.gz.bundle

# Verify
cosign verify-blob my-release.tar.gz --bundle my-release.tar.gz.bundle \
  --certificate-identity=you@example.com \
  --certificate-oidc-issuer=https://github.com/login/oauth
```

#### Option C: SLSA Provenance (Best)

See [SLSA Provenance Workflow](../../workflows/slsa-provenance.yml.template)

### 8. Remove Binary Artifacts

**Current Score Impact**: Binary-Artifacts check
**Effort**: Variable

1. Find binary files:
```bash
# Find potential binaries
find . -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.so" \
  -o -name "*.dylib" -o -name "*.a" -o -name "*.o" -o -name "*.jar" \
  -o -name "*.class" -o -name "*.pyc" \) -not -path "./.git/*"
```

2. Remove from git history (if needed):
```bash
# Remove file from history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/binary" \
  --prune-empty --tag-name-filter cat -- --all
```

3. Add to `.gitignore`:
```gitignore
# Binaries
*.exe
*.dll
*.so
*.dylib
*.a
*.o
*.jar
*.class
*.pyc
__pycache__/

# Build output
dist/
build/
out/
```

4. Build binaries in CI instead:
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: dist/
```

### 9. Fix Dangerous Workflows

**Current Score Impact**: Dangerous-Workflow check
**Effort**: 30 minutes - 2 hours

**Pattern to avoid**: `pull_request_target` with checkout of untrusted code

Dangerous:
```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install  # DANGER: Runs untrusted code with write token
```

Safe alternatives:

**A. Use `pull_request` instead (no write access)**:
```yaml
on: pull_request
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm install && npm test  # Safe: read-only token
```

**B. Separate trusted and untrusted jobs**:
```yaml
on: pull_request_target

jobs:
  # Job 1: Only uses trusted code
  label:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/labeler@v5  # Uses repo code, not PR code

  # Job 2: Build in restricted environment
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      # Only read-only operations here
```

**C. Use workflow_run for post-PR actions**:
```yaml
# .github/workflows/ci.yml
on: pull_request
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm test
      - uses: actions/upload-artifact@v4
        with:
          name: results
          path: results.json

# .github/workflows/comment.yml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  comment:
    if: github.event.workflow_run.conclusion == 'success'
    permissions:
      pull-requests: write
    steps:
      - uses: actions/download-artifact@v4
      # Now safe to comment on PR
```

---

## Comprehensive Remediation Workflow

Add this workflow to continuously monitor and improve your score:

```yaml
# .github/workflows/scorecard.yml
name: OpenSSF Scorecard

on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
  push:
    branches: [main]
  workflow_dispatch:

permissions: read-all

jobs:
  analysis:
    name: Scorecard Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
      actions: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Scorecard
        uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload to Security Tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Remediation Checklist

Use this checklist to track progress:

### Critical Priority
- [ ] Fix Dangerous-Workflow patterns
- [ ] Address known Vulnerabilities
- [ ] Enable Branch-Protection

### High Priority
- [ ] Add SECURITY.md (Security-Policy)
- [ ] Set Token-Permissions to read-all default
- [ ] Enable Code-Review requirements
- [ ] Add Signed-Releases
- [ ] Remove Binary-Artifacts

### Medium Priority
- [ ] Pin-Dependencies to hashes
- [ ] Enable SAST (CodeQL)
- [ ] Add CI-Tests workflow
- [ ] Configure Webhooks with secrets
- [ ] Add Fuzzing (if applicable)

### Low Priority
- [ ] Earn CII-Best-Practices badge
- [ ] Add LICENSE file
- [ ] Publish to package registry (Packaging)
- [ ] Grow Contributors base

---

## Monitoring Progress

Track your score over time:

1. **Scorecard Visualizer**: https://scorecard.dev/
2. **Security Tab**: View SARIF results in GitHub Security tab
3. **Badge**: Add score badge to README:

```markdown
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/OWNER/REPO/badge)](https://scorecard.dev/viewer/?uri=github.com/OWNER/REPO)
```
