# Dependency Security Scanning Tools

This guide covers tools for identifying vulnerabilities in project dependencies across different languages and ecosystems.

## Overview

Dependency vulnerabilities are a major attack vector. Regular scanning helps:
- Identify known vulnerabilities (CVEs)
- Track transitive dependencies
- Prioritize updates by severity
- Meet compliance requirements

---

## Universal Scanners

### OSV-Scanner (Recommended)

Google's open-source vulnerability scanner using the OSV database. Start with
one local scan of your existing lockfiles; no GitHub integration or image
registry is needed. OSV-Scanner v2.7.1 publishes binaries on its
[releases page](https://github.com/google/osv-scanner/releases/tag/v2.7.1).
For source installs, the published [installation guide](https://github.com/google/osv-scanner/blob/v2.7.1/docs/installation.md)
says Go 1.26.2+, but the v2.7.1 `go.mod` declares **Go 1.27.3**; use 1.27.3+
or the prebuilt binary, and check prerequisites for the selected release.

```bash
# Optional source install (Go 1.27.3+ for v2.7.1)
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1

# Or use a packaged binary on macOS (check installed version)
brew install osv-scanner

# Scan existing lockfiles and SBOMs in this directory (source is the default mode)
osv-scanner scan source --recursive .

# Scan specific lockfile
osv-scanner scan source --lockfile=package-lock.json

# Output as JSON
osv-scanner scan source --recursive --format=json --output-file=vulnerabilities.json .

# Scan an SPDX SBOM: the filename must end in .spdx.json (or another recognized SPDX suffix)
osv-scanner scan source --lockfile=sbom.spdx.json

# Image scanning is separate and optional; it may require Docker/registry access
osv-scanner scan image myapp:1.0.0
# Or scan a previously exported Docker archive without Docker
osv-scanner scan image --archive ./myapp.tar
```

**Scope and safety**: v2 automatically scans named SPDX files (`*.spdx.json`,
`*.spdx`, `*.spdx.yml`, `*.spdx.rdf`, `*.spdx.rdf.xml`) and CycloneDX files
(`bom.json`, `*.cdx.json`, `bom.xml`, `*.cdx.xml`). It skips the root Git
repository by default; opt in with `--include-git-root`. Go call analysis is
enabled by default and requires Go; add `--no-call-analysis=go` for untrusted
or toolchain-free scans. Rust call analysis is experimental and executes
dependency `build.rs` scripts; enable it only with explicit approval in an
isolated environment, never on untrusted consume targets by default.
`--offline-vulnerabilities` (with a previously downloaded database) and
`--licenses` are optional; see the [v2 usage guide](https://github.com/google/osv-scanner/blob/v2.7.1/docs/usage.md).
An execution failure is not a clean vulnerability result.

### Trivy

Comprehensive scanner for containers, filesystems, and git repositories.

```bash
# Install
brew install trivy

# Scan filesystem
trivy fs .

# Scan with severity filter
trivy fs --severity HIGH,CRITICAL .

# Output as JSON
trivy fs --format json --output results.json .

# Scan container image
trivy image myapp:latest

# Scan git repository
trivy repo https://github.com/owner/repo
```

### Grype

Anchore's vulnerability scanner.

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan directory
grype dir:.

# Scan container
grype myimage:latest

# Scan SBOM
grype sbom:./sbom.spdx.json
```

### Snyk

Commercial tool with free tier.

```bash
# Install
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor continuously
snyk monitor

# Fix vulnerabilities
snyk fix
```

---

## Language-Specific Tools

### JavaScript / Node.js

#### npm audit (built-in)
```bash
# Check for vulnerabilities
npm audit

# Get JSON output
npm audit --json

# Attempt automatic fixes
npm audit fix

# Force fixes (may have breaking changes)
npm audit fix --force

# Production only
npm audit --omit=dev
```

#### yarn audit
```bash
yarn audit
yarn audit --json
```

#### pnpm audit
```bash
pnpm audit
pnpm audit --fix
```

---

### Python

#### pip-audit
```bash
# Install
pip install pip-audit

# Scan installed packages
pip-audit

# Scan requirements file
pip-audit -r requirements.txt

# Output formats
pip-audit --format json > audit.json
# For an SBOM, generate SPDX with syft (see references/sbom): syft . -o spdx-json > sbom.spdx.json

# Fix vulnerabilities
pip-audit --fix
```

#### Safety
```bash
pip install safety

# Scan
safety check

# Scan requirements file
safety check -r requirements.txt

# JSON output
safety check --json
```

#### Bandit (SAST for Python)
```bash
pip install bandit

# Scan for security issues in code
bandit -r ./src
```

---

### Go

#### govulncheck (Official)
```bash
# Install
go install golang.org/x/vuln/cmd/govulncheck@latest

# Scan module
govulncheck ./...

# Scan binary
govulncheck -mode=binary ./myapp

# JSON output
govulncheck -json ./...
```

#### nancy
```bash
# Install
go install github.com/sonatype-nexus-community/nancy@latest

# Scan
go list -json -deps ./... | nancy sleuth
```

---

### Rust

#### cargo audit
```bash
# Install
cargo install cargo-audit

# Scan
cargo audit

# Fix vulnerabilities
cargo audit fix

# JSON output
cargo audit --json
```

#### cargo deny
```bash
cargo install cargo-deny

# Check licenses and vulnerabilities
cargo deny check
```

---

### Java / Maven

#### OWASP Dependency-Check
```xml
<!-- Add to pom.xml -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>11.1.1</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

```bash
mvn dependency-check:check
```

#### Maven Versions Plugin
```bash
# Check for updates
mvn versions:display-dependency-updates

# Update to latest versions
mvn versions:use-latest-versions
```

---

### Java / Gradle

```groovy
// build.gradle
plugins {
    id 'org.owasp.dependencycheck' version '11.1.1'
}

dependencyCheck {
    failBuildOnCVSS = 7
}
```

```bash
./gradlew dependencyCheckAnalyze
```

---

### .NET

#### dotnet list package
```bash
# List vulnerable packages
dotnet list package --vulnerable

# Include transitive
dotnet list package --vulnerable --include-transitive

# Check outdated
dotnet list package --outdated
```

#### NuGet Audit
```bash
# Enable in project file
<NuGetAudit>true</NuGetAudit>

# Run restore to trigger audit
dotnet restore
```

---

### Ruby

#### bundler-audit
```bash
# Install
gem install bundler-audit

# Update advisory database
bundle-audit update

# Scan
bundle-audit check

# Scan with Gemfile.lock path
bundle-audit check --gemfile-lock=./Gemfile.lock
```

---

### PHP

#### Composer Audit
```bash
# Built into Composer 2.4+
composer audit

# JSON output
composer audit --format=json
```

#### Local PHP Security Checker
```bash
# Install
composer global require enlightn/security-checker

# Scan
security-checker security:check composer.lock
```

---

## CI/CD Integration

### GitHub Actions with OSV-Scanner

Optional: use OSV independently of GitHub Dependency Review. The latest
published action workflow at this update is **v2.7.0** (the scanner itself is
v2.7.1); the scanner's v2.7.1 docs reference a nonexistent action v2.7.1 tag.
These are **job-level reusable workflows**, not a `uses` step. Full scans
block on findings; set `fail-on-vuln: false` to make findings advisory without
suppressing scanner errors. Set `upload-sarif: false` if Code Scanning is
unavailable or the PR is from a fork without write permissions. The PR workflow
reports *new* findings; the full workflow reports *all* findings.

```yaml
name: Dependency Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  merge_group:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'

permissions:
  contents: read
  actions: read
  security-events: write

jobs:
  scan-pr:
    if: github.event_name == 'pull_request'
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@b1d267aea5211fa648d9d442fa64b90dbdcbdd36 # v2.7.0
    with:
      fail-on-vuln: true
      upload-sarif: ${{ github.event.pull_request.head.repo.full_name == github.repository }}
      scan-args: |-
        --no-call-analysis=go
        --recursive
        ./

  scan-full:
    if: github.event_name != 'pull_request'
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@b1d267aea5211fa648d9d442fa64b90dbdcbdd36 # v2.7.0
    with:
      fail-on-vuln: true
      upload-sarif: true
      scan-args: |-
        --no-call-analysis=go
        --recursive
        ./
```

The PR diff workflow checks out the base and head and needs a full Git history;
do not use it as a `merge_group` job (which has no PR base ref). The full job
handles merge queues. If Code Scanning is unavailable, disable SARIF upload on
**both** jobs and reduce their `security-events` permission as supported by
your runner. Fork PRs do not receive write tokens. Both official reusable
workflows upload short-lived artifacts even when SARIF upload is disabled;
check their retention and your repository's data policy before enabling them.
For a GitHub-only minimal start, use
[Dependency Review](../../workflows/dependency-review.yml.template) alone.

### GitHub Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      production-dependencies:
        dependency-type: "production"
      development-dependencies:
        dependency-type: "development"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### GitHub Dependency Review

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review

on: pull_request

permissions:
  contents: read

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0
        with:
          fail-on-severity: moderate
```

This PR-only action needs the dependency graph/API (public repositories or
licensed private repositories); v5 requires Actions Runner **2.327.1+** due
to Node 24. PR comments are optional and require `pull-requests: write`,
which is usually unavailable for fork PRs. If your merge queue requires
a dependency check, use a separate full scan such as OSV's above.

---

## Vulnerability Response Process

### 1. Triage

When vulnerabilities are found:

| Severity | Response Time | Action |
|----------|--------------|--------|
| Critical | Immediate | Patch or mitigate within 24-48 hours |
| High | 1 week | Prioritize for next release |
| Medium | 1 month | Include in regular updates |
| Low | Next release | Batch with other updates |

### 2. Assess Impact

For each vulnerability:
- Is the vulnerable code path reachable?
- Is it exploitable in our context?
- What data/systems are at risk?

For an already available OSV-Scanner v2.7.1 JSON result, the optional offline
`scripts/vulnerability_evidence.py` API can retain evidence before per-package
advisories are flattened into alias groups. Call
`triage_osv_package(package, advisories, product=None, vex_documents=(),
trusted_authors=(), authenticated_authors=(), as_of=None, max_age_days=None,
reachability=None)` with one `results[].packages[].package` (`ecosystem`,
`name`, `version`, optional **versioned** `purl`) and that entry's raw
`vulnerabilities` array. The return value has `package`, `product`, and
`findings`; each finding has scoped `records` (source, aliases, withdrawn,
affected versions/ranges, package-specific fixes, version status, malicious
assertion), an aggregate `version_status`, `vex` contexts, and `reachability`.
Only exact listed versions and safe exact range event boundaries are classified;
other range comparisons, unsupported ecosystems, and uncertain coverage remain
unresolved. OSV `MAL-` reports are **not** by themselves proof of compromise:
the corpus also includes inconclusive typosquat, spam, obfuscation, and
withdrawn reports. A caller-normalized
`database_specific.malicious_activity: {"confirmed": true, "source": "analyst_review"}`
adds a *sourced assertion*, not independently verified compromise. No missing
CVSS becomes a default severity.

VEX input is a list of standalone [OpenVEX 0.2.0](https://github.com/openvex/spec/releases/tag/v0.2.0)
documents (not CSAF, CycloneDX, or encapsulated attestations). An explicit
`product` purl identifies the exact product; a matching package purl identifies
the component, and for a distinct product the statement must name that
component in `subcomponents`. Exact purl text, including version/qualifiers,
must match; only npm, PyPI, Go, crates.io and Maven purls have identity
cross-checking here. `trusted_authors` is an allowlist policy, **not** an
authentication mechanism. Supply `authenticated_authors` only from independent
caller-side verification of the document and its issuer, never from a document
field or user-provided claim. Without both, exact scope and a caller-selected
`max_age_days` freshness policy, even `not_affected` with a machine-readable
justification remains context only. A candidate still requires review: this
API does not suppress vulnerabilities or change scoring. Reachability defaults
to unknown; optional `{status, method}` uses `reachable`/`not_reachable`/
`unknown` and `manual_review`/`static_call_analysis`/`dynamic_observation`/
`not_assessed`. A negative analysis is not proof of unexploitable code.
No scanner, package install, build scripts, network, or optional Python
dependencies are required to triage already-available evidence.

### 3. Remediate

Options in order of preference:
1. **Update** to patched version
2. **Workaround** if no patch available
3. **Replace** dependency with alternative
4. **Accept risk** with documentation (last resort)

### 4. Verify

- Run scanner again after fix
- Test functionality still works
- Update SBOM

### 5. Document

- Record decision in security advisory
- Update changelog
- Notify users if needed

---

## Best Practices

1. **Scan regularly**: Daily or on every commit
2. **Fail builds on critical**: Set severity thresholds
3. **Keep dependencies minimal**: Fewer deps = smaller attack surface
4. **Pin versions**: Use lock files
5. **Monitor continuously**: Enable Dependabot/Renovate
6. **Update proactively**: Don't wait for vulnerabilities
7. **Review transitive deps**: They're often the problem
8. **Have a response plan**: Know who handles vulnerabilities

---

## References

- [OSV Database](https://osv.dev/)
- [NIST NVD](https://nvd.nist.gov/)
- [GitHub Advisory Database](https://github.com/advisories)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis)
- [OSV-Scanner v2 source, image, and GitHub workflows](https://github.com/google/osv-scanner/blob/v2.7.1/docs/usage.md)
