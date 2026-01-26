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

Google's open-source vulnerability scanner using the OSV database.

```bash
# Install
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Or via package managers
brew install osv-scanner

# Scan current directory
osv-scanner -r .

# Scan specific lockfile
osv-scanner --lockfile=package-lock.json

# Output as JSON
osv-scanner -r . --format json > vulnerabilities.json

# Scan SBOM
osv-scanner --sbom=sbom.cyclonedx.json

# Experimental: fix suggestions
osv-scanner fix --non-interactive --strategy=in-place -L package-lock.json
```

**Supported ecosystems**: npm, pip, cargo, go, maven, gradle, nuget, composer, gem, pub, and more.

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
grype sbom:./sbom.cyclonedx.json
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
pip-audit --format cyclonedx-json > sbom.json

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
    <version>9.0.9</version>
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
    id 'org.owasp.dependencycheck' version '9.0.9'
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

```yaml
name: Dependency Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run OSV-Scanner
        uses: google/osv-scanner-action@v1
        with:
          scan-args: |-
            --recursive
            --format=sarif
            --output=osv-results.sarif
            .

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: osv-results.sarif
```

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
  pull-requests: write

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0
```

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
