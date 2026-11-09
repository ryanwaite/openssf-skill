# Secrets Scanning & Detection

Leaked secrets (API keys, passwords, tokens, private keys) are one of the most common and impactful security incidents. This guide covers tools and practices for preventing, detecting, and responding to secret leaks.

**Start now:** run `gitleaks git --redact .` in your repository to check
committed history, or `gitleaks dir --redact .` to check the current files.
The second command includes uncommitted files but not history. Neither
requires enabling a hosted integration or another scanner. Treat a scanner
error as *unknown*, not as a clean scan. A pattern match is not proof that
a credential still works; do not make automated liveness requests to test it.

## Why Secrets Scanning Matters

- **Automated bots** scan public GitHub commits within seconds of exposure
- A leaked AWS key can result in **thousands of dollars** in unauthorized charges within minutes
- Git history preserves secrets **permanently** unless explicitly rewritten
- Over 10 million secrets are detected on GitHub annually

---

## Prevention: Pre-commit Hooks

The best defense is preventing secrets from ever entering version control.

### Gitleaks (Pre-commit)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

Install and run (this staged hook is the simpler starting point; the optional
TruffleHog filesystem hook below scans current files, including unstaged ones):

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run against all files (initial scan)
pre-commit run gitleaks --all-files
```

### detect-secrets (Yelp)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

Create baseline (marks existing false positives):

```bash
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline
```

### TruffleHog (Pre-commit)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.82.13
    hooks:
      - id: trufflehog
        entry: trufflehog filesystem --no-verification --fail .
        pass_filenames: false
```

---

## Detection: CI/CD Integration

### GitHub Secret Scanning

GitHub's built-in secret scanning is available for:
- **Public repositories**: Free, automatic
- **Private repositories**: Check your plan and security feature availability

Enable in repository settings:
1. Go to **Settings → Code security and analysis**
2. Enable **Secret scanning**
3. Enable **Push protection** (blocks pushes containing secrets)

#### Custom Patterns

Define organization-specific secret patterns:

```
# Settings → Code security → Secret scanning → Custom patterns
Pattern name: Internal API Key
Secret format: MYORG_[A-Z0-9]{32}
```

### Gitleaks in CI

```yaml
# .github/workflows/gitleaks.yml
name: Gitleaks
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # For GitHub organizations only: configure the action license as a secret.
          # GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

The official action requires `GITLEAKS_LICENSE` for GitHub organizations,
not personal accounts. If an action license is unavailable, install the OSS
CLI and run `gitleaks git --redact .` instead. Scan full history with
`fetch-depth: 0`; scope a PR range deliberately if a full scan is too costly.
Do not upload unredacted findings as public artifacts.

### TruffleHog in CI

```yaml
# .github/workflows/trufflehog.yml
name: TruffleHog Secrets Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - name: TruffleHog scan
        uses: trufflesecurity/trufflehog@1aa1871f9ae24a8c8a3a48a9345514acf42beb39 # v3.82.13
        with:
          version: '3.82.13' # the action otherwise pulls a mutable :latest image
          extra_args: --no-verification
```

TruffleHog verifies credentials by default, which may contact their providers.
`--no-verification` disables those checks; simply removing `--only-verified`
does **not** disable them. Run verification only with explicit authorization
and appropriate isolation. TruffleHog can print raw findings: restrict CI log
access and redact before sharing.

### GitLab CI

```yaml
# .gitlab-ci.yml
secrets-scanning:
  stage: test
  image:
    name: ghcr.io/gitleaks/gitleaks:v8.30.1
    entrypoint: [""]
  variables:
    GIT_DEPTH: "0"
  script:
    - gitleaks git --redact .
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Tool Comparison

| Feature | Gitleaks | TruffleHog | detect-secrets | GitHub Secret Scanning |
|---------|----------|------------|----------------|----------------------|
| **Type** | Regex + entropy | Regex + verification | Regex + entropy | Cloud service |
| **Verified results** | No | Optional provider checks (requires approval) | No | Some partner alerts |
| **Pre-commit** | Yes | Yes | Yes | No (push protection only) |
| **CI/CD** | Yes | Yes | Yes | Automatic |
| **Custom rules** | Yes (.gitleaks.toml) | Yes (custom detectors) | Yes (plugins) | Yes (custom patterns) |
| **Git history scan** | Yes | Yes | No (file scan by default) | Yes |
| **Language** | Go | Go | Python | Cloud |
| **Cost** | Free (OSS) | Free (OSS) | Free (OSS) | Free public / GHAS private |
| **Speed** | Fast | Moderate | Moderate | N/A |

---

## Configuration

### Gitleaks Configuration (.gitleaks.toml)

```toml
# .gitleaks.toml
title = "Gitleaks Configuration"

[extend]
useDefault = true

# Custom rules supplement built-in rules rather than replacing them.
[[rules]]
id = "internal-api-key"
description = "Internal API Key"
regex = '''MYORG_[A-Za-z0-9]{32}'''
tags = ["key", "internal"]

```

Avoid broad global path or regex allowlists: they can suppress actual
credentials. Use a narrowly scoped, reviewed
[`[[rules.allowlists]]`](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#configuration)
for demonstrated false positives, and re-scan after changing it.

### TruffleHog Configuration

```bash
# Scan current repo
trufflehog git file://. --no-verification

# Scanning a GitHub organization or verifying credential liveness requires
# explicit authorization; do not run it automatically on untrusted sources.

# Exclude paths
trufflehog git file://. --no-verification --exclude-paths=exclude.txt
```

TruffleHog may print secret values; do not dump JSON findings into shared logs
or artifacts. Restrict CI log access and redact findings before sharing.

```text
# exclude.txt
test/fixtures/
docs/examples/
*.md
```

---

## Response: When Secrets Are Leaked

### Immediate Actions (Within Minutes)

1. **Revoke the secret immediately** — do not wait for the PR to merge
   ```bash
   # Example: Rotate AWS keys
   aws iam create-access-key --user-name myuser
   aws iam delete-access-key --user-name myuser --access-key-id AKIA...
   ```

2. **Check for unauthorized usage**
   - Review cloud provider audit logs (AWS CloudTrail, GCP Audit Logs, Azure Activity Log)
   - Check API provider dashboards for unexpected activity

3. **Remove from Git history** (if the repo is public)
   ```bash
   # Using git-filter-repo (recommended over git filter-branch)
   pip install git-filter-repo

   # Remove a specific file from all history
   git filter-repo --path secrets.env --invert-paths

   # Replace a specific string in all history
   git filter-repo --replace-text expressions.txt
   ```

   ```text
   # expressions.txt
   AKIAIOSFODNN7EXAMPLE==>***REDACTED***
   ```

4. **Force push** the cleaned history
   ```bash
   git push --force --all
   git push --force --tags
   ```

### Post-Incident

5. **Audit** — determine what damage occurred during the exposure window
6. **Document** — record the incident, timeline, and response
7. **Prevent recurrence** — install pre-commit hooks, enable push protection

---

## Secret Types to Detect

| Category | Examples | Risk |
|----------|----------|------|
| **Cloud Provider Keys** | AWS Access Keys, GCP Service Account JSON, Azure Client Secrets | Critical — full cloud access |
| **API Keys** | Stripe, Twilio, SendGrid, GitHub PATs, Slack tokens | High — service abuse, data access |
| **Database Credentials** | Connection strings, passwords in config | Critical — data breach |
| **Private Keys** | SSH keys, TLS/SSL certificates, PGP keys | Critical — impersonation |
| **OAuth Secrets** | Client secrets, refresh tokens | High — account takeover |
| **Internal URLs** | Internal API endpoints, admin panels | Medium — reconnaissance |
| **Encryption Keys** | AES keys, JWT signing secrets, HMAC keys | Critical — data decryption |

---

## Best Practices

### Do

- **Use environment variables** or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, GCP Secret Manager)
- **Use `.env` files** for local development and **add `.env` to `.gitignore`**
- **Provide `.env.example`** with placeholder values for documentation
- **Rotate secrets regularly** — automate rotation where possible
- **Use short-lived credentials** (OIDC federation, temporary tokens) over long-lived keys
- **Enable GitHub push protection** on all repositories
- **Run pre-commit hooks** on every developer machine
- **Scan the full Git history** and the current files when both scopes matter

### Don't

- **Never hardcode secrets** in source code, config files, or environment definitions
- **Never commit `.env` files** — add to `.gitignore` immediately
- **Never log secrets** — mask them in CI output and application logs
- **Never share secrets** via chat, email, or ticketing systems
- **Never use the same secret** across environments (dev/staging/production)
- **Never assume** a private repo is safe — access controls change, forks happen

---

## .gitignore Entries for Secrets

```gitignore
# Environment files
.env
.env.local
.env.*.local
.env.production
.env.staging

# Private keys
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519

# Cloud provider credentials
.aws/credentials
.azure/
gcp-credentials.json
service-account*.json

# IDE and local config that may contain secrets
.idea/
.vscode/settings.json

# Secrets baseline (if using detect-secrets)
# Note: .secrets.baseline should be committed — it tracks known false positives
```

---

## References

- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Gitleaks v8.30.1 commands and configuration](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#usage)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [GitHub Push Protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
