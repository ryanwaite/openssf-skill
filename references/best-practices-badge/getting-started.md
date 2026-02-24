# OpenSSF Best Practices Badge

The OpenSSF Best Practices Badge (formerly CII Best Practices Badge) is a way for open source projects to self-certify that they follow security best practices. The badge is recognized by the OpenSSF Scorecard as one of its checks.

## Badge Levels

| Level | Requirements | Typical Effort |
|-------|-------------|----------------|
| **Passing** | 67 criteria | 1-3 hours for a well-maintained project |
| **Silver** | Passing + 22 additional criteria | Several hours to days (requires test coverage, static analysis) |
| **Gold** | Silver + 24 additional criteria | Significant investment (requires reproducible builds, crypto review) |

Most projects should aim for **Passing** first, then work toward **Silver**.

---

## Getting Started

### 1. Create Your Badge Entry

1. Go to [https://www.bestpractices.dev/](https://www.bestpractices.dev/)
2. Click **Get Your Badge Now!**
3. Log in with your GitHub account
4. Enter your project's GitHub URL
5. The tool auto-detects some criteria from your repository

### 2. Self-Certify Criteria

For each criterion, select one of:
- **Met** — your project meets this criterion
- **Unmet** — your project does not meet this criterion yet
- **N/A** — not applicable to your project
- **?** — you're unsure

Provide a brief justification or URL for each "Met" answer.

### 3. Display Your Badge

Once you achieve Passing (or higher), add the badge to your README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

Replace `XXXXX` with your project ID (shown on your badge page).

---

## Passing Level Criteria (Key Requirements)

### Basics

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Description** | Project has a clear description | README.md with project overview |
| **Project URL** | Publicly accessible project page | GitHub repository |
| **OSS License** | An approved OSS license | LICENSE file (MIT, Apache 2.0, etc.) |
| **Documentation** | Basic usage docs exist | README with installation and usage |
| **Interaction** | Way for users to interact | GitHub Issues enabled |

### Change Control

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Version control** | Source in version control | Git (GitHub, GitLab, etc.) |
| **Unique versioning** | Releases have unique IDs | Git tags or GitHub Releases |
| **Release notes** | Changes documented per release | CHANGELOG.md or GitHub Release notes |

### Reporting

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Bug reporting** | Public bug reporting process | GitHub Issues |
| **Vulnerability reporting** | Private vulnerability reporting | SECURITY.md with email or GitHub Security Advisories |

### Quality

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Working build** | Project can be built from source | Build instructions in README/docs |
| **Automated test suite** | Tests exist and are automated | Test framework + CI/CD |
| **New functionality tested** | Tests added for new features | Code review process / PR requirements |
| **Warning flags** | Compiler/linter warnings addressed | Linter configuration, CI checks |

### Security

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Secure development knowledge** | At least one developer knows secure practices | Self-attestation |
| **No unpatched vulnerabilities** (60 days) | Known high/critical CVEs patched within 60 days | Dependency scanning + timely updates |
| **Secure delivery** | Distribution via HTTPS or verified signatures | GitHub (HTTPS) or signed releases |

### Analysis

| Criterion | Requirement | How to Meet |
|-----------|-------------|-------------|
| **Static analysis** | Some form of static analysis applied | Linters, SAST tools (CodeQL, Semgrep) |
| **Dynamic analysis** (if applicable) | Dynamic testing for applicable projects | Fuzzing, DAST tools, or N/A for libraries |

---

## Silver Level (Additional Key Criteria)

| Criterion | Requirement |
|-----------|-------------|
| **DCO or CLA** | Contributors agree to a Developer Certificate of Origin or CLA |
| **Code review** | All changes reviewed before merge |
| **Test coverage 80%+** | At least 80% statement coverage |
| **Bus factor ≥ 2** | Multiple active contributors |
| **Signed releases** | Releases are cryptographically signed |
| **Hardened project site** | HTTPS, security headers, HSTS |

## Gold Level (Additional Key Criteria)

| Criterion | Requirement |
|-----------|-------------|
| **Reproducible builds** | Builds are independently reproducible |
| **Test coverage 90%+** | At least 90% branch coverage |
| **Crypto review** | Cryptographic implementations reviewed by an expert |
| **Bus factor ≥ 3** | Three or more active contributors |

---

## Quick Assessment Checklist

Use this to gauge your readiness for the Passing level before starting:

```
[ ] README.md with description, build instructions, usage
[ ] LICENSE file (approved OSS license)
[ ] SECURITY.md with vulnerability reporting process
[ ] CONTRIBUTING.md with contribution guidelines
[ ] Automated tests that run in CI
[ ] Static analysis (linter) running in CI
[ ] No known unpatched high/critical vulnerabilities
[ ] HTTPS distribution (GitHub provides this automatically)
[ ] Release notes or CHANGELOG for versions
[ ] Bug reporting mechanism (GitHub Issues)
```

If you can check all of these, you're likely ready to achieve **Passing** in under an hour.

---

## Common Pitfalls

1. **Skipping justifications** — Reviewers may question unsupported "Met" claims. Always add a brief note or URL.
2. **Ignoring "should" criteria** — Passing doesn't require all "should" items, but addressing them strengthens your badge.
3. **One-time certification** — The badge should be maintained. Re-verify periodically as your project evolves.
4. **Not displaying the badge** — Add it to your README so users and the Scorecard check can find it.

---

## Scorecard Integration

The OpenSSF Scorecard check **CII-Best-Practices** (being renamed to **OpenSSF Best Practices**) looks for your badge:

- **Score 0**: No badge entry found
- **Score 2**: Badge entry exists but not Passing
- **Score 5**: Passing badge
- **Score 7**: Silver badge
- **Score 10**: Gold badge

To link your badge to Scorecard, make sure:
1. The badge is for the **same repository** Scorecard is scanning
2. The badge URL is accessible (no private badges)

---

## References

- [OpenSSF Best Practices Badge](https://www.bestpractices.dev/)
- [Full Criteria (Passing)](https://www.bestpractices.dev/criteria/0)
- [Full Criteria (Silver)](https://www.bestpractices.dev/criteria/1)
- [Full Criteria (Gold)](https://www.bestpractices.dev/criteria/2)
- [Badge FAQ](https://www.bestpractices.dev/criteria)
- [OpenSSF Scorecard CII-Best-Practices Check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#cii-best-practices)
