# OpenSSF Security Skill for Claude Code

A comprehensive Claude Code skill that helps developers build secure applications following [OpenSSF (Open Source Security Foundation)](https://openssf.org/) best practices.

## Features

- **Threat Modeling**: STRIDE methodology guide with templates
- **Security Policies**: SECURITY.md and vulnerability disclosure templates
- **OpenSSF Scorecard**: All 20 checks explained with remediation steps
- **OSPS Baseline**: Level 1 compliance checklist
- **SBOM Generation**: Tools for 12+ languages/ecosystems
- **SLSA Provenance**: GitHub Actions workflows for Level 3
- **Dependency Security**: Scanning tools and vulnerability response
- **Security Code Review**: OWASP Top 10 focused review guide

## Installation

### Option 1: Clone to Global Skills (Recommended)

```bash
# Clone directly to your global skills directory
git clone https://github.com/YOUR_USERNAME/openssf-skill.git ~/.claude/skills/openssf
```

### Option 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/openssf-skill.git

# Copy to your global skills directory
cp -r openssf-skill ~/.claude/skills/openssf
```

### Option 3: Project-Specific Installation

```bash
# Clone into your project's .claude/skills directory
mkdir -p .claude/skills
git clone https://github.com/YOUR_USERNAME/openssf-skill.git .claude/skills/openssf
```

## Usage

Once installed, invoke the skill in any project:

```
/openssf
```

The skill will:
1. Assess your project's current security posture
2. Detect languages and existing security artifacts
3. Recommend prioritized security improvements
4. Guide you through creating security artifacts

### Example Tasks

- "Help me create a threat model for my authentication system"
- "Generate a SECURITY.md for this project"
- "What OpenSSF Scorecard checks am I failing?"
- "Set up SBOM generation for my releases"
- "Review this code for security issues"

## Skill Structure

```
openssf/
├── SKILL.md                    # Main skill instructions
├── scripts/
│   └── assess-project.py       # Project security assessment
├── templates/
│   ├── SECURITY.md.template
│   ├── threat-model.md.template
│   └── vulnerability-disclosure-policy.md.template
├── workflows/
│   ├── scorecard.yml.template
│   ├── slsa-provenance.yml.template
│   ├── sbom-generation.yml.template
│   └── dependency-review.yml.template
└── references/
    ├── threat-modeling/        # STRIDE methodology
    ├── scorecard/              # All 20 checks + remediation
    ├── osps-baseline/          # Compliance checklists
    ├── sbom/                   # Language-specific tools
    ├── slsa/                   # Supply chain security
    ├── dependency-security/    # Vulnerability scanning
    ├── security-policies/      # Policy creation guides
    ├── security-requirements/  # Requirements checklist
    └── code-review/            # Security review guide
```

## Security Topics Covered

| Topic | Description |
|-------|-------------|
| Threat Modeling | STRIDE methodology, DFD creation, risk assessment |
| Security Policies | SECURITY.md, vulnerability disclosure, response timelines |
| OpenSSF Scorecard | 20 automated security checks with remediation |
| OSPS Baseline | Level 1-3 compliance requirements |
| SBOM | CycloneDX/SPDX generation for all major languages |
| SLSA | Supply chain security levels 1-4 |
| Dependencies | Vulnerability scanning, update strategies |
| Code Review | OWASP Top 10, language-specific patterns |

## Requirements

- [Claude Code CLI](https://claude.ai/code) installed
- Git (for cloning)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Areas for Contribution

- Additional language-specific security guides
- More workflow templates (GitLab CI, CircleCI, etc.)
- Translations
- Additional threat modeling methodologies

## License

MIT License - see [LICENSE](LICENSE) for details.

## References

- [OpenSSF Best Practices](https://best.openssf.org/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [SLSA Framework](https://slsa.dev/)
- [OSPS Baseline](https://baseline.openssf.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Acknowledgments

Built following OpenSSF guidelines and recommendations for secure software development.
