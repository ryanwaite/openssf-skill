# OpenSSF Security Instructions for AI Coding Assistants

A comprehensive set of security instructions and resources that help developers build secure applications following [OpenSSF (Open Source Security Foundation)](https://openssf.org/) best practices.

**Supports both Claude Code and GitHub Copilot.**

## Features

- **Threat Modeling**: STRIDE methodology guide with templates
- **Security Policies**: SECURITY.md and vulnerability disclosure templates
- **OpenSSF Scorecard**: All 20 checks explained with remediation steps
- **OSPS Baseline**: Level 1 compliance checklist
- **SBOM Generation**: Tools for 12+ languages/ecosystems
- **SLSA Provenance**: GitHub Actions workflows for Level 3
- **Dependency Security**: Scanning tools and vulnerability response
- **Security Code Review**: OWASP Top 10 focused review guide

---

## Installation

### For GitHub Copilot

Copy the Copilot instructions file to your repository:

```bash
# Create .github directory if it doesn't exist
mkdir -p .github

# Download the instructions file
curl -o .github/copilot-instructions.md \
  https://raw.githubusercontent.com/ryanwaite/openssf-skill/main/.github/copilot-instructions.md
```

Then enable custom instructions in VS Code:
1. Open Settings (`Cmd+,` or `Ctrl+,`)
2. Search for "Copilot instruction"
3. Enable `github.copilot.chat.codeGeneration.useInstructionFiles`

Copilot will now apply OpenSSF security best practices to all code suggestions in that repository.

### For Claude Code

#### Option 1: Clone to Global Skills (Recommended)

```bash
# Clone directly to your global skills directory
git clone https://github.com/ryanwaite/openssf-skill.git ~/.claude/skills/openssf
```

#### Option 2: Project-Specific Installation

```bash
# Clone into your project's .claude/skills directory
mkdir -p .claude/skills
git clone https://github.com/ryanwaite/openssf-skill.git .claude/skills/openssf
```

Then invoke the skill in any project with `/openssf`.

---

## Usage

The most simple way to get started is:
1. Start GitHub Copilot or Claude Code
2. cd to the root of an open source project
3. Run `/openssf what can you do for me?`

Additional options are below.

### Additional options

Invoke the skill with `/openssf`, then:
- "Help me create a threat model for my authentication system"
- "Generate a SECURITY.md for this project"
- "What OpenSSF Scorecard checks am I failing?"
- "Set up SBOM generation for my releases"
- "Review this code for security issues"

The skill will:
1. Assess your project's current security posture
2. Detect languages and existing security artifacts
3. Recommend prioritized security improvements
4. Guide you through creating security artifacts

---

## Repository Structure

```
openssf-skill/
├── .github/
│   └── copilot-instructions.md  # GitHub Copilot instructions
├── SKILL.md                      # Claude Code skill file
├── scripts/
│   └── assess-project.py         # Project security assessment
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
    ├── threat-modeling/          # STRIDE methodology
    ├── scorecard/                # All 20 checks + remediation
    ├── osps-baseline/            # Compliance checklists
    ├── sbom/                     # Language-specific tools
    ├── slsa/                     # Supply chain security
    ├── dependency-security/      # Vulnerability scanning
    ├── security-policies/        # Policy creation guides
    ├── security-requirements/    # Requirements checklist
    └── code-review/              # Security review guide
```

---

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

---

## Requirements

| Tool | Required For |
|------|--------------|
| [GitHub Copilot](https://github.com/features/copilot) | Copilot instructions |
| [Claude Code](https://claude.com/product/claude-code) | Claude Code skill |
| Git | Cloning the repository |

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Areas for Contribution

- Additional language-specific security guides
- More workflow templates (GitLab CI, CircleCI, etc.)
- Copilot instruction improvements
- Additional threat modeling methodologies

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## References

- [OpenSSF Best Practices](https://best.openssf.org/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [SLSA Framework](https://slsa.dev/)
- [OSPS Baseline](https://baseline.openssf.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GitHub Copilot Custom Instructions](https://docs.github.com/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot)

---

## Acknowledgments

Built following OpenSSF guidelines and recommendations for secure software development.
