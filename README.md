# OpenSSF Security Skill

A Claude Code / GitHub Copilot skill that helps developers build
secure applications following [OpenSSF (Open Source Security Foundation)](https://openssf.org/)
best practices — and evaluate open source projects as an **ensemble**.

**Supports both GitHub Copilot and Claude Code.**

> **Two modes, one skill:**
> - **Advisor** — *help me build or fix a specific control.* Threat models,
>   SECURITY.md, SBOM setup, Sigstore signing, Dockerfile hardening, secrets
>   pre-commit hooks, Scorecard workflows. Assess → recommend → implement.
> - **Audit** — *tell me how safe this is.* Run the OpenSSF tools **together**
>   and fuse the signals into one decision-ready verdict:
>   - **Consume:** *Is this dependency safe to adopt?* → **Adopt / Adopt-with-mitigations / Avoid**
>   - **Produce:** *Is the project we build trustworthy and hardened?* → **A–F posture grade + roadmap**

---

## Why two modes?

Sometimes you know exactly what you need — "generate a SECURITY.md," "set up
SBOM generation," "harden this Dockerfile." That's **advisor** mode: it assesses
your project, recommends prioritized next steps, and walks you through building
the artifact using the bundled references, templates, and workflows.

Other times you want a broader evidence-based assessment. Security tooling may
involve Scorecard, OSV-Scanner, secrets scanning and signing verification.
**Audit** mode fuses the available, applicable evidence:

```
        Scorecard ─┐
   OSV / audits ───┤
         SBOM ─────┤      applicable evidence → mode-specific weights   ┌─ Adopt / Avoid   (consume)
   signing/SLSA ───┼──►   → escalation → qualify incomplete results ──► │
       secrets ────┤            ensemble/risk-model.md                  └─ A–F grade       (produce)
   maintenance ────┘

  OSPS Baseline ─────► separate, unweighted conformance evidence
```

Audit modes have different applicable probes and weights. Missing evidence is
reported as a gap; an incomplete battery is not proof of safety. You can still
fix a specific issue without running the battery.

---

## Installation

### Full skill (router, advisor, audit, scripts, templates and references)

From the **target project's root**, choose *one* project location below (do
not clone into an existing nonempty `openssf` directory):

```bash
mkdir -p .github/skills
git clone https://github.com/ryanwaite/openssf-skill.git .github/skills/openssf
```

GitHub Copilot also accepts `.claude/skills/openssf` or
`.agents/skills/openssf` as project skills. For a **personal Copilot skill**,
clone into `~/.copilot/skills/openssf` or `~/.agents/skills/openssf` instead;
personal skills may not be available in every cloud surface. See the
[supported Copilot skill locations](https://docs.github.com/en/copilot/concepts/customizations/agent-skills).
For **Claude Code**, clone into `.claude/skills/openssf` (project) or
`~/.claude/skills/openssf` (personal). A personal installation is not needed
to begin; use the project copy if you don't want to change your home directory.

Each destination must contain `SKILL.md`, `scripts/`, `skills/`,
`references/`, `templates/`, `workflows/` and `ensemble/`. Select a trusted
revision before relying on its scripts or templates; cloning needs network
access and writes only to the chosen destination. Check local files without
any scanner or account setup:

```bash
python3 .github/skills/openssf/scripts/assess-project.py .
```

Substitute your chosen installed directory for `.github/skills/openssf`. When
you invoke `/openssf` or ask your agent for the `openssf` skill, the agent should
load **that installation's** `SKILL.md` and resolve its relative references,
templates, and scripts from the installed skill directory, **not** from your
target project's current working directory. Skill invocation syntax and
discovery vary by agent/surface. The target directory is always a separate
argument to the local detector or audit runner.

### Instructions-only Copilot (secure coding defaults, no bundled skill)

If you only want secure coding guidance, copy
[`copilot-instructions.md`](.github/copilot-instructions.md) into your
project's `.github/copilot-instructions.md`. This is **not** a full install:
it does not provide `/openssf`, router files, scripts, templates, or references.
It does not run scans. Use the full skill instructions above for those assets.

---

## Usage

The simplest way to get started after a full install:
1. Start GitHub Copilot or Claude Code
2. Open the target project
3. Ask the agent to use the `openssf` skill: "What is the most important
   security action I can take now?" (or `/openssf` where supported)

The router sends your request to the right mode.

### Advisor mode — build or fix a specific control

```
/openssf help me create a threat model for my authentication system
/openssf generate a SECURITY.md for this project
/openssf what OpenSSF Scorecard checks am I failing?
/openssf set up SBOM generation for my releases
/openssf review this code for security issues
```

The advisor can use local language/artifact inventory, recommend a first small
step, and help you create a specific artifact. **No scanner, GitHub feature,
account, SBOM, attestation, or complete audit is required to start.** For
example, write a private vulnerability reporting policy or triage a known
critical vulnerability right away; add automation only when useful.

```bash
python3 <installed-skill>/scripts/assess-project.py /path/to/target
```

The stdlib-only detector emits JSON. `readiness_score` measures **local file
presence**, not enforcement or a security verdict; the deprecated
`security_score` field retains the same numeric score, letter *readiness band*
(A at 80+), and counts for existing consumers. This is **not** the ensemble's
posture grade (A at 90+), an OSPS Baseline certification, or proof that
scanners/CI ran. `capabilities` distinguishes recognized local configuration
from unknown remote/default/centralized capabilities and unverified execution.
`critical_issues` is a legacy count of critical-priority recommendations (not
an incident count); this inventory cannot rule out live vulnerabilities. Start
with its small recommendations, then verify the highest-risk applicable facts
in context.

### Audit mode — get a verdict or grade

```
/openssf evaluate this repo
/openssf help evaluate a dependency with its resolved version and lockfile
/openssf grade our security posture before release
```

The agent establishes the mode (consume vs produce), collects available
evidence, and identifies gaps and concrete next actions. A favorable answer
with missing evidence must remain **provisional**, never a certification.

#### Run the ensemble directly

```bash
# Evaluate a local checkout using available tools
python3 <installed-skill>/scripts/ensemble-eval.py --target /path/to/target --mode consume

# Grade a repo you own
python3 <installed-skill>/scripts/ensemble-eval.py --target /path/to/target --mode produce --format md

# Save the available evidence, then replay it without invoking scanners
python3 <installed-skill>/scripts/ensemble-eval.py --target /path/to/target --mode produce --snapshot-out audit-snapshot.json
python3 <installed-skill>/scripts/ensemble-eval.py --replay audit-snapshot.json --format md
```

`INCOMPLETE` is useful, nonfatal output: the report retains available findings,
provisional results, gaps, and actions you can start now. For supported manual
observations, add `--evidence observations.json`; the
[audit evidence format](skills/audit/SKILL.md#manual-evidence-and-reproducibility)
binds observations to the requested target and mode and distinguishes manual
review from self-report. Importing evidence does not independently verify it.

Only run this broader evaluation when requested. Explicit local directories,
lockfiles/SPDX files, GitHub repositories with optional `@ref`, versioned purls,
`package@version --ecosystem <ecosystem>`, and OCI `@sha256:` references have
distinct target identities. A package coordinate or supplied image digest is
**not** proof that its bytes were fetched or scanned: remote acquisition and
package/image scanning remain unsupported by the source-scan adapter.
Check the report for unknown,
failed, or unsupported probes and corroborate externally before relying on a
verdict. The suite does **not** need to run to produce one useful advisor action.

### What is implemented vs. manual

| Capability | Current scope | Prerequisite for one advisor action? |
|------------|---------------|--------------------------------------|
| Local inventory and SECURITY.md/threat-model guidance | Implemented; stdlib inventory plus bundled templates | Python 3 for the detector; none for manual guidance |
| Scorecard, OSV and Gitleaks via audit runner | Structured Scorecard checks/revision gaps; local source or supported file OSV scans; redacted secrets scanning | No |
| Local repository metadata / CODEOWNERS | Partial indicators, not verified review enforcement | No |
| Local signature/provenance and SPDX evidence | Opt-in `--artifact-evidence`; established optional verifiers, explicit identities/digests, SPDX JSON 2.3 quality/scope; no automatic SLSA level or completeness claim | No |
| Baseline conformance | Optional `--baseline-evidence`; canonical versioned L1-L3 IDs and manual applicability, separate from numeric risk | No |
| Malicious-package/reachability/VEX context | Package-scoped advisory facts and optional `--vex-evidence`; no blind suppression or inferred issuer authentication | No |
| Threat coverage and effective forge controls | Manual evidence; local indicators do not prove enforcement | No |
| Manual evidence and offline replay | Versioned, target-bound observations and snapshots; imported claims are not independently verified | No |
| Remote repositories, packages, OCI images | Explicit reference/coordinate identity only; no automatic cloning, installation, image pulling, or artifact verification | No |

Custom risk **policy v2** removes Baseline from numeric scoring and renormalizes
the other weights without changing their relative importance. Previous
policy-v1 snapshots must use the matching implementation for replay; they are
not silently rescored. The [runtime evidence guide](skills/audit/SKILL.md#optional-target-bound-runtime-evidence)
documents the independent input formats and trust boundaries. Public artifact
verifier trust lookup requires `--allow-network-trust`; this is not needed for
local inventory, Baseline evidence, or inspecting an existing SPDX document.

Audit evidence can require optional scanners, a resolvable repository/lockfile,
forge permissions, and network access. The detector reads local files only;
the audit runner may call external CLIs and network services (Scorecard, OSV,
forge metadata). Check CLI configuration before running it: access tokens and
private repository data can be sent to those services. Never paste secrets into
prompts/reports; redact scanner findings and restrict any temporary outputs.
Sigstore keyless signing and public transparency logs may publish identity and
artifact metadata; verify identities/digests and obtain consent before
signing, publishing, or uploading. A tool not installed is a **gap for a
high-assurance verdict**, not a prerequisite to make progress.

---

## Example Walkthrough

This walkthrough demonstrates using the OpenSSF skill with GitHub Copilot to assess and improve the security posture of an open source repository.

### Step 1: Invoke the Skill

Start by invoking the OpenSSF skill in your project:

![Invoke OpenSSF Skill](docs/images/01-invoke-openssf-skill.png)

### What It Can Do

The skill looks at the project and provides an assessment of the overall project:

![Ask Capabilities](docs/images/02-ask-capabilities.png)

### Comprehensive List of Available Capabilities

The skill provides a comprehensive list of security features it can help with:

![Capabilities List](docs/images/03-capabilities-list.png)
![Scorecard Suggestion](docs/images/04-scorecard-suggestion.png)

### Recommendation for Next Steps

The skill provides a prioritized list of what to do next along with the approximate time to complete each activity:

![Run Scorecard](docs/images/05-run-scorecard.png)

### Step 2: Run Scorecard

In this walkthrough we go with the recommendation to start with running Scorecard:

![Scorecard Results](docs/images/06-scorecard-results.png)

### Scorecard Results

The skill spins up a container, runs the Scorecard analysis, and provides the results:

![Implement Improvements](docs/images/07-implement-improvements.png)

From here, you can use the skill to keep implementing changes.

---

## How it works

| Layer | File(s) | Role |
|-------|---------|------|
| **Router** | `SKILL.md`, `.github/copilot-instructions.md` | Sends the request to advisor or audit |
| **Advisor** | `skills/advisor/` | Assess → recommend → implement a specific control |
| **Audit orchestrator** | `skills/audit/` | Establishes consume/produce mode, runs the battery, produces the report |
| **Audit modes** | `skills/audit/consume/`, `skills/audit/produce/` | Mode-specific batteries and outputs |
| **Fusion engine** | `ensemble/risk-model.md` | Normalization, mode weights, escalation rules, outcome mapping |
| **Output spec** | `ensemble/report-template.md` | The decision-ready report format |
| **Runner** | `scripts/ensemble-eval.py` | Executes the audit ensemble, emits fused JSON/Markdown (degrades gracefully) |
| **Detector** | `scripts/assess-project.py` | Local inventory/readiness (not security posture) |
| **Grounding** | `references/` | Deep per-tool guidance both modes draw on |

### The verdict, in short (audit mode)

- **Mode sets applicable probes and weights.** Consume leans on known CVEs +
  maintenance; produce leans on secrets + provenance + code review.
- **Escalations override the average.** Verified active exposures need separate
  handling; do not infer a live secret or a fixable CRITICAL from file presence.
- **Unknown ≠ fine.** Missing data must qualify favorable claims.
- **Audit claims need evidence.** Verify probe status and weight math before
  treating a report as reproducible or actionable.

---

## Repository Structure

```
openssf-skill/
├── .github/
│   └── copilot-instructions.md   # GitHub Copilot instructions (router + secure-coding)
├── SKILL.md                      # Claude Code skill file — router: advisor | audit
├── skills/
│   ├── advisor/SKILL.md          # Build/fix a specific control (v1 guidance behavior)
│   └── audit/
│       ├── SKILL.md              # Ensemble orchestrator (establishes consume/produce)
│       ├── consume/SKILL.md      # Third-party OSS → Adopt / Adopt-with-mitigations / Avoid
│       └── produce/SKILL.md      # Projects you ship → A–F grade + roadmap
├── ensemble/
│   ├── risk-model.md             # Normalization, weights, escalation, outcome mapping
│   └── report-template.md        # Decision-ready report format
├── scripts/
│   ├── assess-project.py         # Project language/artifact detection
│   └── ensemble-eval.py          # Runs the audit ensemble, emits fused verdict
├── tests/
│   ├── test_assess_project.py    # Unit tests
│   └── test_ensemble_eval.py     # Fusion / risk-model tests
├── templates/
│   ├── SECURITY.md.template
│   ├── threat-model.md.template
│   └── vulnerability-disclosure-policy.md.template
├── workflows/
│   ├── scorecard.yml.template
│   ├── slsa-provenance.yml.template
│   ├── sbom-generation.yml.template
│   ├── dependency-review.yml.template
│   └── gitlab-ci-security.yml.template  # GitLab CI/CD
└── references/
    ├── threat-modeling/          # STRIDE methodology
    ├── scorecard/                # All 19 checks + remediation
    ├── osps-baseline/            # Compliance checklists
    ├── sbom/                     # Language-specific tools
    ├── slsa/                     # Supply chain security
    ├── dependency-security/      # Vulnerability scanning
    ├── security-policies/        # Policy creation guides
    ├── security-requirements/    # Requirements checklist
    ├── code-review/              # Security review guide
    ├── secrets-scanning/         # Secret leak prevention
    ├── signing/                  # Sigstore/Cosign guide
    ├── container-security/       # Docker hardening
    └── best-practices-badge/     # OpenSSF Badge guide
```

---

## Security Topics Covered

| Topic | Description |
|-------|-------------|
| Threat Modeling | STRIDE methodology, DFD creation, risk assessment |
| Security Policies | SECURITY.md, vulnerability disclosure, response timelines |
| OpenSSF Scorecard | 19 automated security checks with remediation |
| OSPS Baseline | Versioned L1-L3 conformance guidance; no official numeric grade |
| SBOM | SPDX generation (default) for all major languages |
| SLSA | Build and Source tracks (v1.2); attestations alone do not prove Build L3 |
| Dependencies | Vulnerability scanning, update strategies |
| Code Review | OWASP Top 10, language-specific patterns |
| Secrets Scanning | Gitleaks, TruffleHog, detect-secrets, pre-commit hooks |
| Artifact Signing | Sigstore ecosystem: Cosign, Fulcio, Rekor, Gitsign |
| Container Security | Dockerfile hardening, image scanning, distroless bases |
| Best Practices Badge | OpenSSF Badge self-certification (Passing/Silver/Gold) |

---

## Requirements

| Tool | Required For |
|------|--------------|
| [GitHub Copilot](https://github.com/features/copilot) | Copilot instructions |
| [Claude Code](https://claude.com/product/claude-code) | Claude Code skill |
| Git/network access | Cloning the full skill (not required for local manual guidance) |
| Python 3 | Running the detector or audit runner; optional CLIs depend on probe |

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines, content standards, and testing instructions.

Quick start:
1. Fork the repository
2. Create a feature branch
3. Make your changes (run `python3 -m unittest discover tests/ -v` to validate)
4. Submit a pull request

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
