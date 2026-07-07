---
name: openssf-audit-produce
description: |
  Evaluate and harden a project YOU BUILD and ship — your own repos and the
  artifacts you release. Invoke for: "assess our repo's security posture",
  "harden our project before release", "are we OpenSSF/OSPS compliant",
  "security review of the code we own", "improve our supply-chain security".
  Produces an A–F posture grade using the ensemble risk model, PRODUCE
  weighting, plus a prioritized remediation roadmap you can act on.
---

# OpenSSF Produce-Mode Evaluation

You are evaluating a project the org **owns and ships**. Unlike consume mode,
you can recommend and directly apply fixes, generate artifacts from
`templates/`, and wire up `workflows/`.

## Signal battery (run all that apply)
1. **Secrets** — Gitleaks/TruffleHog over the working tree and git history.
   A verified live secret is a CRITICAL, stop-everything finding.
2. **Provenance & signing** — current SLSA level; are releases signed with
   Cosign? Set up keyless signing + provenance if missing.
3. **Code review & branch protection** — required reviews, protected default
   branch, CODEOWNERS.
4. **Project health** — OpenSSF Scorecard on your repo; fix failing checks.
5. **Known vulnerabilities** — OSV/audit on your dependency tree.
6. **Threat coverage** — is there a current STRIDE threat model covering trust
   boundaries? Create/update with `templates/threat-model.md.template`.
7. **Baseline** — OSPS Baseline L1 conformance; close gaps.

## Fuse and grade
Apply `ensemble/risk-model.md` with **PRODUCE weights** (secrets, provenance,
code review, and your own Scorecard dominate). Apply escalation rules — a live
secret forces an F until remediated.

Grades: **A** (≥90) · **B** (80–89) · **C** (70–79) · **D** (60–69) · **F**
(<60 or critical escalation).

## Report + roadmap
Use `ensemble/report-template.md`. The required-actions section is a
**remediation roadmap** with priority, effort, and time estimate per item, and
quick wins first. Offer to apply changes directly:
- Generate `SECURITY.md` from `templates/SECURITY.md.template`.
- Add `workflows/scorecard.yml.template`, `workflows/sbom-generation.yml.template`,
  `workflows/slsa-provenance.yml.template`, `workflows/dependency-review.yml.template`.
- Add a secrets pre-commit hook; enable branch protection.

Re-run the ensemble after fixes to show the grade improving — close the loop.
