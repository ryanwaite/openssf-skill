---
name: openssf-audit-consume
description: |
  Evaluate third-party open source you ADOPT or DEPEND ON — libraries,
  packages, container images, and upstream repositories you do not control.
  Invoke for: "is <package> safe to use", "should we add this dependency",
  "vet this library before we adopt it", "supply-chain risk of <repo>",
  "review our dependencies for risk". Produces an Adopt / Adopt-with-mitigations
  / Avoid verdict using the ensemble risk model, CONSUME weighting.
---

# OpenSSF Consume-Mode Evaluation

You are evaluating software the org **brings in** but does **not own**. You
cannot change the upstream repo — you can only observe signals and recommend
**compensating controls** the org applies on its own side.

## What you can and cannot do
- ✅ Observe: Scorecard, known CVEs, maintenance, signing, SBOM, transitive risk.
- ✅ Recommend: version pinning, mirroring/vendoring, monitoring, sandboxing,
  policy gates in CI, choosing an alternative.
- ❌ Do NOT propose "add a SECURITY.md to their repo" — you don't own it. Those
  are signals you *read*, not changes you make.

## Signal battery (run all that apply)
1. **Known vulnerabilities** — OSV-Scanner against the exact version(s); language
   audit tools for the resolved tree. Note fix availability per CVE.
2. **Maintenance** — last release, commit recency, maintainer count / bus factor,
   open-CVE backlog, archived/EOL status.
3. **Supply chain** — generate/inspect an SBOM; assess transitive blast radius;
   check for typosquat/abandoned transitive deps.
4. **Provenance & signing** — are releases signed (Cosign/Sigstore)? SLSA level?
   Can you verify the artifact you'd actually pull?
5. **Project health** — OpenSSF Scorecard on the source repo.
6. **Baseline** — OSPS Baseline L1 as a maturity yardstick (informational).

## Fuse and decide
Apply `ensemble/risk-model.md` with **CONSUME weights** (vulns + maintenance
dominate). Apply escalation rules — an unpatched CRITICAL with a fix, or an
archived critical dependency, caps the verdict regardless of other strengths.

With complete weighted evidence: **Adopt** (≥80) · **Adopt with mitigations**
(55–79) · **Avoid** (<55 or supported escalation). A favorable partial score
is **INCOMPLETE**, with a separate provisional tier, not permission to adopt.
An independently supported negative cap may still warrant Avoid on partial
data. Missing optional
tools must not delay exact-version inventory, manual advisory review, pinning,
or mitigation.

## Report
Use `ensemble/report-template.md`. For "Adopt with mitigations," the required
actions are **compensating controls** the consumer owns:
- Pin the exact safe version; add a lockfile entry.
- Add the package to Dependabot/Renovate + OSV monitoring.
- Mirror/vendor if upstream maintenance is shaky.
- Gate CI on a re-scan; sandbox at runtime if it handles untrusted input.

Always state what you could not determine and how it affects confidence.
Treat unresolved artifact identity and source-only evidence as gaps; a
`package@version` is not a scanner lockfile. Use the versioned manual
observation contract in `skills/audit/SKILL.md` for supported probes.
