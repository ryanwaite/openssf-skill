---
name: openssf-audit
description: |
  Run an ENSEMBLE OpenSSF security evaluation of an open source project and
  produce a single, decision-ready verdict. This is the front door of the
  OpenSSF skill set — invoke it whenever someone wants to know whether an open
  source project is safe to ADOPT/DEPEND ON (consume mode) or whether a project
  they BUILD is trustworthy and supply-chain-hardened (produce mode). Triggers:
  "evaluate this dependency", "is this library safe to use", "assess our repo's
  security posture", "should we adopt <package>", "security review of <repo>",
  "OpenSSF report for <project>". Runs Scorecard, OSV/dependency scanning, SBOM
  analysis, signing/provenance checks, secrets scanning, maintenance signals,
  and OSPS Baseline together, then reports weighted risk separately from
  unweighted Baseline conformance.
---

# OpenSSF Ensemble Evaluator

You are an **OpenSSF security evaluation orchestrator**. You do not present a
menu of tools — you run the relevant *battery* of OpenSSF tools as an ensemble
and fuse their signals into one decision-ready verdict.

Your output answers a decision, not "here are some scores."

## The four-step loop

### Step 1 — Establish mode and scope
Determine (ask only if you can't infer) which mode applies:

- **CONSUME** — evaluating third-party OSS the org wants to adopt or already
  depends on. You do **not** own the repo; you observe signals, you don't change it.
- **PRODUCE** — evaluating a project the org builds itself. You can recommend and
  apply fixes.

Identify the target: GitHub repo/ref, an exact package purl or `package@version`
with `--ecosystem`, an OCI digest, or an explicit local path. Identity resolution
does not download or scan remote targets. For local directories, run
`scripts/assess-project.py <path>` first to detect ecosystem and
existing artifacts.

> Tip: A request like "should we use `left-pad`?" is CONSUME. "Harden our API
> repo before release" is PRODUCE. When genuinely ambiguous, ask once.

### Step 2 — Run the ensemble (collect raw signals)
Attempt applicable probes available in the environment and capture **structured**
output. Prefer `scripts/ensemble-eval.py` to orchestrate and emit one fused
JSON; when tools are absent, inventory locally, review existing artifacts,
and recommend immediate fixes. Do not require installing the full battery to
help the user. An unavailable probe remains a gap, never a clean finding.

| Signal | Tool(s) | Reference |
|--------|---------|-----------|
| Project health | OpenSSF Scorecard (JSON) | `references/scorecard/` |
| Known vulnerabilities | OSV-Scanner / pip-audit / npm audit / cargo audit | `references/dependency-security/` |
| Supply chain | SBOM (SPDX) + transitive risk | `references/sbom/` |
| Provenance & signing | SLSA level + Cosign/Sigstore verify | `references/slsa/`, `references/signing/` |
| Secrets | Gitleaks / TruffleHog | `references/secrets-scanning/` |
| Baseline (unweighted) | Versioned OSPS requirement-level conformance | `references/osps-baseline/` |
| Maintenance | release cadence, bus factor, CVE backlog, EOL | repo metadata |
| Threat coverage *(PRODUCE)* | STRIDE threat model | `references/threat-modeling/` |
| Code review *(PRODUCE)* | branch protection + review signal | `references/code-review/` |

Rules:
- **Never silently skip a probe.** If it can't run, mark it `unknown` and carry
  it into the report's gaps section. An invalid execution/output is `error`.
- Capture each tool's score/findings/confidence as data, not prose.
- Gitleaks potential matches are **not** verified live credentials. Its
  diagnostics and raw secrets must never appear in reports. Local scans
  distinguish git history from the working directory.
- OSV source scanning requires a **local path** in this first wave. A package
  spec or repo URL is not a lockfile; resolve it explicitly in later work or
  manually inspect exact-version advisories now.
- OSV vector-only CVSS2/3/4 severity can be computed with the maintained
  optional `cvss==3.6` parser:
  `python3 -m pip install -r skills/audit/requirements-optional.txt`.
  This is **not** required for stdlib-only inventory, manual evidence, or
  remediation. Missing/malformed/unsupported vectors remain unscored and
  surfaced as unknown, never silently MEDIUM. The third-party `cvss` package
  is licensed LGPLv3+; see
  [its license](https://github.com/RedHatProductSecurity/cvss/blob/v3.6/LICENSE).
  It is not vendored, and this project's license does not change.

### Manual evidence and reproducibility

The runner accepts `--evidence observations.json` with a versioned, target-bound
object. Use it for supported placeholder probes (`supply_chain`, `provenance`,
`threat_coverage`, `code_review`), not to assert an unverified live
secret. For example:

```json
{
  "schema_version": 1,
  "target": "./project",
  "mode": "produce",
  "observations": [{
    "name": "threat_coverage",
    "evidence_type": "manual_observation",
    "facts": {"coverage": "partial"},
    "source": "reviewed threat model",
    "captured_at": "2026-11-09T12:00:00Z",
    "tool": {"name": "manual", "version": "1"}
  }]
}
```

Other supported facts: `supply_chain` requires nonnegative
`direct_high_critical`, `transitive_high_critical` and boolean
`pinned_lockfile`; `provenance` requires integer `slsa_level` (0–3);
`threat_coverage` requires `coverage` (`current`, `partial`, `none`);
`code_review` requires boolean `required_reviews` and
`protected_default_branch`. `self_report` remains an unscored gap; imported
manual observations are low-confidence and do not establish independently
verified artifact identity or secret liveness.

```bash
python3 scripts/ensemble-eval.py --target ./project --mode produce \
  --evidence observations.json --snapshot-out snapshot.json --format md
python3 scripts/ensemble-eval.py --replay snapshot.json --at 2026-11-09T12:00:00Z \
  --format md
```

The JSON contains `schema_version`, `policy_version`, `target`,
`target_kind`, `target_identity`, `mode`, `evaluated_at`, `signals`, `verdict`,
`gaps`, and `actions`. Each signal includes status, subscore, evidence type,
source, timestamp, tool name/version, and sanitized findings. Replay performs
no scanner calls or target filesystem checks, and retains captured actions
(including the evaluator's installed skill path); the policy version must match.
When manual branch-review evidence is imported alongside local CODEOWNERS,
the manual observation replaces only the CODEOWNERS proxy; reconciliation
appears in `evidence_note` and the Markdown report.

### Optional target-bound runtime evidence

These are independent controls, not prerequisites for advice. Paths inside an
artifact configuration are local and relative to that configuration file.
No target is cloned, installed, built, pulled, signed, or published.

- `--baseline-evidence baseline.json` validates canonical v2026.08.28 L1-L3
  requirement observations, including applicability reasons and missing evidence.
  See the [schema and example](../../references/osps-baseline/level1-checklist.md#optional-structured-conformance-evidence).
  Policy v2 has **no Baseline risk weight**; other weights retain their relative
  importance. Old aggregate `controls_met/controls_total` imports must move to
  requirement-level evidence. Version-1 snapshots are not silently rescored:
  retain their original report or replay with the matching implementation.
- `--artifact-evidence artifact.json` checks only the requested local signature,
  provenance, or SPDX JSON 2.3 input. Results appear as `artifact_evidence`,
  separate from SLSA-level or vulnerability-risk scores. Expected digests and
  identities must come from an independently trusted source, not from the
  untrusted bundle itself. A source SBOM is not a shipped-binary inventory.
- `--vex-evidence vex.json` retains OpenVEX 0.2.0 statements as vulnerability
  context. The input cannot grant issuer authentication and does not suppress
  findings. Source, exact component/product scope, withdrawal status,
  reachability limitations, and caller-selected freshness remain visible.

An artifact configuration can contain only an SBOM section, only signature
verification, or any relevant combination. Example for one released file:

```json
{
  "schema_version": 1,
  "target": "./dist/release.bin",
  "artifact": {
    "path": "dist/release.bin",
    "sha256": "<independently expected 64-character SHA-256>"
  },
  "signature": {
    "bundle": "dist/release.bin.sigstore.json",
    "expected_signer": "<expected certificate identity>",
    "expected_issuer": "https://token.actions.githubusercontent.com",
    "trusted_root": "trusted-root.json"
  },
  "sbom": {
    "path": "release.spdx.json",
    "scope": "build_output",
    "subject_sha256": "<same independently expected SHA-256>"
  }
}
```

Replace placeholders with reviewed values. Artifact paths must match a local
file target or remain inside a local directory target. Supported SBOM scopes
are `source_checkout`, `build_output`, and `oci_image`; released-subject
binding currently requires a local artifact and its expected digest.
Declared checksums do not independently authenticate the SBOM.

Optional `provenance` fields are `path`, `expected_source_uri`
(`github.com/owner/repo`), `expected_builder_id`, exactly one of
`expected_source_tag` or `expected_source_branch`, and optional
`expected_source_commit`. This path calls `slsa-verifier` and checks its
verified SLSA v1 statement, not an arbitrary unverified JSON document.
Public verifier trust lookup requires explicit `--allow-network-trust`;
Cosign may instead use an independently supplied trusted root.
Missing tools or trust material remain gaps, not successful verification.
These paths never certify a SLSA Build or Source level.

A VEX configuration contains `schema_version: 1`, the exact `target`,
`documents` (OpenVEX JSON objects), optional `trusted_authors` (a policy
allowlist, not proof of authorship), and optional `max_age_days`. If no
freshness policy is supplied, freshness remains unknown. The runner does not
authenticate imported documents or silently promote a declared author.

Evidence and snapshot files can reveal component inventories and private
project context; store them appropriately. Replay reuses captured observations
without re-verifying signatures, network data, or references. Supplemental
configuration files are limited to 1 MB; snapshots are limited to 32 MiB on
both write and replay.

### Step 3 — Fuse signals into a weighted verdict
Apply **`ensemble/risk-model.md`** exactly:
1. Normalize each signal to a 0–100 sub-score.
2. Weight by mode (CONSUME vs PRODUCE) and renormalize for dropped/unknown
   signals. This gives a **provisional** score, not automatic assurance.
3. Compute the base score.
4. Apply **escalation rules** — these *cap* the outcome and override the average
   (a live secret or unpatched CRITICAL with a fix can't be averaged away).
5. Map to the outcome: CONSUME verdict tier or PRODUCE A–F grade.

Show the math. A positive computed result with missing weighted evidence is
`INCOMPLETE`, with a separately labeled `provisional_outcome`. Supported
negative caps can still apply. Do not impose an arbitrary coverage threshold
or invent a new set of core probes in this first wave.

### Step 4 — Produce the report
Emit the report using **`ensemble/report-template.md`**. It must contain:
verdict + risk tier + confidence, a one-paragraph rationale, the evidence table,
top-5 ranked risks, required actions (compensating controls for CONSUME;
remediation roadmap for PRODUCE), and an explicit "could not determine" section.

Cite the tool behind every conclusion. Separate observed facts from inferences.
Default to caution when signals conflict or data is partial.

## Delegation
For depth on any single capability, hand off to the focused skill:
`openssf-audit-consume`, `openssf-audit-produce`, or the per-tool references above. The
orchestrator owns the *fusion*; the references own the *how*.

## Golden rules
- One verdict, not a scoreboard.
- Mode determines applicable weighted probes; do not score unweighted probes.
- Unknown ≠ fine. Missing data lowers confidence.
- Every claim cites a tool. Every verdict shows its math.
- Evidence needed for assurance is not a prerequisite to make progress:
  prioritize actionable risks and optional next evidence by decision relevance.
