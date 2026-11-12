# Ensemble Risk Model

This is the **fusion engine** of the OpenSSF ensemble. It defines how the raw
output of many independent OpenSSF tools is normalized, weighted, and combined
into a reproducible decision aid. This is a **custom heuristic**, not an
OpenSSF certification, OSPS Baseline grade, or proof of artifact safety.

**Policy version 2:** OSPS Baseline conformance is reported separately, without
a numeric risk weight. The remaining version-1 weights are divided by 0.92
(consume) or 0.90 (produce), preserving their relative importance. A version-1
snapshot must be replayed with its original policy implementation, not silently
rescored under version 2. New evaluations record `policy_version: "2"`.

The goal: turn a pile of disconnected tool scores ("Scorecard 4.2", "3 CVEs",
"unsigned releases") into one decision — *Adopt / Adopt-with-mitigations / Avoid*
for consumed dependencies, or an *A–F posture grade* for projects you build.

> **Reproducibility rule:** the verdict must follow from the rules below, not
> from intuition. Always show the math (sub-scores, weights, escalations) so a
> human can audit it.

---

## 1. Signals

Each probe in the ensemble produces one **signal**. A signal has:

| Field | Meaning |
|-------|---------|
| `name` | The probe (e.g. `scorecard`, `known_vulns`) |
| `raw` | The tool's native output (score, count, boolean, list) |
| `subscore` | Normalized 0–100 (higher = safer), per the rules in §2 |
| `confidence` | `high` / `medium` / `low` — how much to trust this signal |
| `status` | `ok` / `unknown` (not measured or severity unresolved) / `error` (failed contract) |
| `evidence_type`, `source`, `captured_at`, `tool` | Observation vs. manual observation vs. self-report vs. verified finding; provenance/time/tool version |

**Never silently drop a signal.** A probe that cannot run is `unknown` (or
`error` for an invalid execution/output), carries 0 weight, and MUST appear
in the report's gaps. Its absence is an assurance gap, not a prerequisite for
inventory, manual review, or immediate remediation.

---

## 2. Normalization (raw → subscore, 0–100)

| Signal | Source tool(s) | Normalization |
|--------|----------------|---------------|
| `scorecard` | OpenSSF Scorecard | Preserve the upstream aggregate as context; score 10 times the mean of available non-overlapping checks. Consume excludes Vulnerabilities, Maintained, Signed-Releases, and Pinned-Dependencies; produce excludes Vulnerabilities, Code-Review, Branch-Protection, and Signed-Releases. Omitted/unavailable checks, missing revision/time, revision mismatch, dirty working trees, and observations older than 90 days remain unscored gaps. This is a separate custom heuristic, not the upstream aggregate. |
| `known_vulns` | OSV-Scanner or explicit exact-version OSV API query | Start at 100. Subtract 40 per CRITICAL, 20 per HIGH, 8 per MEDIUM, 2 per LOW, 0 per NONE (CVSS 0) **advisory group per affected package/version**. Floor at 0. A documented fixed version doubles that finding's deduction. Unknown severity prevents a scored clean result. Numeric CVSS 0–10 and explicit advisory severity buckets are supported; optional `cvss==3.6` calculates CVSS2/3/4 vectors (base score only) in an isolated interpreter. Missing extra, malformed/unsupported vectors, and contradictory uncomputable vectors remain unknown, not MEDIUM. When computed and explicit buckets conflict, retain the higher severity; an independently supported CRITICAL fact still triggers its cap even if another severity entry is unresolved. API-only lookup remains medium confidence and does not establish package-content integrity or dependency closure. |
| `maintenance` | Repo metadata | Full policy: 100 if released ≤3mo AND ≥2 active maintainers. −25 if last release 3–12mo; −50 if >12mo; −25 if bus factor = 1; −100 if archived/EOL (floor 0). Current runner only has a *low/medium-confidence commit/push recency proxy* (100 ≤90d, 75 ≤365d, 50 older, or 0 archived). It must not claim release cadence or maintainer count from a push. |
| `supply_chain` | SBOM + transitive analysis | 100 minus 5 per direct dependency with its own CRITICAL/HIGH CVE, minus 2 per deep (transitive) one. Floor 0. Pinned + lockfile present adds +10 (cap 100). |
| `provenance` | SLSA level, Sigstore/Cosign verify | SLSA L3=100, L2=70, L1=40, L0/none=10. +0 but flips `signing_verified` flag used by escalation rules. |
| `secrets` | Gitleaks | 100 if history (when git available) and working directory both clean. Potential regex finding → 50 pending verification; a separately *verified live* secret → 0 (and triggers CRITICAL escalation). Never include secret bytes in reports. |
| `threat_coverage` | STRIDE threat model (PRODUCE only) | 100 if current model exists covering trust boundaries; 50 if partial/stale; 0 if none. |
| `code_review` | Effective branch protection + review evidence | 100 if confirmed required reviews + protected primary branch; 50 if exactly one predicate is established true and the other established false; 0 if both are established false. Incomplete visibility, bypass ambiguity, or different branch scope remains unknown/unscored. Imported settings are low-confidence observations; CODEOWNERS alone is not enforcement evidence and is unscored. |

If a tool emits richer detail, prefer it — these are floors, not ceilings.

`baseline_conformance` is **outside** this normalization table. It records
versioned requirement IDs, applicability, observations, and unknowns, with no
score or certification. `artifact_evidence` separately records optional
signature/provenance verification and SPDX inventory quality. A verified
signature does not establish a SLSA level, and an SPDX document's checksum
declaration does not prove inventory completeness.

OSV records retain package-scoped affected ranges and fixes, withdrawal status,
malicious-package assertions, and reachability/VEX context. Withdrawn records
are retained as context, not scored. A malicious advisory identifier is not
proof of compromise. Imported VEX author allowlists do not authenticate the
document; no imported not-affected statement automatically suppresses findings.

Optional `project_evidence` preserves live or imported exact-branch settings,
release/support/maintainer facts, and reviewed threat-model areas. These facts
do not manufacture release cadence, bus factor, or whole-project coverage from
activity, contributor counts, or a filename. Maintenance recency calculations
use `evaluated_at`, not wall-clock time; the existing recency proxy remains
explicitly limited. An archive flag or manually reviewed EOL declaration can
support a zero maintenance score, but consumer criticality is still required
for its escalation. Richer partial threat-area evidence stays unscored instead
of being promoted to project-wide coverage.

Explicit remote acquisition records actual capture time. Evidence more than
five minutes in the future or older than 90 days relative to `--at` remains
unscored, with the supplied scope visible. Replay preserves the captured
observations and does not refresh services or authenticate an imported snapshot.

Optional `security_insights`, `registry_evidence`, and `supply_chain_analysis`
are contextual, unweighted sections. Maintainer claims, registry-advertised
attestations, schema acceptance, and declared dependency paths do not raise
assurance or satisfy a missing scored probe on their own. Correlating an existing
advisory with an inventory path never creates a second deduction. There is no
policy-version change for adding these observations; policy v2 remains in effect.

---

## 3. Mode weights

The same signals are weighted differently depending on what question we're
answering. Weights sum to 1.0. Signals with `status != ok` are dropped and the remaining weights are
**renormalized** for a *provisional base score*; original weights never change.
Do not treat that base as positive assurance without all weighted probes.

### CONSUME — "Should we adopt / depend on this?"
Emphasis: what can hurt *us* by pulling it in.

| Signal | Weight |
|--------|--------|
| `known_vulns` | 0.28 / 0.92 |
| `maintenance` | 0.22 / 0.92 |
| `supply_chain` | 0.16 / 0.92 |
| `scorecard` | 0.14 / 0.92 |
| `provenance` | 0.12 / 0.92 |

### PRODUCE — "Is what we ship trustworthy and hardened?"
Emphasis: controls we own and are accountable for.

| Signal | Weight |
|--------|--------|
| `secrets` | 0.20 / 0.90 |
| `provenance` | 0.16 / 0.90 |
| `code_review` | 0.16 / 0.90 |
| `scorecard` | 0.14 / 0.90 |
| `known_vulns` | 0.12 / 0.90 |
| `threat_coverage` | 0.12 / 0.90 |

---

## 4. Base score

```
base = Σ (subscore_i × weight_i)   over all signals with status == ok
```

`base` is 0–100. Higher is safer.

The runner reports each original weight, effective normalized weight, and
contribution, plus weighted coverage. If no weighted signal was scored,
`base` is null. A positive computed result with a missing weighted probe is
reported as **INCOMPLETE** with a separately labeled `provisional_outcome`
(not an adoption recommendation or grade). This first-wave rule avoids
inventing a numerical threshold or new core-probe set. A supported negative
cap can still report Avoid/F on partial evidence, even when the numeric base
remains null. In that case the cap rule determines the outcome, but no numeric
final score is fabricated. Missing evidence never erases an independently
supported adverse fact. `INCOMPLETE`
is usable output, not a CLI failure.

---

## 5. Escalation rules (overrides)

Escalations **cap** the final outcome regardless of a high `base`. A weighted
average must never be allowed to "average away" a disqualifying finding. Apply
the most severe matching rule.

| Trigger | Effect |
|---------|--------|
| Independently **verified live** secret exposed | Outcome = **CRITICAL / Avoid or F**. Halt and flag for incident response. Gitleaks regex matches alone do not meet this predicate. |
| Unpatched **CRITICAL** CVE with a fix available | Cap outcome at **High Risk** (CONSUME: *Avoid* unless compensating control documented). |
| Project **archived / EOL / unmaintained >12mo** AND explicitly known to be a critical dependency | Cap at **High Risk**. An archived upstream alone does not establish consumer criticality. |
| Verified releases **unsigned** AND `provenance` SLSA ≤ L1 AND distributing binaries | Cap at **Medium Risk** at best. Unverified manual claims alone do not trigger this. |
| Any weighted probe missing or low-confidence | Confidence is **low**. Full coverage with some medium-confidence signals gives **medium**; all-high is **high**. |

---

## 6. Outcome mapping

### CONSUME — verdict tiers
| base (after escalation cap) | Verdict |
|------|---------|
| ≥ 80 | **Adopt** |
| 55–79 | **Adopt with mitigations** (list required compensating controls) |
| < 55 or High/Critical escalation | **Avoid** |

### PRODUCE — posture grade
| base (after escalation cap) | Grade |
|------|-------|
| ≥ 90 | **A** |
| 80–89 | **B** |
| 70–79 | **C** |
| 60–69 | **D** |
| < 60 or Critical escalation | **F** |

---

## 7. Risk ranking for findings

Within the report, rank individual findings by:

```
priority = severity × exploitability × exposure
```

- **severity**: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
- **exploitability**: fix-available & network-reachable=3, fix-available=2, theoretical=1
- **exposure**: in a direct dependency / production path=3, transitive=2, dev-only=1

Show the top 5. When exposure is not established, disclose the conservative
direct-dependency assumption in the priority math; never state it as observed.
Potential secrets without established liveness are urgent triage but not
silently assigned CRITICAL severity.

---

## 8. Worked example (CONSUME)

A library: custom non-overlapping Scorecard subscore 65; one HIGH CVE
(fix available); maintenance subscore 100; SLSA L1. Baseline observations
are reported separately and do not enter this arithmetic.

```
scorecard    = 65    × (0.14 / 0.92)
known_vulns  = 60    × (0.28 / 0.92)  (100 − 20 doubled for fix-available = 60)
maintenance  = 100   × (0.22 / 0.92)
supply_chain = (n/a, unknown → dropped, weights renormalized)
provenance   = 40    × (0.12 / 0.92)
```
After renormalizing for the dropped `supply_chain` weight,
`base = (9.10 + 16.80 + 22.00 + 4.80) / 0.76 = 69.34210… → 69.3`.
No escalation triggers fire (HIGH CVE caps at High Risk only on CRITICAL).
→ **INCOMPLETE** with *provisional* Adopt with mitigations: upgrade past the
HIGH CVE now; investigate supply-chain exposure if assurance is needed.

The point of this file is that two evaluators running the same tools on the same
target should reach the **same** verdict.
