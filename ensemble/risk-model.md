# Ensemble Risk Model

This is the **fusion engine** of the OpenSSF ensemble. It defines how the raw
output of many independent OpenSSF tools is normalized, weighted, and combined
into a reproducible decision aid. This is a **custom heuristic**, not an
OpenSSF certification, OSPS Baseline grade, or proof of artifact safety.

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
| `scorecard` | OpenSSF Scorecard | `subscore = scorecard_aggregate * 10` (0–10 → 0–100) |
| `known_vulns` | OSV-Scanner for local source | Start at 100. Subtract 40 per CRITICAL, 20 per HIGH, 8 per MEDIUM, 2 per LOW **advisory group per affected package/version**. Floor at 0. A documented fixed version doubles that finding's deduction. Unknown severity prevents a scored clean result. Numeric CVSS 0–10 and explicit advisory severity buckets are supported; vector-only severity is unknown until assessed with a maintained calculator/tool. |
| `maintenance` | Repo metadata | Full policy: 100 if released ≤3mo AND ≥2 active maintainers. −25 if last release 3–12mo; −50 if >12mo; −25 if bus factor = 1; −100 if archived/EOL (floor 0). Current runner only has a *low/medium-confidence commit/push recency proxy* (100 ≤90d, 75 ≤365d, 50 older, or 0 archived). It must not claim release cadence or maintainer count from a push. |
| `supply_chain` | SBOM + transitive analysis | 100 minus 5 per direct dependency with its own CRITICAL/HIGH CVE, minus 2 per deep (transitive) one. Floor 0. Pinned + lockfile present adds +10 (cap 100). |
| `provenance` | SLSA level, Sigstore/Cosign verify | SLSA L3=100, L2=70, L1=40, L0/none=10. +0 but flips `signing_verified` flag used by escalation rules. |
| `secrets` | Gitleaks | 100 if history (when git available) and working directory both clean. Potential regex finding → 50 pending verification; a separately *verified live* secret → 0 (and triggers CRITICAL escalation). Never include secret bytes in reports. |
| `baseline` | OSPS Baseline catalog version (manual import) | Custom `subscore = (controls_met / controls_total) * 100`; **not** an official OSPS score or certification. |
| `threat_coverage` | STRIDE threat model (PRODUCE only) | 100 if current model exists covering trust boundaries; 50 if partial/stale; 0 if none. |
| `code_review` | Branch protection + review signal | 100 if required reviews + protected default branch; 50 if partial; 0 if direct pushes allowed. |

If a tool emits richer detail, prefer it — these are floors, not ceilings.

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
| `known_vulns` | 0.28 |
| `maintenance` | 0.22 |
| `supply_chain` | 0.16 |
| `scorecard` | 0.14 |
| `provenance` | 0.12 |
| `baseline` | 0.08 |

### PRODUCE — "Is what we ship trustworthy and hardened?"
Emphasis: controls we own and are accountable for.

| Signal | Weight |
|--------|--------|
| `secrets` | 0.20 |
| `provenance` | 0.16 |
| `code_review` | 0.16 |
| `scorecard` | 0.14 |
| `known_vulns` | 0.12 |
| `threat_coverage` | 0.12 |
| `baseline` | 0.10 |

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
cap can still report Avoid/F on partial evidence; missing
evidence never erases an independently supported adverse fact. `INCOMPLETE`
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

A library: Scorecard 6.5; one HIGH CVE (fix available); last release 2mo ago,
2 maintainers; clean secrets; SLSA L1, unsigned; OSPS 6/10.

```
scorecard    = 65    × 0.14 = 9.10
known_vulns  = 60    × 0.28 = 16.80   (100 − 20 doubled for fix-available = 60)
maintenance  = 100   × 0.22 = 22.00
supply_chain = (n/a, unknown → dropped, weights renormalized)
provenance   = 40    × 0.12 = ...
baseline     = 60    × 0.08 = ...
```
After renormalizing for the dropped `supply_chain` weight,
`base = (9.10 + 16.80 + 22.00 + 4.80 + 4.80) / 0.84 = 68.45238… → 68.5`.
No escalation triggers fire (HIGH CVE caps at High Risk only on CRITICAL).
→ **INCOMPLETE** with *provisional* Adopt with mitigations: upgrade past the
HIGH CVE now; investigate supply-chain exposure if assurance is needed.

The point of this file is that two evaluators running the same tools on the same
target should reach the **same** verdict.
