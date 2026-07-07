# Ensemble Risk Model

This is the **fusion engine** of the OpenSSF ensemble. It defines how the raw
output of many independent OpenSSF tools is normalized, weighted, and combined
into a single, reproducible verdict.

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
| `status` | `ok` / `unknown` (tool couldn't run) / `error` |

**Never silently drop a signal.** A probe that cannot run is `unknown`, carries
0 weight, and MUST appear in the report's "What we could not determine" section.

---

## 2. Normalization (raw → subscore, 0–100)

| Signal | Source tool(s) | Normalization |
|--------|----------------|---------------|
| `scorecard` | OpenSSF Scorecard | `subscore = scorecard_aggregate * 10` (0–10 → 0–100) |
| `known_vulns` | OSV-Scanner, pip/npm/cargo audit | Start at 100. Subtract 40 per unpatched CRITICAL, 20 per HIGH, 8 per MEDIUM, 2 per LOW. Floor at 0. A fix being available makes the deduction count double (it's negligence, not bad luck). |
| `maintenance` | Repo metadata | 100 if released ≤3mo AND ≥2 active maintainers. −25 if last release 3–12mo. −50 if >12mo. −25 if bus factor = 1. −100 if archived/EOL. Floor 0. |
| `supply_chain` | SBOM + transitive analysis | 100 minus 5 per direct dependency with its own CRITICAL/HIGH CVE, minus 2 per deep (transitive) one. Floor 0. Pinned + lockfile present adds +10 (cap 100). |
| `provenance` | SLSA level, Sigstore/Cosign verify | SLSA L3=100, L2=70, L1=40, L0/none=10. +0 but flips `signing_verified` flag used by escalation rules. |
| `secrets` | Gitleaks, TruffleHog | 100 if clean. Any *verified live* secret → 0 (and triggers CRITICAL escalation). Historical/inactive only → 50. |
| `baseline` | OSPS Baseline L1 | `subscore = (controls_met / controls_total) * 100`. |
| `threat_coverage` | STRIDE threat model (PRODUCE only) | 100 if current model exists covering trust boundaries; 50 if partial/stale; 0 if none. |
| `code_review` | Branch protection + review signal | 100 if required reviews + protected default branch; 50 if partial; 0 if direct pushes allowed. |

If a tool emits richer detail, prefer it — these are floors, not ceilings.

---

## 3. Mode weights

The same signals are weighted differently depending on what question we're
answering. Weights sum to 1.0. Signals with `status != ok` are dropped and the
remaining weights are **renormalized** so they still sum to 1.0.

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

---

## 5. Escalation rules (overrides)

Escalations **cap** the final outcome regardless of a high `base`. A weighted
average must never be allowed to "average away" a disqualifying finding. Apply
the most severe matching rule.

| Trigger | Effect |
|---------|--------|
| Verified **live** secret exposed | Outcome = **CRITICAL / Avoid**. Halt and flag for incident response. |
| Unpatched **CRITICAL** CVE with a fix available | Cap outcome at **High Risk** (CONSUME: *Avoid* unless compensating control documented). |
| Project **archived / EOL / unmaintained >12mo** AND used as a critical dependency | Cap at **High Risk**. |
| Releases **unsigned** AND `provenance` SLSA ≤ L1 AND distributing binaries | Cap at **Medium Risk** at best. |
| Any probe core to the mode is `unknown` (e.g. Scorecard failed in CONSUME) | Verdict confidence drops one level; never report "low risk" with high confidence on partial data. |

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

Show the top 5. This keeps remediation focused on what actually moves risk.

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
After renormalizing for the dropped `supply_chain` weight, `base ≈ 67`.
No escalation triggers fire (HIGH CVE caps at High Risk only on CRITICAL).
→ **Adopt with mitigations**: pin the version, upgrade past the HIGH CVE,
monitor for signed releases.

The point of this file is that two evaluators running the same tools on the same
target should reach the **same** verdict.
