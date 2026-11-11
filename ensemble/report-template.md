# Ensemble Evaluation Report Template

Use this structure for every ensemble verdict. Fill every section. If a section
has no data, say so explicitly — gaps are findings too.

Keep it **decision-ready**: partial evidence should enable focused work today
without presenting an unqualified Adopt/A or demanding installation of every
optional tool. Scores/grades are custom heuristics, not OpenSSF certification.

---

```markdown
# OpenSSF Ensemble Evaluation — <target name>

- **Mode:** Consume | Produce
- **Target:** <repo URL / package@version / local path>
- **Ecosystem:** <languages / package managers detected>
- **Evaluated:** <date> · **Tools run:** <N of M>
- **Identity:** <requested target; immutable artifact verified or unresolved>
- **Evidence coverage:** <N/M applicable weighted signals; total weighted coverage>
- **Policy/schema:** <custom policy version / evidence schema version>

## Verdict

> **<Adopt | Adopt with mitigations | Avoid | INCOMPLETE>**  (Consume)
> **Posture grade: <A–F | INCOMPLETE>**  (Produce)
> Risk tier: <critical | high | medium if a cap applies; otherwise not assigned>
> · Confidence: <High | Medium | Low>

<One paragraph: the rationale, tied to the 2–3 strongest signals. Why this
verdict and not the adjacent one. Plain language for a decision-maker.>
<For INCOMPLETE, separately label the calculated *provisional* outcome. This is
not an adoption recommendation/grade. A supported negative cap still applies.>

## Evidence

| Signal | Status | Sub-score | Original → effective weight | Contribution | Confidence | Source / time | Finding |
|--------|--------|-----------|-----------------------------|--------------|------------|---------------|---------|
| Known vulnerabilities | ok | 60 | 0.28 → 0.333 | 20.00 | high | OSV-Scanner / date | one HIGH (fix available) |
| Supply chain | unknown | — | 0.16 → 0 | — | low | unmeasured | SBOM not reviewed |

**Math:** Σ (sub-score × effective weight) = <base>; cap → <final>.
**Escalations applied:** <none | rule + effect>.

## Top risks (ranked)

1. **<finding ID and affected package@version>** — source; severity ×
   exploitability × exposure = <n>. <Known fixes, assumptions, and why it matters.>
2. ...
   (up to 5)

## Required actions

List **observed** high-priority fixes first (upgrade named affected version,
triage potential secrets, rotate if independently confirmed live). With no
scanner available, begin with local inventory, targeted guidance, and manual
review. Scanners and complete evidence are optional *assurance steps*, not
mandatory setup before progress. Do not prescribe actions for unsupported
target types as though a successful scan occurred.

## What we could not determine
- <signal> — <unknown / execution error / nonapplicable if established>
  — <why> — <optional evidence path where appropriate>.

## Provenance of this report
Each conclusion above maps to a named source, capture time, and tool version
(or explicitly unrecorded). Distinguish tool observations, manually imported
observations, project self-reports, and independently verified findings. Where
signals conflicted, default to caution. No raw secret bytes or scanner stderr.
```

---

## Authoring notes for the agent

- **Cite the tool** behind every conclusion. "Scorecard reports…", "OSV-Scanner found…".
- **Separate fact from inference.** "No SECURITY.md found" is fact; "likely no disclosure process" is inference.
- **Never inflate confidence on partial data.** A positive partial result is
  `INCOMPLETE`, with a separately labeled provisional calculation.
- **Make actions copy-pasteable** where possible (commands, config snippets).
- Replay with `--replay snapshot.json --at <ISO-8601>`; no probes run. Identity,
  observations, timestamp, policy version, and effective weights must remain
  visible in JSON and Markdown.
