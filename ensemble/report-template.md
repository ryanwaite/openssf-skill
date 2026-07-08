# Ensemble Evaluation Report Template

Use this structure for every ensemble verdict. Fill every section. If a section
has no data, say so explicitly — gaps are findings too.

Keep it **decision-ready**: an engineering leader should be able to read the
verdict and rationale alone and make a call.

---

```markdown
# OpenSSF Ensemble Evaluation — <target name>

- **Mode:** Consume | Produce
- **Target:** <repo URL / package@version / local path>
- **Ecosystem:** <languages / package managers detected>
- **Evaluated:** <date> · **Tools run:** <N of M>

## Verdict

> **<Adopt | Adopt with mitigations | Avoid>**  (Consume)
> **Posture grade: <A–F>**  (Produce)
> Risk tier: <Low | Medium | High | Critical> · Confidence: <High | Medium | Low>

<One paragraph: the rationale, tied to the 2–3 strongest signals. Why this
verdict and not the adjacent one. Plain language for a decision-maker.>

## Evidence

| Signal | Sub-score | Weight | Key finding | Confidence |
|--------|-----------|--------|-------------|------------|
| Known vulnerabilities | 60 | 0.28 | 1 HIGH (fix available) | high |
| Maintenance | 100 | 0.22 | active, 2 maintainers | high |
| Scorecard | 65 | 0.14 | weak on branch protection | high |
| Supply chain (SBOM) | — | — | not run | — |
| Provenance / signing | 40 | 0.12 | SLSA L1, unsigned | medium |
| OSPS Baseline | 60 | 0.08 | 6/10 controls | medium |

**Base score:** <0–100> · **Escalations applied:** <none | rule + effect>

## Top risks (ranked)

1. **<finding>** — severity × exploitability × exposure = <n>. <Why it matters.>
2. ...
   (up to 5)

## Required actions

### Consume mode → compensating controls
- [ ] Pin to `<version>` and upgrade past <CVE> when patched.
- [ ] Add to dependency monitoring / Dependabot alerts.
- [ ] Vendor or mirror if upstream maintenance is a concern.

### Produce mode → remediation roadmap (with effort)
- [ ] <fix> — priority <critical/high>, effort <low/med>, ~<time>.
- [ ] ...

## What we could not determine
- <signal> — <why it couldn't run> — <how to close the gap>.

## Provenance of this report
Each conclusion above maps to a named tool. Observed facts vs. inferences are
distinguished. Where signals conflicted, we defaulted to caution.
```

---

## Authoring notes for the agent

- **Cite the tool** behind every conclusion. "Scorecard reports…", "OSV-Scanner found…".
- **Separate fact from inference.** "No SECURITY.md found" is fact; "likely no disclosure process" is inference.
- **Never inflate confidence on partial data.** If a core probe is `unknown`,
  the verdict confidence cannot be `high`.
- **Make actions copy-pasteable** where possible (commands, config snippets).
