---
name: openssf
description: |
  OpenSSF security skill set with two modes. **Advisor** helps you BUILD or FIX a
  specific security control (threat model, SECURITY.md, SBOM setup, Sigstore
  signing, Dockerfile hardening, secrets pre-commit hook, Scorecard workflow).
  **Audit** runs the OpenSSF tools as an ENSEMBLE (Scorecard, OSV/dependency
  scanning, SBOM, Sigstore/SLSA signing, secrets scanning, OSPS Baseline) and
  fuses their signals into one decision-ready verdict — Adopt/Avoid for a
  dependency you consume, or an A–F grade for a project you produce. Invoke for
  anything from "generate a SECURITY.md" to "is this library safe to adopt?" to
  "grade our security posture." Routes the request to the right mode: advisor or
  audit (which further picks consume vs produce).
---

# OpenSSF Skill — Router

This skill set has **two modes**. Read the request and route to the right one.

## Routing

| If the user wants to… | Go to |
|-----------------------|-------|
| Build or fix ONE specific control (threat model, SECURITY.md, signing setup, Dockerfile hardening, SBOM how-to, Scorecard workflow, fix a failing check) | **`skills/advisor`** |
| Get a VERDICT or GRADE for a project (don't know consume vs produce yet) | **`skills/audit`** (orchestrator) |
| Vet third-party OSS they adopt / depend on | **`skills/audit/consume`** → Adopt / Adopt-with-mitigations / Avoid |
| Assess / grade a project they build & ship | **`skills/audit/produce`** → A–F grade + roadmap |
| Deep-dive one capability (Scorecard, SBOM, signing, secrets, SLSA, threat model, …) | the matching folder in **`references/`** |

### The two modes in one line each
- **advisor** — *"help me build or fix this specific thing."* Assess → recommend
  prioritized next steps → guide the user through creating the artifact using
  `references/`, `templates/`, and `workflows/`.
- **audit** — *"tell me how safe this is."* Run the ensemble battery, fuse the
  signals per `ensemble/risk-model.md`, and emit one verdict/grade per
  `ensemble/report-template.md`. The audit orchestrator picks **consume**
  (Adopt / Adopt-with-mitigations / Avoid) or **produce** (A–F grade).

**Default:** if the ask is "do this one security task," start at `skills/advisor`.
If the ask is "how good/safe is this," start at `skills/audit`. When genuinely
ambiguous, ask once.

## The audit model in one breath
1. **Mode** — Consume (don't own it) vs Produce (own it). Mode sets the weights.
2. **Run the battery** — never skip a probe; an un-run probe is `unknown`, not "fine."
3. **Fuse** — normalize → weight → escalate (live secrets / critical CVEs cap the
   verdict) per `ensemble/risk-model.md`.
4. **Report** — one verdict + evidence + ranked risks + actions, per
   `ensemble/report-template.md`.

## Tooling
- `scripts/assess-project.py` — local language/artifact detection (used by both modes).
- `scripts/ensemble-eval.py` — runs the audit ensemble and emits a fused
  JSON/Markdown verdict (degrades gracefully when a tool isn't installed).

Every conclusion cites the tool behind it. Every verdict shows its math.
