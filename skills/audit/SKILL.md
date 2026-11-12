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
alone does not download or scan remote targets; `--acquire-remote` is a separate
explicit option for supported public targets. For local directories, run
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
- OSV source scanning requires a local path, which can be a supplied directory/
  file or a bounded public commit archive explicitly requested with
  `--acquire-remote`. A package coordinate uses the separate exact-version OSV
  query; it is never passed as a lockfile. No remote acquisition is implicit.
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
the manual observation supplements the unscored CODEOWNERS indicator; reconciliation
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
verified SLSA v0.2 or v1 statement, not an arbitrary unverified JSON document.
The published generator v2.1.0 uses v0.2; its predicate version is not the SLSA
framework version or a level claim. Only the supported predicate-specific
builder/source/ref layouts are accepted.
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

### Optional remote and project evidence

`--acquire-remote` adds one target-specific operation; it never installs,
builds, executes, or signs target code:

| Target | Operation and scope |
|---|---|
| Public GitHub repository/ref | Resolve the commit through `api.github.com`, fetch its commit-addressed `codeload.github.com` archive, and invoke an available local OSV source scanner on the temporary snapshot |
| Exact package version | Paginated `api.osv.dev/v1/query` advisories for that ecosystem/name/version; no package download or dependency closure |
| `ghcr.io` / `docker.io` image digest | Invoke `osv-scanner scan image` after installed-tool/running-Docker preflight; the scanner may pull the selected image, but the evaluator never starts Docker or runs the image |

Acquisition has fixed public endpoint boundaries and does not forward GitHub
credentials. GitHub redirects, archive traversal, links/devices, duplicates,
oversized metadata or file contents, and incomplete extraction fail explicitly.
Current archive bounds are 16 MiB compressed, 64 MiB total extracted regular
file data, 8 MiB per file, 2,000 files, and 4,000 entries, with a separate bounded
decompressed tar stream. A large unsupported repository is not silently
truncated and called scanned.

Remote source/image scanner processes are POSIX-only and bounded in duration
and output. Remote source scanning uses an explicit empty scanner configuration,
no ignore-file exclusions, disabled Go call analysis and transitive resolution,
and does not run Rust build scripts. A source archive has **no Git history**:
it is not a history-based secrets scan or submodule inventory. Paths retained
in findings are relative to the resolved commit's snapshot, not temporary
filesystem paths. OSV `--all-packages` preserves clean-package coverage;
zero sources still means unknown coverage.

`remote_acquisition` records source, scope, counts, commit/purl/digest, and
actual fetch time. Acquisition observations over 90 days old or more than five
minutes after a requested `--at` remain unscored; no historical capture time is
fabricated. Replay preserves captured acquisition evidence without downloading
again. Private registries/repositories, general code installation, and arbitrary
URL fetches are not supported by this path.

`--fetch-governance` separately requests read-only GitHub repository metadata,
exact-branch protection/effective rules, ruleset details, commit, and latest
stable release through existing `gh` access. It changes no settings and does not
request new permissions. `--governance-branch` selects a literal branch when
needed. Default branch selection is based on returned metadata, not assumed
`main`. Missing access, truncated pages, bypass roles/actors, and a branch tip
different from the assessed source revision remain explicit limitations.
Only complete, primary-branch review/protection predicates can contribute a
review score. A local CODEOWNERS file contributes no enforcement score.

Live lookup is bounded to 40 distinct requests with a 90-second overall budget
checked between calls and a 30-second per-call timeout. Exhausted budgets are
gaps, not proof of missing controls. Live governance has an actual capture time
after requests complete; it cannot
be combined with `--at` or an offline governance input. To review historical
evidence, capture a snapshot and replay it. Settings describe current controls,
not proof that every historical PR received human approval. Contributor counts,
bot commits, and long periods without changes do not establish human maintainer
count, bus factor, or abandonment.

For offline input, `--governance-evidence settings.json` uses this wrapper:

```json
{
  "schema_version": 1,
  "target": "example/demo@main",
  "governance": {
    "schema_version": 1,
    "target": "github.com/example/demo",
    "revision": "main",
    "branch": "main",
    "captured_at": "2026-11-12T00:00:00Z",
    "repository_metadata": {"status": 403, "data": null},
    "branch_info": {"status": 403, "data": null},
    "branch_protection": {"status": 403, "data": null},
    "effective_rules": [{"status": 403, "data": null, "next": false}],
    "rulesets": [{"status": 403, "data": null, "next": false}],
    "ruleset_details": {}
  }
}
```

Replace this deliberately inaccessible example with actual observed response
envelopes; the example records gaps, not control absence. See the
[governance API guide](../../references/code-review/security-review-guide.md)
for a complete snapshot. The wrapper can instead or additionally contain
`maintenance` with matching normalized target/revision/capture time and optional
`repository`, `latest_commit`, `latest_release`, `support`, and `maintainers`
observations. Imported snapshots are **not authenticated live API results**.
Sources, reviewed dates, and self-reported support assertions remain separate.

`--threat-evidence reviewed-threat.json` is independently useful without a forge
account or scanner:

```json
{
  "schema_version": 1,
  "target": "./project",
  "threat_model": {
    "schema_version": 1,
    "target": "./project",
    "revision": "<reviewed revision>",
    "captured_at": "2026-11-12T00:00:00Z",
    "areas": [{
      "scope": "Authentication",
      "source": "Human architecture review",
      "reference": "docs/threat-model.md",
      "reviewed_at": "2026-11-11T00:00:00Z",
      "reviewer": "<reviewer identity>",
      "evidence_type": "manual_observation",
      "coverage": "partial",
      "assets": ["Sessions"],
      "trust_boundaries": ["Untrusted login request to application"],
      "limitations": ["Recovery flow not yet reviewed"]
    }]
  }
}
```

Use the actual requested target and reviewed revision; when an immutable local
commit/digest is known, the revision must match it. Unknown local identity does
not prevent recording a clearly scoped review. Evidence is rendered under
`project_evidence`; a reviewed area does not establish whole-project threat
coverage. References and reviewer claims are not independently authenticated.

Live compatibility checked on November 12, 2026: Cosign 3.1.4 successfully
verified its published checksum-file bundle with an explicitly supplied,
out-of-band trusted root; wrong signer/issuer/digest were rejected. SLSA v0.2/v1
layouts are covered by upstream specimens and tests, but live positive
`slsa-verifier` verification was blocked by public TUF DNS on this host.
Online OSV service access was also DNS-blocked; actual scanner JSON shapes
were checked against an isolated **synthetic** offline database. These are
compatibility boundaries, not findings about the scanned packages.

### Optional inventory and maintainer metadata

These features add contextual observations, not weights or new prerequisites.
Missing optional tools never block local inventory, manual review, or known
critical remediation.

**Generate one local SPDX SBOM.** The artifact input's `sbom` object accepts
exactly one `path` or `generate: true`. For an already-built release:

```json
{
  "schema_version": 1,
  "target": "./dist/release.tgz",
  "artifact": {
    "path": "dist/release.tgz",
    "sha256": "<independently expected 64-character SHA-256>"
  },
  "sbom": {
    "generate": true,
    "scope": "build_output",
    "validate_schema": true
  }
}
```

Paths are relative to the configuration file. For `source_checkout`, use a
local-directory target; no artifact digest or separate `subject_sha256` is
appropriate for source generation. Generation currently supports only explicit
local files/directories on POSIX, not image pulls. It calls an installed Syft
with SPDX JSON 2.3 output, isolated configuration and disabled update/remote
enrichment options. Credentials and target configuration are not inherited.
This is not kernel-enforced network isolation. Time/output/tree traversal are
bounded; source/digest changes during generation reject the result. Private
temporary output is removed; the returned report preserves extracted facts,
not a published SBOM file. For publishing, use the separate release workflow.

`validate_schema` defaults to false. When explicitly true, it uses the pinned
official SPDX 2.3 JSON schema and optional `jsonschema==4.25.1` in an isolated
Python interpreter. Install its pinned requirements only if needed:

```bash
python3 -m pip install -r <installed-skill>/skills/audit/requirements-sbom.txt
```

No schema references are fetched at runtime. Missing validation packages remain
unknown; invalid structure is an error. Format validation does not establish
all semantic consistency, inventory truth, completeness, or downstream
acceptance. The original schema source, digest and license are documented in
the [SBOM guide](../../references/sbom/tools-by-language.md).

When known-vulnerability evidence already exists, `supply_chain_analysis`
matches its exact ecosystem/name/version/purl identities to the inventory.
Paths distinguish described subjects, declared containment, direct/transitive
dependencies, and disconnected components. They do **not** establish code
execution or exploitability. Ambiguity and missing matches are explicit;
no advisory is suppressed or deducted twice, and `score_adjustment` is null.
The existing weighted supply-chain signal is not automatically satisfied by
an incomplete graph or a schema-valid SBOM.

**Read local Security Insights.** `--security-insights <file-or-directory>`
selects one local document or searches the root/`.github/` standard filenames.
Multiple candidates require explicit selection. JSON works with the standard
library; YAML requires the optional pinned parser:

```bash
python3 -m pip install -r <installed-skill>/skills/audit/requirements-metadata.txt
```

The reader rejects duplicate keys, YAML tags/anchors/aliases, oversized input,
unsupported/development schema versions, unsafe credential-bearing URLs, and
conflicting project/repository scope. It records document digest, available
target revision, capture/review/update dates, scope and bounded claims without
copying entire maintainer contact lists. Dates more than 365 days old, future
dates, and review-before-update produce contextual freshness gaps, not a risk
grade. Inheritance and evidence links are **not fetched**.

Optional installed CUE (tested v0.14.2) validates against a byte-pinned copy of
the released v2.2.0 schema; no target-supplied schema is executed. The validator
uses isolated environment/configuration, no stdin and `CUE_REGISTRY=none`.
Without CUE, `schema_validation` remains unknown. Even valid documents are
`self_report`, never independent verification or Baseline credit. An unmatched
or unavailable repository scope cannot become a verified control.

**Discover public registry attestations.** `--registry-evidence` operates only
on an exact npm/PyPI package target. It contacts official `registry.npmjs.org`
or `pypi.org` endpoints, with no inherited proxy credentials, cookies, redirect
following, package download, installation or publishing. It inspects npm
distribution integrity/attestation metadata and individual PyPI wheel/sdist
digests plus PEP 740 Integrity API responses. Results are per distribution,
not a blanket claim for a version with several files.

Requests have bounded response size and elapsed-read time, a 20-second
discovery budget checked between requests, and at most 12 PyPI distributions.
Missing/yanked/malformed/mismatched evidence stays visible; larger releases
are not silently truncated. Publisher/source values and signed-statement
contents remain unverified claims. A completed discovery may have `status: ok`
while **always** retaining `verification: not_verified`.

Optional independently obtained expected digests use
`--registry-digests expected.json` together with `--registry-evidence`:

```json
{
  "schema_version": 1,
  "target": "sampleproject@4.0.0",
  "expected_digests": {
    "sampleproject-4.0.0-py3-none-any.whl": "sha256:<independently expected 64-character digest>"
  }
}
```

Digest association compares expectations with registry metadata, not downloaded
package bytes. It neither authenticates the attestation nor establishes an
expected signer. No SLSA level or risk score is inferred. The lower-level API's
injected request function is for controlled callers/tests; CLI network access
requires the explicit flag. `--at` is rejected with live registry discovery;
capture current metadata and replay its snapshot instead.

The report preserves `security_insights`, `registry_evidence`, and
`supply_chain_analysis` through JSON/Markdown and offline replay. These sections
do not change custom policy v2. Live development checks used published npm/PyPI
metadata and synthetic local Syft inventories; cryptographic registry-attestation
verification remains separate. Public TUF and OSV DNS remained unavailable on
the development host; no alternate untrusted endpoint or verification bypass
was used.

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
or invent a new set of core probes without an explicit policy decision.

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
