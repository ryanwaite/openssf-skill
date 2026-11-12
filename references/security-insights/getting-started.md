# Security Insights 2.2: bounded discovery, ingestion, and authoring

[Security Insights v2.2.0](https://github.com/ossf/security-insights/releases/tag/v2.2.0) is a YAML format for **maintainer self-report**, not independent proof of a control, a substitute for a `SECURITY.md`, or an OSPS Baseline grade. Start by publishing a working private vulnerability contact or policy; a Security Insights file is an optional way to make that information discoverable. No scanner, badge, or release-signing service is required.

## Discover and interpret

With explicit local opt-in, `scripts/security_insights.py` reads a file selected by the caller or discovers one `security-insights.{yml,yaml,json}` in the target directory or its `.github/` directory. Call `discover_security_insights(identity, evaluated_at, project_dir=...)` or `read_security_insights(identity, file_path, evaluated_at)`; `identity` is a resolved local-directory or GitHub-repository target and `evaluated_at` is a timezone-aware ISO-8601 timestamp. A repository-only target needs an explicit **local** directory or file; no remote acquisition takes place. Multiple candidate files require explicit selection. An absent file means **not reported**, not "no controls." The result is JSON-safe `{status, facts, gaps}` with a document SHA-256, capture/evaluation timestamps, target/revision/working-tree provenance, claimed canonical URL and scope matching, dates, validation state, and bounded self-report claims. An explicit repository-target file is *not* cryptographically bound to its selected revision; a dirty local working tree is likewise not a clean revision. Repository identity must match both `repository.url` and the target's entry in `project.repositories` when those sections are present.

The base reader uses the Python standard library for JSON. For YAML, install optional PyYAML in the caller's environment; absent PyYAML produces a targeted gap with no extracted claims. YAML aliases, anchors, explicit tags, merges, and duplicate keys are rejected. Full released-schema validation is attempted only when the `cue` CLI is installed: the pinned `references/security-insights/schema-v2.2.0.cue` is the [v2.2.0 tagged schema at commit `701ac2a02ef17fc8b316f5df685428773c51372a`](https://github.com/ossf/security-insights/blob/701ac2a02ef17fc8b316f5df685428773c51372a/spec/schema.cue), SHA-256 `4e4b61470b5484fc8969f2a8a77ffbe0712a7c8a870c2079188f246c14cd58b1`. The specification is provided under the [upstream Community Specification License 1.0](https://github.com/ossf/security-insights/blob/v2.2.0/LICENSE). Alternatively supply a caller-trusted local byte-identical copy via `schema_path`; never use a schema path from a target document. CUE runs with the trusted schema directory as its working directory, no inherited environment or stdin, `CUE_REGISTRY=none`, and discarded diagnostics; an unavailable CLI means validation is **unknown**, never passed. Development validation with `cue v0.14.2` confirmed standalone vetting against this pinned file accepts synthetic released-schema JSON and YAML and rejects a missing required license. Valid format does not independently verify truth, URLs, security settings, or policy availability. Inheritance URLs are recorded as untrusted claims, **not fetched or resolved**; no user-supplied URL is followed. Unsafe credential/query-bearing URLs are omitted. Dates in the future, review before update, or review older than 365 days produce explicit gaps, not a failing or clean security grade. Project-level policy/support/design and repository-level status/security-policy links are reported separately as `self_report` claims, never numeric score or OSPS Baseline credit.

## Author the first useful file

Use the [released v2.2.0 schema](https://github.com/ossf/security-insights/blob/v2.2.0/spec/schema.cue) and [released minimum example](https://github.com/ossf/security-insights/blob/v2.2.0/examples/example-minimum.yml). The example still says `schema-version: 2.0.0`; for a **v2.2.0** file, use `2.2.0` and validate against the released schema, not `main`, `-dev`, or an earlier example's field names. In v2.2.0, vulnerability reporting uses **`project.vulnerability-reporting.policy`**, not `security-policy` in that project object; the separate `repository.documentation.security-policy` URL is valid. Add `project.documentation.design` only when design documentation exists.

```yaml
header:
  schema-version: 2.2.0
  last-updated: '2026-11-09'
  last-reviewed: '2026-11-09'
  url: https://github.com/owner/repo/raw/refs/heads/main/.github/security-insights.yml
project:
  name: Example Project
  administrators:
    - name: Example Maintainer
      primary: true
  repositories:
    - name: repo
      url: https://github.com/owner/repo
      comment: Primary source repository
  vulnerability-reporting:
    reports-accepted: true
    bug-bounty-available: false
    policy: https://github.com/owner/repo/blob/main/SECURITY.md
repository:
  url: https://github.com/owner/repo
  status: active
  accepts-change-request: true
  accepts-automated-change-request: false
  core-team:
    - name: Example Maintainer
      primary: true
  license:
    url: https://github.com/owner/repo/blob/main/LICENSE
    expression: MIT
  security:
    assessments:
      self:
        comment: No formal self-assessment has been completed.
```

Replace **all** illustrative values, dates, URLs, licensing and truth values before publishing; do not claim a completed assessment by adding a placeholder. Place the real file in the root or `.github/` and validate with the [tagged CUE schema](https://github.com/ossf/security-insights/tree/v2.2.0/spec) using `cue vet -d '#SecurityInsights' ./spec path/to/security-insights.yml` from a v2.2.0 schema checkout (or an equivalent released schema validator). This validation checks structure, **not truth**. Later, add only factual release attestations, tooling, and evidence URLs that you actually maintain; re-review and update the dates when the contents change.
