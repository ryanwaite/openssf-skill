# Security Insights 2.2: bounded discovery and authoring

[Security Insights v2.2.0](https://github.com/ossf/security-insights/releases/tag/v2.2.0) is a YAML format for **maintainer self-report**, not independent proof of a control, a substitute for a `SECURITY.md`, or an OSPS Baseline grade. Start by publishing a working private vulnerability contact or policy; a Security Insights file is an optional way to make that information discoverable. No scanner, badge, or release-signing service is required.

## Discover and interpret

Look for `security-insights.yml` in a repository root or forge directory such as `.github/`. Read `header.schema-version`, `header.last-updated`, `header.last-reviewed`, and `header.url`; associate the report with the specific commit or release you are examining. Check any `header.project-si-source` project inheritance, review project and repository scopes separately, and follow linked security policies to confirm they remain accessible. **No file** means "not reported here", not "no security controls"; a file with old dates is a prompt for maintainer follow-up, not a finding of noncompliance. Treat all claims as unverified until separately supported by artifacts and current settings.

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
