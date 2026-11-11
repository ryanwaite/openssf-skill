# OpenSSF Best Practices Badge

The [Best Practices Badge](https://www.bestpractices.dev/) records project **self-reported** practices. It is not independent certification or an OSPS Baseline grade. Start by documenting a security contact and vulnerability reporting policy, then answer only the criteria you can substantiate. A badge account or all-tools setup is not required to improve those controls.

## Choose the appropriate track

| Track | What it describes | Next step |
|-------|-------------------|-----------|
| `baseline-1`, `baseline-2`, `baseline-3` | OSPS Baseline-specific badge levels | Use the [versioned OSPS requirements](https://baseline.openssf.org/versions/2026-08-28), record evidence and the version assessed. Do not equate these with Passing/Silver/Gold. |
| `passing`, `silver`, `gold` | Best Practices criteria and progressively broader project practices | Start with Passing and complete unmet criteria with dated evidence. |

These are distinct tracks, not interchangeable scores. [OpenSSF's Baseline badge announcement](https://openssf.org/blog/2026/02/25/getting-an-openssf-baseline-badge-with-the-best-practices-badge-system/) describes `baseline-1/2/3` alongside existing badge levels. Badge service catalogs, JSON proposal/import support (including `.bestpractices.json`), and individual criteria may lag a published Baseline version; check the **live** service catalog/version before making a claim. A proposed/imported JSON response is not an issued badge or verified assessment. Never infer a live badge level solely from a local checklist or a stale API response.

## Minimal path

1. Publish one relevant artifact (for example `SECURITY.md` with a reachable security contact), without creating a badge entry.
2. On [bestpractices.dev](https://www.bestpractices.dev/), register the public project and select the intended track; follow the service's live prompts. Record **met**, **unmet**, **not applicable with rationale**, or **unknown**, and attach a policy URL, repository setting, or release artifact where applicable.
3. Address the highest-impact missing requirement first (such as compromised maintainer access or untrusted CI credentials). Revisit the entry when practices or catalog versions change. Display the badge only after the service issues the relevant level:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

Replace `XXXXX` with the service-assigned project ID; verify the displayed badge's track and level. A passing badge does not prove signed releases or a Baseline level; a baseline badge does not by itself establish the Best Practices Gold level. Check the [service documentation](https://www.bestpractices.dev/en) and [OSPS Baseline FAQ](https://github.com/ossf/security-baseline/blob/main/docs/faq.md) for scope and interpretation. Scorecard may consume badge information but cannot turn self-report into independent evidence.
