# OSPS Baseline Level 1 Checklist (2026.08.28)

Use the [versioned OSPS Baseline checklist](https://github.com/ossf/security-baseline/blob/main/docs/versions/2026-08-28-checklist.md) and [catalog](https://baseline.openssf.org/versions/2026-08-28) as the authority for control text, levels, and applicability. This is the complete Level 1 requirement list for that version, not a score or an automated compliance determination. The 2026.08.28 release uses Gemara v1 catalog and machine-readable mappings; mappings to other frameworks do not establish compliance with those frameworks.

Start with one missing, high-impact control: publish a security contact (**OSPS-VM-02.01**), protect the primary branch (**OSPS-AC-03.01**), or isolate untrusted CI code (**OSPS-BR-01.03**). Record the repository setting, policy URL, or release artifact that demonstrates it; do not wait for a scanner, badge, SBOM, or signing service. Mark a condition-specific requirement not applicable only with a reason (for example, no releases yet); mark inaccessible settings as **unknown**, not passed.

## Access control

- [ ] **OSPS-AC-01.01**: When a user attempts to read or modify a sensitive resource in the project's authoritative repository, the system MUST require the user to complete a multi-factor authentication process. Check maintainer access and the forge's MFA policy; public read access is not a sensitive resource.
- [ ] **OSPS-AC-02.01**: When a new collaborator is added, the version control system MUST require manual permission assignment, or restrict the collaborator permissions to the lowest available privileges by default. Inspect new-collaborator defaults, not just existing roles.
- [ ] **OSPS-AC-03.01**: When a direct commit is attempted on the project's primary branch, an enforcement mechanism MUST prevent the change from being applied. Inspect the effective branch/ruleset policy, including bypass actors.
- [ ] **OSPS-AC-03.02**: When an attempt is made to delete the project's primary branch, the version control system MUST treat this as a sensitive activity and require explicit confirmation of intent. Verify the forge's behavior or policy separately from direct-commit protection.

## Build and release

- [ ] **OSPS-BR-01.01**: When a CI/CD pipeline operates on untrusted metadata, those parameters MUST be sanitized and validated prior to use in the pipeline. Inspect event fields used in shell/scripts; passing untrusted data through an environment variable avoids expression injection but does not replace input validation.
- [ ] **OSPS-BR-01.03**: When a CI/CD pipeline operates on untrusted code snapshots, it MUST prevent access to privileged CI/CD credentials and assets. Separate untrusted PR build/test from deployment, release credentials, and privileged runners.
- [ ] **OSPS-BR-03.01**: When the project lists a URI as an official project channel, that URI MUST be exclusively delivered using encrypted channels. Review published project URLs.
- [ ] **OSPS-BR-03.02**: When the project lists a URI as an official distribution channel, that channel MUST be protected from adversary-in-the-middle attacks using cryptographically authenticated channels. Inspect official release/download channels.
- [ ] **OSPS-BR-07.01**: The project MUST prevent the unintentional storage of unencrypted sensitive data, such as secrets and credentials, in the version control system. Check secret-handling controls and investigate any detected leaks; a clean scanner result alone is not proof.

## Documentation and governance

- [ ] **OSPS-DO-01.01**: When the project has made a release, the project documentation MUST include user guides for all basic functionality.
- [ ] **OSPS-DO-02.01**: When the project has made a release, the project documentation MUST include a guide for reporting defects.
- [ ] **OSPS-GV-02.01**: The project MUST have one or more mechanisms for public discussions about proposed changes and usage obstacles.
- [ ] **OSPS-GV-03.01**: The project documentation MUST include an explanation of the contribution process, or clearly state that public contributions are not accepted. The explicit no-public-contributions option is part of the 2026.08.28 requirement.

## Licensing

- [ ] **OSPS-LE-02.01**: The license for the source code MUST meet the OSI Open Source Definition or the FSF Free Software Definition.
- [ ] **OSPS-LE-02.02**: The license for the released software assets MUST meet the OSI Open Source Definition or the FSF Free Software Definition.
- [ ] **OSPS-LE-03.01**: The license for the source code MUST be maintained in the corresponding repository's LICENSE file, COPYING file, LICENSES/ directory, or LICENSE/ directory. `LICENSES/` is explicitly accepted in 2026.08.28.
- [ ] **OSPS-LE-03.02**: The license for the released software assets MUST be included in the released source code, or in a LICENSE file, COPYING file, or LICENSE/ directory alongside the corresponding release assets.

## Quality and vulnerability management

- [ ] **OSPS-QA-01.01**: The project's source code repository MUST be publicly readable at a static URL.
- [ ] **OSPS-QA-01.02**: The version control system MUST contain a publicly readable record of all changes made, who made the changes, and when the changes were made.
- [ ] **OSPS-QA-02.01**: When the package management system supports it, the source code repository MUST contain a dependency list that accounts for the direct language dependencies.
- [ ] **OSPS-QA-04.01**: Projects with multiple repositories MUST document a list of codebases that are part of the project.
- [ ] **OSPS-QA-05.01**: The version control system MUST NOT contain generated executable artifacts.
- [ ] **OSPS-QA-05.02**: The version control system MUST NOT contain unreviewable binary artifacts.
- [ ] **OSPS-VM-02.01**: The project documentation MUST contain security contacts. Add a private reporting channel as a practical next step; a documented private channel is an additional Level 2 requirement (**OSPS-VM-03.01**).

## Avoid moving higher-level controls into Level 1

**OSPS-AC-04.01** (default CI task permissions), **OSPS-BR-06.01** (signed releases), and **OSPS-QA-06.01** (automated tests before accepting commits) are **Level 2**. **OSPS-QA-07.01** (non-author human approval before merging into the primary branch) is **Level 3**. Review is useful even before Level 3, but do not claim it is an L1 requirement. **OSPS-BR-01.02** was removed in the 2026.02.19 release; do not resurrect it.

See the [2026.08.28 release notes](https://github.com/ossf/security-baseline/blob/main/docs/release_notes.md) for version changes. The [Baseline FAQ](https://github.com/ossf/security-baseline/blob/main/docs/faq.md) explicitly excludes scoring/grading projects, comparing projects, and treating the Baseline as regulatory certification. Evidence may require manual verification; absence of a particular automation is not proof a control is unmet.
