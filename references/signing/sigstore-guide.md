# Sigstore: Sign and Verify a Release Artifact

Signing is a **separate release control**, not a prerequisite for publishing a security policy, remediating a dependency, or generating an SBOM. First identify one actual release artifact and its expected digest, signer identity, and OIDC issuer. Then sign, publish verification material, and test verification as a consumer. OSPS **BR-06.01** (signed releases or a signed manifest covering every asset) is **Level 2**, not a Level 1 prerequisite.

## Cosign 3.1.4

Use the [Cosign v3.1.4 release](https://github.com/sigstore/cosign/releases/tag/v3.1.4) appropriate to your OS, and verify its published checksum before running it. If building with Go, use `go install github.com/sigstore/cosign/v3/cmd/cosign@v3.1.4` with a compatible Go toolchain; the former `/v2` module path is not a Cosign v3 installation. The v3 series began at **v3.0.1**, not a published v3.0.0. Run `cosign version` and review the [versioned command reference](https://github.com/sigstore/cosign/tree/v3.1.4/doc) before changing release automation.

### Single local blob: smallest complete flow

```bash
# Replace the filename; keyless signing opens an OIDC login when not in CI.
cosign sign-blob --yes --bundle myapp.tar.gz.sigstore.json myapp.tar.gz
sha256sum myapp.tar.gz

# Copy the artifact, its bundle, and the expected SHA-256 digest to the consumer.
# Replace the policy values with the actual expected signer and issuer.
sha256sum myapp.tar.gz
cosign verify-blob --bundle myapp.tar.gz.sigstore.json \
  --certificate-identity 'maintainer@example.org' \
  --certificate-oidc-issuer 'https://accounts.google.com' \
  myapp.tar.gz
```

Compare the **received** file's digest with a digest obtained through a trusted channel, then verify the bundle against the expected identity and issuer. The bundle is **required for this flow**: it carries the signature, certificate, and transparency-log verification material. Publish it next to the exact release asset; a `.sig` and `.cert` pair from an older example is not a substitute for this v3 bundle workflow. Signing the file does not establish that it came from the expected source or that dependencies are safe.

For private Sigstore deployments, establish and distribute an independently trusted root and appropriate signing configuration; Cosign 3 uses a TUF-provided signing configuration and trust material by default for the public service. Use `--trusted-root` only with a root whose provenance you have validated. Do not turn off certificate, transparency-log, or trust checks to make verification pass. For offline verification, provide the bundle **and** independently trusted root, and verify the configured policy. See [Cosign signing configuration](https://github.com/sigstore/cosign/blob/v3.1.4/doc/cosign_signing-config.md) and [trusted roots](https://github.com/sigstore/cosign/blob/v3.1.4/doc/cosign_trusted-root.md).

### OCI image

Sign the immutable image digest after pushing the image:

```bash
# Replace the example with the digest returned by the image push.
cosign sign --yes 'ghcr.io/owner/image@sha256:<actual-64-hex-digest>'
cosign verify \
  --certificate-identity 'https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  'ghcr.io/owner/image@sha256:<actual-64-hex-digest>'
```

Registry signature discovery may use legacy Cosign tag storage or OCI 1.1 referrers depending on registry/tool support; check the registry's referrers behavior before enforcing a policy. Never verify only a mutable tag, assume a signer from an arbitrary certificate, or set `COSIGN_EXPERIMENTAL=1` (not needed for the v3 keyless flow). Grant `id-token: write` **only to the GitHub Actions job that needs keyless OIDC**; restrict registry write permission to the signing/publishing job.

For other signing needs, [Gitsign](https://github.com/sigstore/gitsign) addresses Git commits rather than release asset signatures; [sigstore-python](https://github.com/sigstore/sigstore-python) and [sigstore-js](https://github.com/sigstore/sigstore-js) expose language-specific flows. Rekor is a transparency log, not a substitute for checking the signer identity or artifact digest. If enforcing admission with a [Sigstore policy controller](https://docs.sigstore.dev/policy-controller/overview/), first test a policy against a known-good digest and explicitly chosen issuer/identity; make admission blocking only after that policy is verified. These are optional next steps, not prerequisites to signing one blob.

## Package-registry alternatives (context-dependent)

- **npm trusted publishing** is an OIDC-based publishing option for supported providers/runners. Configure a publisher in npm, use npm **11.5.1+** and Node.js **22.14+** where applicable, grant the job `id-token: write`, and check the [current provider and runner restrictions](https://docs.npmjs.com/trusted-publishers/). `npm publish --provenance` applies only when its required CI/registry conditions are met; npm 9.5+ does **not** make every publication automatically carry provenance. Verify the actual published package and its attestation rather than inferring it from a command.
- **PyPI trusted publishing** may attach a [PEP 740 attestation](https://docs.pypi.org/attestations/) **per distribution**. Confirm that each wheel and sdist has the expected attestation and digest; an attestation does not independently prove source correctness or satisfy SLSA Build Level 3.

### Read-only public registry discovery

For an **exact-version package target**, `scripts/registry_evidence.py` exposes
`discover_registry_evidence(target, *, allow_fetch=False, request=None, expected_digests=None)`.
The target is the package dictionary returned by `target_identity.resolve_target(...)`.
Public network access is **off by default**; pass `allow_fetch=True` explicitly.
`request(url) -> bytes` is an alternative opt-in for in-memory/offline tests;
it must enforce its own I/O bounds if used with a real network. Optional
`expected_digests` maps exact distribution filenames to independently obtained
`sha256:<hex>` or `sha512:<hex>` strings. Without such a value, a registry digest
is **observed metadata only**, not a comparison to a locally held artifact.

The function returns JSON-safe `{status, facts, gaps}`. An `ok` status means
**discovery completed**, never that a signature was verified. Both the top-level
`facts.verification` and each attestation's `verification` are `not_verified`;
`gaps` always records that signatures remain unverified and digest association
is not trust. The report never assigns a signer identity, SLSA level, or security
grade. Credential-bearing publisher/source claims are omitted from the report.
Each npm tarball or PyPI wheel/sdist gets its own digest, source URL, expected
digest comparison (when supplied), attestation status (`discovered`, `absent`,
`unknown`, or `error`), and signed-statement *subject-to-registry-digest*
comparison. Publisher/source values and DSSE statement contents are **unverified
claims**. An absent attestation is distinct from an inaccessible provenance
endpoint (e.g., PyPI 403) and a yanked file remains explicitly marked yanked.
For enforcement, use a verifier that independently checks the exact artifact,
signature, trust root, transparency log, and separately configured expected
signer/issuer; do not derive expected policy from the discovered claims.

### Local npm registry-attestation verification (optional)

`scripts/registry_verification.py` offers
`verify_registry_distribution(identity, config, *, allow_network_trust=False)`
for **one exact npm tarball** with a SLSA provenance v1 Sigstore DSSE bundle
(v0.3). This is separate from discovery and does not fetch or install a
package. `identity` is an exact-version package target from
`target_identity.resolve_target(...)`. `config` requires:

- `filename` (e.g. `semver-7.7.3.tgz`), `artifact_path` (already downloaded
  local tarball), and `bundle_path` (already obtained local Sigstore JSON
  bundle for **that** tarball);
- `expected_digest` (`sha512:<128 hex digits>`, independently obtained, not
  copied from registry metadata), `certificate_identity` (exact Fulcio signer
  identity), `certificate_oidc_issuer` (exact issuer URL), and
  `source_repository` (exact expected HTTPS repository URL);
- `predicate_type: "https://slsa.dev/provenance/v1"`; optionally
  `source_ref`, `source_path`, and `builder_id` for tighter signed-claim checks;
- optionally `trusted_root_path` to an **independently validated** Sigstore
  TrustedRoot JSON. Without this file, the default result is `unknown` and no
  network trust lookup is attempted. Setting `allow_network_trust=True`
  explicitly permits Cosign's public Sigstore TUF trust lookup instead.

The verifier requires a locally installed [Cosign 3.1.4](https://github.com/sigstore/cosign/releases/tag/v3.1.4)
(`cosign verify-blob-attestation`). It compares the local bytes with the
independently expected digest, checks that the signed statement contains exactly
the expected package/version, digest, predicate, and source assertions, then
uses Cosign to verify DSSE signature, Fulcio certificate identity/issuer,
SCT, transparency-log proof, and digest claim. It does **not** disable those
checks or infer any policy from registry responses. `ok` denotes verification
of **that one** distribution only; `facts.signature`, `facts.signer`, and
`facts.source_assertion` describe distinct checks; `facts.builder_assertion`
is `authenticated` only if an independently expected `builder_id` matched.
A source assertion
authenticated by a signer is not independent proof the source is correct or
that a SLSA level has been attained. Invalid digest/identity/signature returns
`error`; missing trust/tool/material or unsupported layout returns `unknown`.
The function emits no verifier stdout/stderr (which could contain private
details). It bounds local artifact hashing (256 MiB, 12 seconds), JSON input
(512 KiB), and the verifier run (18 seconds); larger files remain `unknown`.
A private, system-temporary 0700 snapshot directory holds read-only copies of
the exact artifact, bundle, and optional root used for parsing **and** Cosign;
it is removed on success and failure. Symlinks and special-file inputs are
rejected. If any original or snapshot changes during verification, no
affirmative result is issued. This safe file-snapshot path currently requires
POSIX file APIs; unavailable platform support remains unknown rather than
breaking basic advice. The target and caller directory need not be writable.
An `ok` result includes SHA-256 digests of the
verified snapshots (`facts.snapshot_sha256`), the independently expected
certificate identity and issuer, and `facts.verifier.captured_at`; the
executable's exact version is explicitly `unrecorded` (install/check Cosign
v3.1.4 yourself). These digests identify the verified bytes, not a guarantee
that a mutable original file will remain unchanged after the call returns.
A caller that reads policy from disk must confine all paths to its approved
directory and never use untrusted metadata to fill policy fields.

**PyPI PEP 740** uses a different envelope representation; this Cosign-only
API explicitly returns `unknown` for PyPI rather than treating an envelope as
a bundle or claiming verification of a wheel/sdist. Use a PEP 740-aware
verifier such as the [`pypi-attestations` public API](https://github.com/pypi/pypi-attestations)
with an independently set identity and trust policy for PyPI. Never promote
the read-only discovery `not_verified` status based on metadata alone.

Validation example (2026-11-13): `semver-7.8.6.tgz` from
[`registry.npmjs.org/semver/-/semver-7.8.6.tgz`](https://registry.npmjs.org/semver/-/semver-7.8.6.tgz)
and its SLSA v1 v0.3 bundle from
[`/-/npm/v1/attestations/semver@7.8.6`](https://registry.npmjs.org/-/npm/v1/attestations/semver@7.8.6)
verified `ok` offline with checksum-checked Cosign v3.1.4
(`sha256:424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`).
The separately obtained expected SHA-512 came from the `node_modules/semver`
entry in [npm/cli's committed lockfile](https://github.com/npm/cli/blob/8f92e740ee1547568779284005454ce2f1a5e58b/package-lock.json);
the local TrustedRoot came from the
[Sigstore root-signing repository](https://github.com/sigstore/root-signing/blob/730ca4cf59d1ba36ccc06d9d7064dac508f7608a/targets/trusted_root.json),
not from package metadata. The expected GitHub Actions signer workflow was
independently checked in
[npm/node-semver](https://github.com/npm/node-semver/blob/b37b033b585ad5e575afeccadb426ea41bc6cea4/.github/workflows/release-integration.yml):
`https://github.com/npm/node-semver/.github/workflows/release-integration.yml@refs/heads/main`;
the issuer was `https://token.actions.githubusercontent.com` and the
independent expected source was `https://github.com/npm/node-semver`. The
signed source-workflow path is `.github/workflows/release.yml`, independently
checked in the [caller workflow at the same commit](https://github.com/npm/node-semver/blob/b37b033b585ad5e575afeccadb426ea41bc6cea4/.github/workflows/release.yml);
it is distinct from the reusable signer workflow `release-integration.yml`.
Do not assume those identities are interchangeable. The integrated CLI also
verified this specimen with private input snapshots; wrong source path/ref,
digest and signer expectations remained failures, not automatically relaxed
policy. This
example trusts the pinned official GitHub root-signing repository as an
out-of-band source; its TUF chain was **not independently validated** in this
environment (TUF CDN DNS was unavailable). Altering the real bundle signature
or expected certificate identity failed verification. Unit-test positive
results that mock Cosign are API contract tests, **not** cryptographic proof.

### Discovery endpoint details

Only official fixed HTTPS API endpoints are queried. npm uses
[`GET /{package}/{version}`](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
at `registry.npmjs.org` for `dist.integrity` and, if advertised, its
`dist.attestations.url` at `/-/npm/v1/attestations/{package}@{version}`. Scoped
names encode the slash as `%2F`; the returned URL is checked against the exact
package/version before fetching. PyPI uses
[`GET /pypi/{project}/{version}/json`](https://docs.pypi.org/api/json/)
for *individual* distribution filenames and SHA-256 digests, then
[`GET /integrity/{project}/{version}/{filename}/provenance`](https://docs.pypi.org/api/integrity/)
for each file (PEP 740). PyPI's version JSON `provenance: null` does **not**
establish that the Integrity API has no provenance. No tarball/wheel is fetched,
no arbitrary URL from metadata is followed, and redirects are refused.
Requests have a 3-second timeout, 20-second discovery budget, 512-KiB response
cap, and at most 12 PyPI distributions; larger/unavailable responses remain
unknown/error rather than becoming positive evidence. Public registry metadata
may change; use an independently obtained digest for release identity.

For a later maturity upgrade, bind SBOM and provenance to the **same shipped artifact digest**, publish verification instructions, and enforce identity/issuer/digest policy in the consuming deployment. None of those optional integrations is required before taking the first signing step.
