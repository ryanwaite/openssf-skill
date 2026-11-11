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

For a later maturity upgrade, bind SBOM and provenance to the **same shipped artifact digest**, publish verification instructions, and enforce identity/issuer/digest policy in the consuming deployment. None of those optional integrations is required before taking the first signing step.
