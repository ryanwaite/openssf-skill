# SLSA Build and Source Tracks (v1.2)

[SLSA v1.2](https://slsa.dev/spec/v1.2/) separates **Build** and **Source** requirements. A Build provenance statement is not a Source-track attestation. The stable Build predicate remains `https://slsa.dev/provenance/v1` (not `/v1.2`). Assess the **specific build and distributed artifact**, not the repository as a whole; no one workflow or generator automatically grants every Build Level 3 requirement.

| Build level | Starting point | Additional assurance to check |
|-------------|----------------|------------------------------|
| L1 | Generate provenance bound to the built artifact | Explain where consumers find it and what it describes. |
| L2 | Use a hosted build platform and authenticated provenance | Verify provenance identity, subject digest, and source. |
| L3 | Harden the build platform against tampering | Evaluate builder isolation, build definitions, provenance generation, distribution and verification against v1.2 requirements. |

Start with **one** release artifact. Build it, record its SHA-256 digest, and publish provenance for that digest. A consumer should independently obtain the artifact and provenance, check the digest and expected source ref and builder identity, and fail closed on mismatch. Signing a hand-authored JSON object does **not** attest to the actual build. Other controls (SBOM, scanner, signing separate blobs) can be adopted independently.

## GitHub Actions: two independent paths

1. For an existing GitHub-hosted workflow, [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) provide a bounded start using `actions/attest@v4` for an actual build output, followed by `gh attestation verify <artifact> --repo owner/repo`. Give the attesting job only required permissions (`id-token: write`, `attestations: write`, and `contents: read`; add `artifact-metadata: write` only if the chosen attestation path requires it). Verify subject digest, source, and signer/builder identity; availability and permissions vary by repository/plan.
2. The [SLSA GitHub generator v2.1.0](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/generic/README.md) can generate provenance for generic files. Adapt [`workflows/slsa-provenance.yml.template`](../../workflows/slsa-provenance.yml.template) to the real build and release trigger; give it hashes of **those files**, not a source tree or a placeholder. The generator's reusable workflow **must** use a full version tag (`@v2.1.0`); a SHA or abbreviated tag breaks its builder identity check. This is a narrow exception to normal SHA-pinned action guidance. Other actions remain SHA-pinned. Its generation/isolation features alone do not establish end-to-end Build L3.

For a released file, verify with [slsa-verifier v2.7.1](https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.1):

```bash
# Fetch the actual release file and its .intoto.jsonl provenance first.
# For several subjects the generic generator defaults to multiple.intoto.jsonl.
slsa-verifier verify-artifact dist/myapp \
  --provenance-path dist/myapp.intoto.jsonl \
  --source-uri github.com/owner/repo \
  --source-tag v1.0.0
```

Verify the verifier's installed version and the expected builder identity in the resulting statement, including the **full semver generator tag** for this template. Match both the file digest and the source tag/commit against a trusted expected value. Do not assume a `--source-uri` match alone authenticates a release. For images, use an actual image digest and the documented [container generator](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/container/README.md) or an attestations path; `docker/build-push-action` exposes `digest` but not a built-in `image` output. If setting a job `image` output, define an `id` on your own step writing it to `$GITHUB_OUTPUT`.

The [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/) is the authority for levels; [in-toto](https://in-toto.io/) defines attestation envelopes. Manual verification of builder isolation and the consumer's verification policy remains necessary even if provenance is generated automatically.

Other hosted build systems can publish provenance too; assess the actual builder, artifact digest, and consumer verification policy against the same Build track before making a level claim. A signed statement from a generic CI script, a self-hosted persistent runner, or a hand-written provenance file is not automatically equivalent to a hardened builder.
