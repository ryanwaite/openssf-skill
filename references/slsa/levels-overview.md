# SLSA Framework Overview

SLSA (Supply-chain Levels for Software Artifacts) is a security framework for protecting the integrity of software builds. It defines levels of increasing security guarantees.

## What is SLSA?

SLSA addresses supply chain attacks by ensuring:
- **Source integrity**: Code comes from the expected repository
- **Build integrity**: Builds are reproducible and tamper-resistant
- **Provenance**: Artifacts include verifiable build metadata

## SLSA Levels

| Level | Summary | Trust Requirements |
|-------|---------|-------------------|
| **Level 0** | No guarantees | - |
| **Level 1** | Provenance exists | Documentation only |
| **Level 2** | Signed provenance | Hosted build service |
| **Level 3** | Hardened builds | Hardened build platform |

### Level 0: No SLSA
- No provenance
- No build integrity guarantees
- Most projects start here

### Level 1: Provenance Exists
**Goal**: Make builds auditable

Requirements:
- [ ] Build process is documented
- [ ] Provenance is generated (metadata about how artifact was built)
- [ ] Provenance includes: builder, source, build config

**What you get**:
- Basic supply chain visibility
- Ability to investigate incidents

### Level 2: Signed Provenance
**Goal**: Prevent tampering after build

Requirements (Level 1 plus):
- [ ] Provenance is signed by the build service
- [ ] Build runs on a hosted platform (not local)
- [ ] Source is version-controlled

**What you get**:
- Tamper-evident provenance
- Harder for attackers to forge build metadata

### Level 3: Hardened Builds
**Goal**: Prevent tampering during build

Requirements (Level 2 plus):
- [ ] Build runs in an isolated, ephemeral environment
- [ ] Build definition comes from source (not editable at build time)
- [ ] No direct human access during build
- [ ] Secrets are injected, not embedded

**What you get**:
- Protection against compromised build infrastructure
- Protection against insider threats
- Strongest practical guarantees

---

## Provenance

Provenance is metadata that describes how an artifact was built.

### SLSA Provenance v1.0 Format

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "my-artifact.tar.gz",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/slsa-framework/slsa-github-generator/...",
      "externalParameters": {
        "repository": "https://github.com/owner/repo",
        "ref": "refs/tags/v1.0.0"
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
      },
      "metadata": {
        "invocationId": "https://github.com/owner/repo/actions/runs/123456"
      }
    }
  }
}
```

### Key Provenance Fields

| Field | Description |
|-------|-------------|
| `subject` | The artifact(s) this provenance describes |
| `buildType` | Type of build (e.g., GitHub Actions, Google Cloud Build) |
| `builder.id` | Identity of the build service |
| `externalParameters` | Inputs that triggered the build (repo, ref) |
| `invocationId` | Link to the specific build run |

---

## Implementing SLSA with GitHub Actions

### Level 1: Basic Provenance

```yaml
name: Build with Provenance

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: make build

      - name: Generate provenance
        run: |
          echo '{
            "builder": "github-actions",
            "buildTimestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
            "source": {
              "repository": "${{ github.repository }}",
              "ref": "${{ github.ref }}",
              "sha": "${{ github.sha }}"
            }
          }' > provenance.json

      - uses: actions/upload-artifact@v4
        with:
          name: artifacts
          path: |
            dist/*
            provenance.json
```

### Level 2-3: SLSA GitHub Generator (Recommended)

Use the official SLSA generator for Level 2/3 provenance:

```yaml
name: SLSA Provenance

on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write  # Required for signing

jobs:
  build:
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build artifacts
        run: |
          make build
          # Creates dist/my-binary

      - name: Generate digests
        id: hash
        run: |
          cd dist
          sha256sum * > checksums.txt
          echo "digests=$(base64 -w0 checksums.txt)" >> $GITHUB_OUTPUT

      - uses: actions/upload-artifact@v4
        with:
          name: artifacts
          path: dist/

  provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.digests }}"
      upload-assets: true  # Attach to release

  release:
    needs: [build, provenance]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: artifacts
          path: dist/

      - uses: softprops/action-gh-release@v1
        with:
          files: dist/*
```

### Container Images with SLSA

```yaml
name: Container SLSA

on:
  push:
    tags: ['v*']

jobs:
  build:
    outputs:
      image: ${{ steps.build.outputs.image }}
      digest: ${{ steps.build.outputs.digest }}
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      - name: Output digest
        run: |
          echo "image=ghcr.io/${{ github.repository }}" >> $GITHUB_OUTPUT
          echo "digest=${{ steps.build.outputs.digest }}" >> $GITHUB_OUTPUT

  provenance:
    needs: build
    permissions:
      packages: write
      id-token: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
      registry-username: ${{ github.actor }}
    secrets:
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

---

## Verifying SLSA Provenance

### Using slsa-verifier

```bash
# Install
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify binary
slsa-verifier verify-artifact my-binary \
  --provenance-path my-binary.intoto.jsonl \
  --source-uri github.com/owner/repo \
  --source-tag v1.0.0

# Verify container
slsa-verifier verify-image ghcr.io/owner/repo@sha256:abc123... \
  --source-uri github.com/owner/repo
```

### Verification Checks

The verifier confirms:
- Provenance was signed by a trusted builder
- Source repository matches expected
- Build ref/tag matches expected
- No tampering occurred

---

## SLSA for Different Build Systems

### Google Cloud Build
- Native SLSA Level 3 support
- Provenance generated automatically
- Configure with `requestedVerifyOption: VERIFIED`

### GitLab CI
- Use `cosign` for signing
- Generate provenance with custom scripts
- Level 2 achievable with managed runners

### CircleCI
- Use orbs for SLSA
- Level 2 with cloud runners
- Custom provenance generation needed

### Jenkins
- Most complex to achieve SLSA
- Consider migrating to cloud-native CI
- Level 1 achievable with documentation

---

## SLSA Compliance Checklist

### Level 1 Checklist
- [ ] Build process documented
- [ ] Provenance generated for releases
- [ ] Provenance includes builder identity
- [ ] Provenance includes source reference
- [ ] Provenance distributed with artifacts

### Level 2 Checklist
- [ ] All Level 1 requirements
- [ ] Provenance cryptographically signed
- [ ] Build runs on hosted service (not local)
- [ ] Source comes from version control
- [ ] Signature verifiable by consumers

### Level 3 Checklist
- [ ] All Level 2 requirements
- [ ] Build environment is ephemeral
- [ ] Build environment is isolated
- [ ] Build config comes from source
- [ ] No human access during build
- [ ] Secrets not in build config

---

## Common Pitfalls

### Level 2 Pitfalls
- Using self-hosted runners (reduces trust)
- Not setting `id-token: write` permission
- Forgetting to pin GitHub Actions to hashes

### Level 3 Pitfalls
- Allowing build config modifications at runtime
- Using persistent build environments
- Embedding secrets in workflow files

---

## Benefits by Level

| Benefit | L1 | L2 | L3 |
|---------|----|----|-----|
| Audit trail | ✓ | ✓ | ✓ |
| Tampering detection (post-build) | | ✓ | ✓ |
| Tampering prevention (during build) | | | ✓ |
| Insider threat protection | | | ✓ |
| Compliance evidence | ✓ | ✓ | ✓ |

---

## References

- [SLSA Specification](https://slsa.dev/spec/v1.0/)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [SLSA Verifier](https://github.com/slsa-framework/slsa-verifier)
- [in-toto Framework](https://in-toto.io/)
- [Sigstore](https://sigstore.dev/)
