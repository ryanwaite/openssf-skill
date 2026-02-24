# Sigstore: Artifact Signing & Verification

Sigstore is an open-source project under the OpenSSF that provides free, easy-to-use tools for signing, verifying, and protecting software artifacts. It eliminates the need for managing long-lived signing keys.

## Why Sigstore?

Traditional code signing requires:
- Generating and storing private keys securely
- Managing key rotation and revocation
- Distributing public keys to verifiers

Sigstore solves this with **keyless signing** — developers authenticate via OpenID Connect (GitHub, Google, Microsoft), and Sigstore issues short-lived certificates tied to their identity.

---

## Sigstore Components

| Component | Purpose |
|-----------|---------|
| **Cosign** | Sign and verify container images and blobs |
| **Fulcio** | Certificate authority — issues short-lived certificates |
| **Rekor** | Transparency log — immutable record of signing events |
| **Gitsign** | Sign Git commits with Sigstore |
| **sigstore-python** | Python library and CLI for signing/verification |
| **sigstore-js** | JavaScript/TypeScript library for signing/verification |

---

## Cosign: Container Image Signing

### Installation

```bash
# macOS
brew install cosign

# Linux (Go install)
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Verify installation
cosign version
```

### Keyless Signing (Recommended)

```bash
# Sign a container image (opens browser for OIDC authentication)
cosign sign myregistry.io/myimage:v1.0.0

# Sign with GitHub Actions OIDC (no browser needed in CI)
cosign sign myregistry.io/myimage@sha256:abc123...
```

### Keyless Verification

```bash
# Verify an image signed with keyless signing
cosign verify myregistry.io/myimage:v1.0.0 \
  --certificate-identity=user@example.com \
  --certificate-oidc-issuer=https://accounts.google.com

# Verify by GitHub Actions identity
cosign verify myregistry.io/myimage:v1.0.0 \
  --certificate-identity=https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

### Signing Blobs (Non-Container Artifacts)

```bash
# Sign a release binary
cosign sign-blob myapp-v1.0.0-linux-amd64 \
  --output-signature myapp-v1.0.0-linux-amd64.sig \
  --output-certificate myapp-v1.0.0-linux-amd64.cert

# Verify the signed blob
cosign verify-blob myapp-v1.0.0-linux-amd64 \
  --signature myapp-v1.0.0-linux-amd64.sig \
  --certificate myapp-v1.0.0-linux-amd64.cert \
  --certificate-identity=user@example.com \
  --certificate-oidc-issuer=https://accounts.google.com
```

### Key-Based Signing (When Keyless Isn't Possible)

```bash
# Generate a key pair
cosign generate-key-pair

# Sign with key
cosign sign --key cosign.key myregistry.io/myimage:v1.0.0

# Verify with public key
cosign verify --key cosign.pub myregistry.io/myimage:v1.0.0
```

---

## GitHub Actions Integration

### Sign Container Images in CI

```yaml
# .github/workflows/release.yml
name: Release with Signing
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write  # Required for keyless signing

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da # v3.7.0

      - name: Log in to GHCR
        uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75 # v6.9.0
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      - name: Sign the image
        run: cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
        env:
          COSIGN_EXPERIMENTAL: 1
```

### Sign Release Binaries

```yaml
# .github/workflows/release-binaries.yml
name: Release Binaries
on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da # v3.7.0

      - name: Build binaries
        run: |
          # Your build commands here
          echo "building..."

      - name: Sign all release artifacts
        run: |
          for file in dist/*; do
            cosign sign-blob --yes "$file" \
              --output-signature "${file}.sig" \
              --output-certificate "${file}.cert"
          done

      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@c95fe1489396fe8a9eb87c0abf8aa5b2ef267fda # v2.2.1
        with:
          files: |
            dist/*
            dist/*.sig
            dist/*.cert
```

---

## Gitsign: Signing Git Commits

### Installation

```bash
# macOS
brew install gitsign

# Go install
go install github.com/sigstore/gitsign@latest
```

### Configuration

```bash
# Configure Git to use Gitsign (per-repo)
cd myproject
git config commit.gpgsign true
git config tag.gpgsign true
git config gpg.x509.program gitsign
git config gpg.format x509

# Or configure globally
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
```

### Usage

```bash
# Commits are now automatically signed (opens browser for OIDC)
git commit -m "feat: add new feature"

# Verify a commit signature
git verify-commit HEAD

# Verify with Gitsign-specific details
gitsign verify --certificate-identity=user@example.com \
  --certificate-oidc-issuer=https://accounts.google.com
```

---

## Rekor Transparency Log

Every Sigstore signing event is recorded in Rekor, an immutable, tamper-resistant log.

### Querying Rekor

```bash
# Install rekor-cli
go install github.com/sigstore/rekor/cmd/rekor-cli@latest

# Search for entries by email
rekor-cli search --email user@example.com

# Get a specific entry
rekor-cli get --uuid <entry-uuid>

# Search by artifact SHA
rekor-cli search --sha sha256:abc123...
```

### Rekor Web UI

Browse the public transparency log at: https://search.sigstore.dev/

---

## Language-Specific Signing

### Python (sigstore-python)

```bash
# Install
pip install sigstore

# Sign a Python package
python -m sigstore sign dist/mypackage-1.0.0.tar.gz

# Verify
python -m sigstore verify identity dist/mypackage-1.0.0.tar.gz \
  --cert-identity user@example.com \
  --cert-oidc-issuer https://accounts.google.com
```

### npm (sigstore-js)

npm packages published to the npm registry are automatically signed with Sigstore provenance starting from npm v9.5.0+:

```bash
# Publish with provenance (in GitHub Actions)
npm publish --provenance
```

Verify:

```bash
# Check provenance of an installed package
npm audit signatures
```

---

## Verification Policies

### Kubernetes (cosign policy-controller)

Enforce that only signed images run in your cluster:

```yaml
# policy.yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
    - glob: "ghcr.io/myorg/**"
  authorities:
    - keyless:
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/*
```

---

## Best Practices

### Do

- **Use keyless signing** — avoids key management complexity and security risks
- **Verify in CI/CD** — automatically verify signatures before deploying
- **Pin cosign by hash** in GitHub Actions workflows
- **Use OIDC identity** from GitHub Actions (no manual secrets needed)
- **Check the Rekor log** to audit signing history
- **Sign container images by digest**, not tag (tags are mutable)

### Don't

- **Don't store private keys in CI** if you can use keyless signing instead
- **Don't skip verification** — signing without verification provides no security value
- **Don't sign by tag** — always use the image digest (`@sha256:...`)
- **Don't ignore certificate identity** in verification (always specify `--certificate-identity` and `--certificate-oidc-issuer`)

---

## Migration from Traditional Signing

| Traditional | Sigstore Equivalent |
|-------------|-------------------|
| GPG key pair | Keyless signing (cosign sign) |
| Key distribution | Rekor transparency log |
| Key revocation | Short-lived certificates (auto-expire) |
| PGP signatures on releases | cosign sign-blob |
| GPG-signed commits | Gitsign |
| Notary v1 (Docker Content Trust) | Cosign |

---

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Cosign GitHub](https://github.com/sigstore/cosign)
- [Gitsign GitHub](https://github.com/sigstore/gitsign)
- [Rekor GitHub](https://github.com/sigstore/rekor)
- [sigstore-python](https://github.com/sigstore/sigstore-python)
- [Sigstore: The Movie (Intro Video)](https://www.youtube.com/watch?v=wqBAZmMoAaI)
- [OpenSSF Sigstore Project Page](https://openssf.org/community/sigstore/)
