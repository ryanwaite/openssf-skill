# Container Security Guide

Containers are a critical part of modern software delivery. Securing them requires attention at every stage: base image selection, build configuration, image scanning, runtime hardening, and registry security.

## Why Container Security Matters

- Containers inherit vulnerabilities from their base images
- Misconfigured containers can expose host systems and networks
- Container images are a supply chain attack vector
- Over 50% of container images in public registries contain known vulnerabilities

---

## Base Image Selection

### Use Minimal Base Images

| Image | Size | Packages | Use Case |
|-------|------|----------|----------|
| `scratch` | 0 MB | None | Statically compiled Go/Rust binaries |
| `distroless` | ~20 MB | Minimal runtime | Java, Python, Node.js apps |
| `alpine` | ~7 MB | musl + busybox | General purpose, small footprint |
| `ubuntu` | ~78 MB | Full package manager | When you need apt |
| `debian-slim` | ~80 MB | Reduced Debian | When you need glibc |

### Prefer Distroless Images

Google's distroless images contain only the application runtime — no shell, no package manager, no unnecessary OS tools.

```dockerfile
# Go application
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
ENTRYPOINT ["/server"]
```

```dockerfile
# Node.js application
FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=builder /app /app
CMD ["server.js"]
```

```dockerfile
# Python application
FROM python:3.13-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt
COPY . .

FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=builder /deps /deps
COPY --from=builder /app /app
ENV PYTHONPATH=/deps
CMD ["app.py"]
```

### Pin Image Versions

```dockerfile
# Bad - mutable tag, unpredictable base
FROM node:latest

# Better - pinned major version
FROM node:22-slim

# Best - pinned by digest (immutable)
FROM node:22-slim@sha256:abcdef1234567890...
```

---

## Multi-Stage Builds

Multi-stage builds reduce image size and remove build-time secrets/tools from the final image.

```dockerfile
# Stage 1: Build
FROM rust:1.83 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release  # Cache dependencies
COPY src ./src
RUN cargo build --release

# Stage 2: Runtime (minimal)
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/myapp /myapp
ENTRYPOINT ["/myapp"]
```

---

## Dockerfile Security Best Practices

### Run as Non-Root

```dockerfile
# Create a non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# Set ownership of application files
COPY --chown=appuser:appgroup . /app

# Switch to non-root user
USER appuser
```

Or use the `nonroot` tag with distroless images:

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
```

### Don't Store Secrets in Images

```dockerfile
# BAD - secret is in image layer history
COPY .env /app/.env
ENV API_KEY=sk-1234567890

# GOOD - use build secrets (BuildKit)
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=api_key \
    cat /run/secrets/api_key | myapp configure
```

Build with secrets:

```bash
docker build --secret id=api_key,src=./api_key.txt .
```

### Minimize Layer Count and Content

```dockerfile
# BAD - leaves package cache in layer
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y wget

# GOOD - single layer, clean up cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget && \
    rm -rf /var/lib/apt/lists/*
```

### Use COPY Instead of ADD

```dockerfile
# BAD - ADD auto-extracts archives and supports URLs (unexpected behavior)
ADD https://example.com/app.tar.gz /app/

# GOOD - explicit and predictable
COPY app.tar.gz /app/
RUN tar -xzf /app/app.tar.gz -C /app/ && rm /app/app.tar.gz
```

### Set Read-Only Filesystem

```dockerfile
# In docker-compose.yml or at runtime
services:
  app:
    image: myapp:latest
    read_only: true
    tmpfs:
      - /tmp
```

```bash
# Or via docker run
docker run --read-only --tmpfs /tmp myapp:latest
```

### Drop Capabilities

```bash
# Drop all capabilities, add only what's needed
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:latest
```

### Set Resource Limits

```bash
docker run --memory=512m --cpus=1 --pids-limit=100 myapp:latest
```

---

## Image Scanning

### Trivy

```bash
# Install
brew install trivy  # macOS
# or: apt-get install trivy

# Scan an image
trivy image myapp:latest

# Scan and fail on HIGH/CRITICAL
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:latest

# Scan a Dockerfile
trivy config Dockerfile

# Output as JSON
trivy image --format json --output results.json myapp:latest
```

### Grype

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan an image
grype myapp:latest

# Fail on high severity
grype myapp:latest --fail-on high
```

### GitHub Actions: Image Scanning

```yaml
# .github/workflows/container-scan.yml
name: Container Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947e7f3b0aba1c0a325 # v0.30.0
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@48ab28a6f5dbc2a99bf1e0131198dd8f1df78169 # v3.28.0
        with:
          sarif_file: trivy-results.sarif
```

---

## Docker Compose Security

```yaml
# docker-compose.yml
services:
  app:
    image: myapp:latest
    user: "1001:1001"
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
    tmpfs:
      - /tmp:noexec,nosuid,nodev
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## Registry Security

### Use Private Registries

- **GitHub Container Registry (GHCR)**: Free for public, included with GitHub plans
- **Docker Hub**: Rate-limited for free tier
- **AWS ECR / GCP Artifact Registry / Azure ACR**: Cloud-native options

### Enable Image Signing

Sign images with Sigstore cosign (see [Sigstore Guide](../signing/sigstore-guide.md)):

```bash
cosign sign ghcr.io/myorg/myapp@sha256:abc123...
```

### Scan Images in Registry

```bash
# Scan images already in a registry
trivy image ghcr.io/myorg/myapp:latest
grype ghcr.io/myorg/myapp:latest
```

---

## Security Checklist

### Build Time

- [ ] Use minimal base image (distroless, Alpine, or scratch)
- [ ] Pin base image by digest
- [ ] Use multi-stage builds
- [ ] Run as non-root user (USER directive)
- [ ] Don't store secrets in images or ENV
- [ ] Use COPY instead of ADD
- [ ] Clean up package manager caches in the same layer
- [ ] Use `.dockerignore` to exclude unnecessary files
- [ ] Scan image for vulnerabilities before pushing
- [ ] Lint Dockerfile with hadolint

### Runtime

- [ ] Run with `--read-only` filesystem where possible
- [ ] Drop all capabilities (`--cap-drop=ALL`), add only needed ones
- [ ] Set memory and CPU limits
- [ ] Set `--pids-limit` to prevent fork bombs
- [ ] Use `no-new-privileges` security option
- [ ] Mount sensitive data as secrets, not environment variables
- [ ] Use health checks
- [ ] Enable logging and monitoring

### Registry

- [ ] Use a private registry for proprietary images
- [ ] Enable vulnerability scanning in registry
- [ ] Sign images with Sigstore cosign
- [ ] Implement image retention policies
- [ ] Use RBAC for registry access

---

## Dockerfile Linting with Hadolint

```bash
# Install
brew install hadolint

# Lint a Dockerfile
hadolint Dockerfile

# Ignore specific rules
hadolint --ignore DL3008 --ignore DL3009 Dockerfile
```

```yaml
# .hadolint.yaml
ignored:
  - DL3008  # Pin versions in apt-get install
trustedRegistries:
  - docker.io
  - gcr.io
```

GitHub Actions:

```yaml
- name: Lint Dockerfile
  uses: hadolint/hadolint-action@54c9adbab1582c2ef04b2016b760714a4bfde3cf # v3.1.0
  with:
    dockerfile: Dockerfile
```

---

## .dockerignore

Always include a `.dockerignore` to prevent sensitive or unnecessary files from entering the build context:

```dockerignore
.git
.github
.env
.env.*
*.pem
*.key
node_modules
__pycache__
.pytest_cache
target/
dist/
build/
*.log
README.md
docs/
tests/
```

---

## References

- [Docker Security Best Practices](https://docs.docker.com/build/building/best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Google Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Grype](https://github.com/anchore/grype)
- [Hadolint](https://github.com/hadolint/hadolint)
- [Sigstore Cosign](https://github.com/sigstore/cosign)
- [OWASP Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
