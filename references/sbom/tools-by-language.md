# SBOM Generation Tools by Language

A Software Bill of Materials (SBOM) is a machine-readable inventory of all components in your software. This guide covers tools for generating SBOMs in SPDX or CycloneDX formats.

## SBOM Formats

### SPDX (Software Package Data Exchange)
- **Standard**: ISO/IEC 5962:2021
- **Best for**: Compliance, legal, license tracking
- **Formats**: JSON, XML, YAML, RDF, tag-value

### CycloneDX
- **Standard**: OWASP standard, ECMA-424
- **Best for**: Security, vulnerability tracking, lightweight automation
- **Formats**: JSON, XML

**Recommendation**: CycloneDX for security-focused use cases, SPDX for compliance. Many organizations generate both.

---

## Universal Tools (Multi-Language)

### Syft (Recommended)
**Best for**: Container images, file systems, multi-language projects

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Or via Homebrew
brew install syft

# Generate CycloneDX SBOM
syft . -o cyclonedx-json > sbom.cyclonedx.json

# Generate SPDX SBOM
syft . -o spdx-json > sbom.spdx.json

# Scan a container image
syft alpine:latest -o cyclonedx-json > alpine-sbom.json

# Scan a directory
syft dir:/path/to/project -o cyclonedx-json > project-sbom.json
```

**Supported ecosystems**: npm, pip, go, cargo, maven, gradle, nuget, gem, composer, and more.

### Trivy
**Best for**: Combined SBOM + vulnerability scanning

```bash
# Install
brew install trivy

# Generate CycloneDX SBOM
trivy fs --format cyclonedx --output sbom.cyclonedx.json .

# Generate SPDX SBOM
trivy fs --format spdx-json --output sbom.spdx.json .

# Scan container
trivy image --format cyclonedx myimage:latest > sbom.json
```

### cdxgen (CycloneDX Generator)
**Best for**: CycloneDX format with extensive language support

```bash
# Install
npm install -g @cyclonedx/cdxgen

# Generate SBOM
cdxgen -o sbom.json

# Specify project type
cdxgen -t python -o sbom.json

# Recursive for monorepos
cdxgen -r -o sbom.json
```

---

## Language-Specific Tools

### JavaScript / Node.js

#### CycloneDX Node.js Module
```bash
# Install
npm install --save-dev @cyclonedx/cyclonedx-npm

# Generate from package-lock.json
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Generate from node_modules
npx @cyclonedx/cyclonedx-npm --package-lock-only=false
```

#### npm audit (built-in)
```bash
# Generate SBOM-like output
npm ls --json > dependencies.json

# Check vulnerabilities
npm audit --json > audit.json
```

#### yarn
```bash
# For Yarn projects
npm install -g @cyclonedx/yarn-plugin-cyclonedx
yarn cyclonedx --output sbom.json
```

---

### Python

#### cyclonedx-python
```bash
# Install
pip install cyclonedx-bom

# From requirements.txt
cyclonedx-py requirements -i requirements.txt -o sbom.json --format json

# From Poetry
cyclonedx-py poetry -o sbom.json --format json

# From Pipenv
cyclonedx-py pipenv -o sbom.json --format json

# From pip freeze
pip freeze | cyclonedx-py stdin -o sbom.json --format json
```

#### pip-audit (vulnerability scanning)
```bash
pip install pip-audit
pip-audit --format cyclonedx-json > sbom.json
```

#### SPDX for Python
```bash
pip install spdx-tools
# Then use Syft for generation
```

---

### Go

#### cyclonedx-go
```bash
# Install
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# Generate from go.mod
cyclonedx-gomod mod -json -output sbom.json

# Include test dependencies
cyclonedx-gomod mod -json -test -output sbom.json
```

#### spdx-sbom-generator
```bash
go install github.com/opensbom-generator/spdx-sbom-generator/cmd/generator@latest
generator -p . -o sbom.spdx
```

---

### Rust

#### cargo-cyclonedx
```bash
# Install
cargo install cargo-cyclonedx

# Generate SBOM
cargo cyclonedx --format json > sbom.json
```

#### cargo-sbom (SPDX)
```bash
cargo install cargo-sbom
cargo sbom > sbom.spdx.json
```

---

### Java / Maven

#### CycloneDX Maven Plugin
```xml
<!-- Add to pom.xml -->
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <version>2.7.11</version>
    <executions>
        <execution>
            <phase>package</phase>
            <goals>
                <goal>makeAggregateBom</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

```bash
# Generate SBOM
mvn cyclonedx:makeAggregateBom
# Output: target/bom.json
```

#### SPDX Maven Plugin
```xml
<plugin>
    <groupId>org.spdx</groupId>
    <artifactId>spdx-maven-plugin</artifactId>
    <version>0.6.5</version>
</plugin>
```

---

### Java / Gradle

#### CycloneDX Gradle Plugin
```groovy
// build.gradle
plugins {
    id 'org.cyclonedx.bom' version '1.8.2'
}

cyclonedxBom {
    includeConfigs = ["runtimeClasspath"]
    outputFormat = "json"
}
```

```bash
# Generate SBOM
./gradlew cyclonedxBom
# Output: build/reports/bom.json
```

---

### .NET / C#

#### CycloneDX .NET Tool
```bash
# Install
dotnet tool install --global CycloneDX

# Generate from solution
dotnet CycloneDX MySolution.sln -o sbom.json -j

# Generate from project
dotnet CycloneDX MyProject.csproj -o sbom.json -j
```

---

### Ruby

#### cyclonedx-ruby-gem
```bash
# Install
gem install cyclonedx-ruby

# Generate from Gemfile.lock
cyclonedx-ruby -p . -o sbom.json
```

---

### PHP

#### CycloneDX PHP Composer
```bash
# Install
composer require --dev cyclonedx/cyclonedx-php-composer

# Generate
composer make-bom --output-file=sbom.json
```

---

## CI/CD Integration

### GitHub Actions (Syft)

```yaml
name: Generate SBOM

on:
  release:
    types: [published]
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      - name: Generate SPDX SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.cyclonedx.json
            sbom.spdx.json

      # Optionally attach to release
      - name: Upload to Release
        if: github.event_name == 'release'
        uses: softprops/action-gh-release@v1
        with:
          files: |
            sbom.cyclonedx.json
            sbom.spdx.json
```

### GitHub Actions (Trivy)

```yaml
- name: Generate SBOM with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    format: 'cyclonedx'
    output: 'sbom.cyclonedx.json'
```

---

## Validating SBOMs

### CycloneDX Validation

```bash
# Install validator
npm install -g @cyclonedx/cyclonedx-cli

# Validate
cyclonedx validate --input-file sbom.json
```

### SPDX Validation

```bash
# Using SPDX tools
pip install spdx-tools
pyspdxtools parse sbom.spdx.json
```

### NTIA Minimum Elements Check

An SBOM should contain:
- [ ] Supplier name
- [ ] Component name
- [ ] Component version
- [ ] Unique identifier
- [ ] Dependency relationship
- [ ] Author of SBOM
- [ ] Timestamp

---

## Best Practices

1. **Generate during build**: Create SBOM as part of CI/CD, not manually
2. **Include with releases**: Attach SBOM to release artifacts
3. **Version the SBOM**: Include version info in SBOM metadata
4. **Sign the SBOM**: Use Sigstore or GPG to sign SBOM files
5. **Store historically**: Keep SBOMs for audit trails
6. **Update regularly**: Regenerate when dependencies change
7. **Use both formats**: Generate both CycloneDX and SPDX if stakeholders need different formats

---

## Troubleshooting

### Missing dependencies
- Ensure lock files are up to date
- Run dependency installation before SBOM generation
- Use `--include-dev` flags for dev dependencies

### Large SBOMs
- Use JSON format (smaller than XML)
- Consider filtering to direct dependencies only
- Compress SBOM files for distribution

### Container SBOMs
- Scan the final image, not base image separately
- Include build-time dependencies if needed
- Consider multi-stage builds

---

## References

- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
- [OpenSSF SBOM Everywhere](https://openssf.org/blog/2025/06/05/choosing-an-sbom-generation-tool/)
- [Syft Documentation](https://github.com/anchore/syft)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
