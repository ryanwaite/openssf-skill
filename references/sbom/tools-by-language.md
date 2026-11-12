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

**Recommendation**: This skill standardizes on **SPDX JSON 2.3** as its default for generation and distribution. Syft **v1.57.1** also supports SPDX JSON 2.2 and 3.0, but 3.0 is opt-in: verify your validator and downstream consumer before changing versions. CycloneDX remains an optional secondary format for consumers such as Dependency-Track. Signing is a separate release decision; an unsigned SBOM can still be useful.

**Start now**: Choose one scope (source checkout, installed/build artifact, or runtime image), generate its SBOM, and label that scope. A source SBOM is **not** evidence of what a released binary contains. For a release, build the asset, inventory the actual file or immutable image digest, and record the matching artifact digest alongside its SBOM. You do not need to activate every scanner, registry, or signing tool to start.

---

## Universal Tools (Multi-Language)

### Syft (Recommended)
**Best for**: Container images, file systems, multi-language projects

```bash
# Install with your package manager, or download a versioned release
# and verify its published checksum before running it.
brew install syft
syft version  # For the examples below, use v1.57.1 and check its output.

# Generate SPDX JSON 2.3 source-checkout SBOM (explicit version)
syft dir:/path/to/checkout -o spdx-json@2.3 > sbom.spdx.json

# Generate CycloneDX SBOM (only if a consumer requires it)
syft . -o cyclonedx-json > sbom.cyclonedx.json

# Scan the exact immutable runtime image that was shipped
syft 'registry.example.org/owner/image@sha256:<actual-64-hex-digest>' -o spdx-json > image-sbom.spdx.json

# Scan a directory
syft dir:/path/to/project -o spdx-json@2.3 > project-sbom.json
```

**Supported ecosystems**: npm, pip, go, cargo, maven, gradle, nuget, gem, composer, and more.

The optional local runtime can scan an **explicit existing file** (`build_output`, with an independently expected SHA-256) or **explicit directory** (`source_checkout`). It does not build, fetch images, install Syft, sign, publish, or turn a source scan into release evidence. It sets an isolated Syft config, disables update checks and supported network enrichment (including Go tooling), and removes private system-temporary data after parsing. It does not require the target or current directory to be writable. If the selected system temporary location lies inside the scanned source, that scratch directory is excluded. This is **not** kernel-enforced network isolation.

Use the ensemble's `--artifact-evidence` configuration with either
`"sbom": {"path": "existing.spdx.json", "scope": "source_checkout"}` or
`"sbom": {"generate": true, "scope": "source_checkout"}`. Choose exactly one
input, and use `build_output` with an explicit artifact/digest for a release.
The generator is optional and its absence yields a targeted gap, not a blocker
on local advice. Source/file snapshots are bounded and checked before/after
generation; concurrent changes reject the observation.

Add `"validate_schema": true` to either SBOM configuration to request offline
validation against the official SPDX 2.3 JSON schema using optional
`skills/audit/requirements-sbom.txt` dependencies. Missing validation packages
remain unknown; malformed documents fail. The unmodified bundled
[`spdx-2.3.schema.json`](spdx-2.3.schema.json) is from the SPDX specification
contributors at commit
[`aadf3b0b8dbbabdb4d880b0fc714255fea436ff7`](https://github.com/spdx/spdx-spec/blob/aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json),
SHA-256 `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`,
provided under [CC BY 3.0](SPDX-SCHEMA-LICENSE). No schema is fetched at runtime.
Schema acceptance checks the published structural rules, **not** all semantic
consistency, inventory truth, completeness, or downstream tool compatibility.

Advisory graph paths describe declared package relationships, not runtime/code
reachability or exploitability. Existing normalized advisories are matched
only by precise namespace/name/version and package URL, not rescanned or
deducted again. Containment is distinct from dependency edges; cycles and
disconnected/ambiguous components remain visible. Graph expansion is bounded
to 10,000 routes/results and 128 nodes per path. Output is contextual
`supply_chain_analysis`, not a second numeric risk score.

### Trivy
**Best for**: Combined SBOM + vulnerability scanning

```bash
# Install
brew install trivy

# Generate SPDX SBOM (default)
trivy fs --format spdx-json --output sbom.spdx.json .

# Generate CycloneDX SBOM (only if a consumer requires it)
trivy fs --format cyclonedx --output sbom.cyclonedx.json .

# Scan container
trivy image --format spdx-json myimage:latest > sbom.json
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

# From an installed environment
cyclonedx-py environment --of JSON > environment.cyclonedx.json

# From a requirements.txt file
cyclonedx-py requirements requirements.txt --of JSON > requirements.cyclonedx.json

# From Poetry (lockfile)
cyclonedx-py poetry --of JSON > sbom.json

# From Pipenv (lockfile)
cyclonedx-py pipenv --of JSON > sbom.json

```

`environment`, `requirements`, `pipenv`, and `poetry` are distinct inputs. There is no `cyclonedx-py pip` subcommand; use `environment` for the installed interpreter and `requirements` for a requirements file. Confirm the installed version's CLI syntax with `cyclonedx-py --help` before use.

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
    <version>2.9.1</version>
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
    id 'org.cyclonedx.bom' version '1.10.0'
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

[`workflows/sbom-generation.yml.template`](../../workflows/sbom-generation.yml.template) is a pinned-action, **source-checkout** recipe. It publishes an explicitly named source SBOM; it does not pretend to inventory release binaries. Adapt the input to an actual built artifact or immutable image digest before claiming release inventory. Record the artifact digest, chosen Syft/SPDX versions, scan scope, and whether vulnerability findings are **advisory** (`fail-build: false`) or **blocking** under your documented policy. An advisory scan still fails on tool errors; do not suppress those errors. Publishing a release SBOM without this binding should not be described as proof of the shipped artifact's dependencies.

---

## Validating SBOMs

### CycloneDX Validation

```bash
# With a compatible CycloneDX CLI installed, validate only the
# optional secondary-format output, not the SPDX source SBOM.
cyclonedx validate --input-file sbom.json
```

### SPDX Validation

```bash
# Using SPDX tools; validate the SPDX 2.3 JSON document
pip install spdx-tools
pyspdxtools -i sbom.spdx.json
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

1. **Select the scope**: Clearly distinguish source, build, and runtime inventories
2. **Generate during build when claiming release scope**: Inventory the actual built asset or image by digest
3. **Validate generator, schema and consumer**: Confirm Syft version, parse SPDX 2.3 and check downstream ingestion
4. **Bind to the release**: Record the exact shipped artifact digest and publish the matching SBOM
5. **Store historically**: Keep SBOMs for audit trails
6. **Update regularly**: Regenerate when dependencies change
7. **Prefer SPDX**: Generate SPDX 2.3 JSON by default; add CycloneDX only when a specific consumer (e.g., Dependency-Track) requires it. Sign later if your release policy calls for it.

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
