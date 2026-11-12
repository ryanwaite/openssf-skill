"""Optional, bounded evidence for one local release artifact and SPDX 2.3 inventory.

The caller supplies expected identities and a digest from an independent channel.
Verification does not sign, publish, fetch artifacts, or assign a SLSA level.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time
from urllib.parse import unquote, urlsplit


MAX_EVIDENCE = 8 * 1024 * 1024
MAX_ARTIFACT = 2 * 1024 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
MAX_ITEMS = 5000
TIMEOUT = 45
PREDICATE = "https://slsa.dev/provenance/v1"
PREDICATE_V02 = "https://slsa.dev/provenance/v0.2"
STATEMENTS = {"https://in-toto.io/Statement/v1",
              "https://in-toto.io/Statement/v0.1"}
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]+\Z")
_CREDENTIAL = re.compile(
    r"(?i)(?:api[_-]?key|token|secret|password|credential)\s*[=:]|"
    r"://[^/\s]+:[^/@\s]+@")


class TrustLookupUnavailable(Exception):
    """The verifier could not reach the public Sigstore TUF trust root."""


def _result(status, facts=None, *gaps):
    return {"status": status, "facts": facts or {}, "gaps": list(gaps)}


def _digest(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("An independently expected SHA-256 digest is required.")
    return value.lower()


def _file(value, limit=None):
    if not isinstance(value, (str, Path)) or not str(value):
        raise ValueError("A local regular file is required.")
    path = Path(value)
    if ".." in path.parts or path.name.startswith("-") or "://" in str(path):
        raise ValueError("Unsafe local evidence path.")
    if path.is_symlink() or not path.is_file():
        raise ValueError("A local regular file (not a symlink) is required.")
    if limit is not None and path.stat().st_size > limit:
        raise ValueError("Evidence file exceeds the size limit.")
    return path.resolve()


def _json_file(value):
    path = _file(value, MAX_EVIDENCE)
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_EVIDENCE + 1)
        if len(data) > MAX_EVIDENCE:
            raise ValueError("Evidence file exceeds the size limit.")
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Malformed evidence JSON.") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate evidence JSON key.")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError("Invalid evidence JSON constant.")


def _hash_file(path):
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > MAX_ARTIFACT:
                raise ValueError("Artifact exceeds the local verification size limit.")
            h.update(chunk)
    return h.hexdigest()


def _text(value):
    if not isinstance(value, str) or not 0 < len(value) <= 512 or \
            any(ord(c) < 32 or ord(c) == 127 for c in value) or value.startswith("-"):
        raise ValueError("Expected a nonempty, safe policy value.")
    return value


def _uri(value, *, github=False):
    value = _text(value)
    if github and "://" in value:
        raise ValueError("Source URI must be github.com/owner/repo.")
    parsed = urlsplit(value if "://" in value else "https://" + value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or \
            parsed.password or parsed.query or parsed.fragment or \
            (github and (parsed.hostname != "github.com" or
                         not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                                          parsed.path))):
        raise ValueError("Expected a credential-free HTTPS identity or repository URI.")
    return value


def _execute(args, timeout=TIMEOUT, *, public_trust=False):
    """Capture only bounded output; never surface untrusted CLI diagnostics."""
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as proc:
        selector = selectors.DefaultSelector()
        output = bytearray()
        diagnostics = bytearray()
        try:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Verification tool timed out.")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.fileobj is proc.stdout:
                        output.extend(chunk)
                    elif public_trust and len(diagnostics) < 8192:
                        diagnostics.extend(chunk[:8192 - len(diagnostics)])
                    if len(output) > MAX_OUTPUT:
                        raise ValueError("Verification tool output exceeds the size limit.")
                    # Keep only enough stderr to identify a known trust-lookup outage.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Verification tool timed out.")
            code = proc.wait(timeout=remaining)
            if code and public_trust and b"tuf refresh failed:" in diagnostics and \
                    b"lookup tuf-repo-cdn.sigstore.dev" in diagnostics:
                raise TrustLookupUnavailable(
                    "Public Sigstore TUF trust lookup is unavailable; restore DNS access "
                    "to tuf-repo-cdn.sigstore.dev and retry.")
            return code, bytes(output)
        except (TimeoutError, ValueError, subprocess.TimeoutExpired) as exc:
            proc.kill()
            proc.wait()
            if isinstance(exc, subprocess.TimeoutExpired):
                raise TimeoutError("Verification tool timed out.") from exc
            raise
        finally:
            selector.close()


def _preflight(artifact_path, expected_sha256):
    artifact = _file(artifact_path)
    if artifact.stat().st_size > MAX_ARTIFACT:
        raise ValueError("Artifact exceeds the local verification size limit.")
    expected = _digest(expected_sha256)
    if _hash_file(artifact) != expected:
        raise ValueError("Local artifact does not match the independently expected SHA-256.")
    return artifact, expected


def _postflight(artifact, digest):
    if _hash_file(artifact) != digest:
        raise ValueError("Local artifact changed during verification.")


def verify_signature(artifact_path, expected_sha256, bundle_path, expected_signer,
                     expected_issuer, *, trusted_root_path=None,
                     allow_network_trust=False):
    """Verify a Cosign 3 blob bundle and exact keyless signer/issuer policy."""
    try:
        artifact, digest = _preflight(artifact_path, expected_sha256)
        bundle = _file(bundle_path, MAX_EVIDENCE)
        material = _json_file(bundle)
        if not isinstance(material, dict) or not isinstance(material.get("verificationMaterial"), dict) \
                or not isinstance(material.get("messageSignature"), dict):
            raise ValueError("Expected a Cosign blob-signature bundle.")
        signer = _text(expected_signer)
        if "://" in signer:
            _uri(signer)
        issuer = _uri(expected_issuer)
        root = _file(trusted_root_path, MAX_EVIDENCE) if trusted_root_path else None
        if root:
            if not isinstance(_json_file(root), dict):
                raise ValueError("Invalid trusted root JSON.")
        elif not allow_network_trust:
            return _result("unknown", {"sha256": digest},
                           "Provide an independently trusted Sigstore root or explicitly allow public trust lookup.")
        tool = shutil.which("cosign")
        if not tool:
            return _result("unknown", {"sha256": digest}, "Install Cosign 3 to verify this bundle.")
        cmd = [tool, "verify-blob", "--bundle", str(bundle),
               "--certificate-identity", signer, "--certificate-oidc-issuer", issuer]
        if root:
            cmd += ["--trusted-root", str(root)]
        cmd.append(str(artifact))
        code, _ = _execute(cmd, public_trust=not root)
        _postflight(artifact, digest)
        if code:
            return _result("error", {"sha256": digest},
                           "Cosign rejected the signature, subject, signer, issuer, or trust material.")
        return _result("ok", {"sha256": digest, "signed_identity_verified": True,
                              "expected_signer": signer, "expected_issuer": issuer,
                              "trust": "supplied_root" if root else "public_lookup",
                              "tool": "cosign"},
                       "A blob signature does not establish build provenance or a SLSA level.")
    except TrustLookupUnavailable as exc:
        return _result("unknown", None, str(exc))
    except (ValueError, OSError, TimeoutError) as exc:
        return _result("error", None, str(exc) if isinstance(exc, (ValueError, TimeoutError))
                       else "Cannot read local verification input or run Cosign.")


def verify_provenance(artifact_path, expected_sha256, provenance_path,
                      expected_source_uri, expected_builder_id, *,
                      expected_source_tag=None, expected_source_branch=None,
                      expected_source_commit=None,
                      allow_network_trust=False):
    """Verify a local SLSA v0.2 or v1 attestation with slsa-verifier v2.7.1.

    The verifier's public trust lookup is explicitly opt-in. The verified
    statement is parsed for predicate and subject; no SLSA level is inferred.
    """
    try:
        artifact, digest = _preflight(artifact_path, expected_sha256)
        provenance = _file(provenance_path, MAX_EVIDENCE)
        source = _uri(expected_source_uri, github=True)
        builder = _uri(expected_builder_id)
        if expected_source_tag and expected_source_branch:
            raise ValueError("Choose exactly one source tag or branch.")
        if not (expected_source_tag or expected_source_branch):
            raise ValueError("An expected source tag or branch is required.")
        ref = _text(expected_source_tag or expected_source_branch)
        if not _REF.fullmatch(ref) or ".." in ref:
            raise ValueError("Invalid expected source ref.")
        if expected_source_commit is not None and (not isinstance(expected_source_commit, str)
                                                   or not _COMMIT.fullmatch(expected_source_commit)):
            raise ValueError("Expected source commit must be a full Git object ID.")
        if not allow_network_trust:
            return _result("unknown", {"sha256": digest},
                           "Explicitly allow the verifier's public trust lookup.")
        tool = shutil.which("slsa-verifier")
        if not tool:
            return _result("unknown", {"sha256": digest},
                           "Install slsa-verifier v2.7.1 to verify provenance.")
        cmd = [tool, "verify-artifact", str(artifact), "--provenance-path",
               str(provenance), "--source-uri", source, "--builder-id", builder,
               "--source-tag" if expected_source_tag else "--source-branch", ref,
               "--print-provenance"]
        code, output = _execute(cmd, public_trust=True)
        _postflight(artifact, digest)
        if code:
            return _result("error", {"sha256": digest},
                           "The provenance verifier rejected subject, builder, source, ref, or trust.")
        if not output or len(output) > MAX_OUTPUT:
            raise ValueError("Missing or oversized verified provenance statement.")
        try:
            statement = json.loads(output, object_pairs_hook=_unique_object,
                                   parse_constant=_invalid_constant)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("Malformed verified provenance statement.") from exc
        if not isinstance(statement, dict) or statement.get("_type") not in STATEMENTS or \
                statement.get("predicateType") not in (PREDICATE, PREDICATE_V02):
            raise ValueError("Unsupported in-toto statement or SLSA predicate.")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not any(
                isinstance(s, dict) and isinstance(s.get("digest"), dict) and
                s["digest"].get("sha256") == digest for s in subjects):
            raise ValueError("Verified provenance has no matching artifact subject.")
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            raise ValueError("Verified provenance is missing the expected builder.")
        expected_uri = ("git+https://" + source.removeprefix("https://") +
                        "@refs/" + ("tags/" if expected_source_tag else "heads/") + ref)
        if statement["predicateType"] == PREDICATE_V02:
            invocation = predicate.get("invocation")
            source_data = invocation.get("configSource") if isinstance(invocation, dict) else None
            actual_builder = predicate.get("builder")
            sources = [source_data]
        else:
            definition = predicate.get("buildDefinition")
            details = predicate.get("runDetails")
            sources = definition.get("resolvedDependencies") if isinstance(definition, dict) else None
            actual_builder = details.get("builder") if isinstance(details, dict) else None
        if not isinstance(actual_builder, dict) or actual_builder.get("id") != builder:
            raise ValueError("Verified provenance is missing the expected builder.")
        if not isinstance(sources, list):
            raise ValueError("Verified provenance has no supported source dependencies.")
        matches = [item for item in sources if isinstance(item, dict) and
                   item.get("uri") == expected_uri]
        if not matches:
            raise ValueError("Verified provenance does not match the expected source and ref.")
        if expected_source_commit:
            algorithm = ("sha1" if len(expected_source_commit) == 40 else "sha256") \
                if statement["predicateType"] == PREDICATE_V02 else "gitCommit"
            if any(not isinstance(item.get("digest"), dict) or
                   not isinstance(item["digest"].get(algorithm), str) or
                   item["digest"][algorithm].lower() != expected_source_commit.lower()
                   for item in matches):
                raise ValueError("Verified provenance does not match the expected source commit and ref.")
        return _result("ok", {"sha256": digest, "provenance_verified": True,
                              "predicate_type": statement["predicateType"], "builder_id": builder,
                              "source_uri": source, "source_ref": ref,
                              "source_commit": expected_source_commit.lower()
                              if expected_source_commit else None,
                              "tool": "slsa-verifier"},
                       "Build and Source track levels require separate control assessment.")
    except TrustLookupUnavailable as exc:
        return _result("unknown", None, str(exc))
    except (ValueError, OSError, TimeoutError) as exc:
        return _result("error", None, str(exc) if isinstance(exc, (ValueError, TimeoutError))
                       else "Cannot read local verification input or run slsa-verifier.")


def _spdx_items(document, key):
    items = document.get(key, [])
    if not isinstance(items, list) or len(items) > MAX_ITEMS or \
            any(not isinstance(item, dict) for item in items):
        raise ValueError("Invalid or oversized SPDX element list.")
    return items


def _identity(value):
    if not isinstance(value, str) or not 0 < len(value) <= 512 or \
            any(ord(c) < 32 or ord(c) == 127 for c in unquote(value)) or \
            _CREDENTIAL.search(unquote(value)):
        raise ValueError("Missing, malformed, or credential-bearing SPDX identity.")
    return value


def ingest_spdx(spdx_path, scope, *, subject_sha256=None, expected_sha256=None,
                validate_schema=False):
    """Inventory SPDX JSON 2.3 without claiming vulnerability or release coverage.

    A subject digest is only bound if a document-described element records the
    same SHA-256 checksum. expected_sha256 is an independently acquired digest.
    """
    try:
        if scope not in ("source_checkout", "build_output", "oci_image"):
            raise ValueError("Scope must be source_checkout, build_output, or oci_image.")
        document = _json_file(spdx_path)
        if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
            raise ValueError("Only SPDX JSON 2.3 is supported.")
        if type(validate_schema) is not bool:
            raise ValueError("validate_schema must be boolean.")
        schema_validation = None
        if validate_schema:
            from spdx_validation import validate_spdx
            schema_validation = validate_spdx(document)
            if schema_validation["status"] in ("invalid", "error"):
                return _result("error", {"schema_validation": schema_validation},
                               schema_validation["reason"])
        doc_id = document.get("SPDXID")
        namespace = document.get("documentNamespace")
        if doc_id != "SPDXRef-DOCUMENT" or not isinstance(namespace, str) or \
                not namespace or not isinstance(document.get("name"), str) or \
                not document["name"]:
            raise ValueError("Missing SPDX document identity.")
        _identity(namespace)
        _identity(document["name"])
        if urlsplit(namespace).query or urlsplit(namespace).username or \
                urlsplit(namespace).password:
            raise ValueError("SPDX namespace must not contain credentials or query values.")
        creation = document.get("creationInfo")
        if document.get("dataLicense") != "CC0-1.0" or not isinstance(creation, dict) or \
                not isinstance(creation.get("created"), str) or \
                not isinstance(creation.get("creators"), list) or not creation["creators"] or \
                any(not isinstance(creator, str) for creator in creation["creators"]):
            raise ValueError("Missing SPDX 2.3 creation or data-license metadata.")
        packages = _spdx_items(document, "packages")
        files = _spdx_items(document, "files")
        snippets = _spdx_items(document, "snippets")
        relationships = _spdx_items(document, "relationships")
        if not packages:
            raise ValueError("SPDX has no packages to inventory.")
        ids = {doc_id}
        for item in packages + files + snippets:
            identifier = item.get("SPDXID")
            if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or \
                    identifier in ids:
                raise ValueError("Missing, malformed, or duplicate SPDX element ID.")
            ids.add(identifier)
        described = document.get("documentDescribes", [])
        if not isinstance(described, list) or len(described) > MAX_ITEMS:
            raise ValueError("Invalid SPDX document descriptions.")
        edges = []
        for rel in relationships:
            left, right, kind = (rel.get(k) for k in
                                 ("spdxElementId", "relatedSpdxElement", "relationshipType"))
            if not isinstance(left, str) or not isinstance(right, str) or \
                    left not in ids or right not in ids or not isinstance(kind, str) or \
                    not re.fullmatch(r"[A-Z_]{2,64}", kind):
                raise ValueError("Malformed or dangling SPDX relationship.")
            edges.append({"from": left, "to": right, "type": kind})
            if kind == "DESCRIBES" and left == doc_id:
                described.append(right)
        if not described or any(not isinstance(ref, str) or ref not in ids or
                                ref == doc_id for ref in described):
            raise ValueError("SPDX document has no valid described elements.")
        inventory = []
        for package in packages:
            name, version = package.get("name"), package.get("versionInfo")
            _identity(name)
            if version:
                _identity(version)
            refs = package.get("externalRefs", [])
            if not isinstance(refs, list) or len(refs) > MAX_ITEMS:
                raise ValueError("Invalid SPDX external references.")
            purls = []
            for ref in refs:
                if not isinstance(ref, dict):
                    raise ValueError("Malformed SPDX external reference.")
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    if not isinstance(purl, str) or not re.match(
                            r"pkg:[A-Za-z0-9.+-]+/[^/?#]+", purl):
                        raise ValueError("Malformed package URL in SPDX.")
                    purls.append(_identity(purl))
            inventory.append({"id": package["SPDXID"], "name": name,
                              "version": version, "purls": purls})
        subject = _digest(subject_sha256) if subject_sha256 is not None else None
        expected = _digest(expected_sha256) if expected_sha256 is not None else None
        if expected and subject != expected:
            raise ValueError("SBOM subject does not match the independently expected SHA-256.")
        bound = False
        if subject:
            for item in packages + files:
                if item["SPDXID"] not in described:
                    continue
                checksums = item.get("checksums", [])
                if not isinstance(checksums, list) or len(checksums) > MAX_ITEMS or \
                        any(not isinstance(c, dict) for c in checksums):
                    raise ValueError("Invalid SPDX checksums.")
                if any(isinstance(c, dict) and c.get("algorithm") == "SHA256" and
                       c.get("checksumValue", "").lower() == subject for c in checksums
                       if isinstance(c.get("checksumValue"), str)):
                    bound = True
                    break
        gaps = []
        if schema_validation and schema_validation["status"] != "valid":
            gaps.append(schema_validation["reason"])
        missing_versions = sum(not p["version"] for p in inventory)
        missing_purls = sum(not p["purls"] for p in inventory)
        dependency_count = sum(e["type"] in ("DEPENDS_ON", "DEPENDENCY_OF") for e in edges)
        if missing_versions:
            gaps.append("Package versions are missing; resolve identities before vulnerability matching.")
        if missing_purls:
            gaps.append("Package URLs are missing; resolve component identities before vulnerability matching.")
        if not dependency_count:
            gaps.append("No dependency relationships; direct/transitive coverage is unknown.")
        reachable = set(described)
        for _ in range(len(edges)):
            added = set()
            for edge in edges:
                left, right, kind = edge["from"], edge["to"], edge["type"]
                if kind in ("CONTAINS", "DEPENDS_ON", "DESCRIBES") and left in reachable:
                    added.add(right)
                elif kind == "DEPENDENCY_OF" and right in reachable:
                    added.add(left)
            if added <= reachable:
                break
            reachable.update(added)
        disconnected = sum(package["id"] not in reachable for package in inventory)
        if disconnected:
            gaps.append("Some packages are disconnected from described subject(s); inventory coverage is unverified.")
        if scope != "source_checkout" and not bound:
            gaps.append("No document-described element binds the shipped subject SHA-256; release coverage is unverified.")
        if scope == "source_checkout":
            gaps.append("A source checkout inventory is not an inventory of released binaries.")
        facts = {"scope": scope, "document_id": doc_id, "document_namespace": namespace,
                 "subject_sha256": subject, "subject_bound": bound,
                 "binding_type": "declared_checksum_only" if bound else "none",
                 "independent_digest_match": bool(expected and bound),
                 "described_ids": sorted(set(described)),
                 "packages": inventory, "relationships": edges,
                 "quality": {"package_count": len(inventory),
                             "missing_version_count": missing_versions,
                             "missing_purl_count": missing_purls,
                             "dependency_relationship_count": dependency_count,
                             "disconnected_package_count": disconnected,
                             "described_element_count": len(set(described)),
                             "schema_validated": bool(schema_validation and
                                                      schema_validation["status"] == "valid"),
                             "completeness": "unknown"}}
        if schema_validation:
            facts["schema_validation"] = schema_validation
        return _result("partial" if gaps else "ok", facts, *gaps)
    except (ValueError, OSError) as exc:
        return _result("error", None, str(exc) if isinstance(exc, ValueError)
                       else "Cannot read local SPDX input.")
