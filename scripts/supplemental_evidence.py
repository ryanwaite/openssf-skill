"""Explicit local evidence inputs; no acquisition or automatic trust grants."""

import json
from pathlib import Path

from artifact_evidence import ingest_spdx, verify_provenance, verify_signature


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate evidence JSON key")
        value[key] = item
    return value


def _constant(_):
    raise ValueError("Nonfinite values are not valid evidence")


def read_document(path, max_bytes=1_000_000):
    """Read bounded JSON, including rejecting duplicate keys and nonfinite numbers."""
    with Path(path).open("rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError("Evidence input exceeds its size limit")
    try:
        return json.loads(content, object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Evidence input must be valid JSON") from exc


def _document(path, target, required, optional=()):
    data = read_document(path)
    if not isinstance(data, dict) or not set(required) <= set(data) or \
            set(data) - set(required) - set(optional):
        raise ValueError("Invalid supplemental evidence fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported supplemental evidence schema_version")
    if data["target"] != target:
        raise ValueError("Supplemental evidence target mismatch")
    return data


def _path(parent, value):
    if not isinstance(value, str) or not value or "://" in value:
        raise ValueError("Evidence must name a local file")
    path = Path(value)
    if ".." in path.parts or path.name.startswith("-"):
        raise ValueError("Unsafe evidence file path")
    path = path if path.is_absolute() else parent / path
    if path.is_symlink() or not path.is_file():
        raise ValueError("Evidence must name a local regular file, not a symlink")
    return path.resolve()


def artifact_evidence(path, target, identity, *, allow_network_trust=False):
    """Verify only requested artifact controls against explicit caller expectations."""
    data = _document(path, target, ("schema_version", "target"),
                     ("artifact", "signature", "provenance", "sbom"))
    if not any(key in data for key in ("signature", "provenance", "sbom")):
        raise ValueError("Request at least one artifact evidence check")
    parent = Path(path).resolve().parent
    artifact = data.get("artifact")
    artifact_path = expected = None
    if artifact is not None:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise ValueError("Artifact needs path and independently expected sha256")
        artifact_path = _path(parent, artifact["path"])
        expected = artifact["sha256"]
        if identity["kind"] == "local_file":
            if artifact_path != Path(identity["path"]) or expected != identity["sha256"]:
                raise ValueError("Artifact must match the requested local file and digest")
        elif identity["kind"] == "local_directory":
            if not artifact_path.is_relative_to(Path(identity["path"])):
                raise ValueError("Artifact must be inside the requested local directory")
        else:
            raise ValueError("Local artifact verification requires a local file/directory target")
    if ("signature" in data or "provenance" in data) and artifact_path is None:
        raise ValueError("Signature/provenance checks require an explicit artifact")
    results = {}
    if "signature" in data:
        config = data["signature"]
        required = {"bundle", "expected_signer", "expected_issuer"}
        if not isinstance(config, dict) or not required <= set(config) or \
                set(config) - required - {"trusted_root"}:
            raise ValueError("Invalid signature evidence fields")
        results["signature"] = verify_signature(
            artifact_path, expected, _path(parent, config["bundle"]),
            config["expected_signer"], config["expected_issuer"],
            trusted_root_path=_path(parent, config["trusted_root"])
            if config.get("trusted_root") else None,
            allow_network_trust=allow_network_trust,
        )
    if "provenance" in data:
        config = data["provenance"]
        required = {"path", "expected_source_uri", "expected_builder_id"}
        optional = {"expected_source_tag", "expected_source_branch", "expected_source_commit"}
        if not isinstance(config, dict) or not required <= set(config) or \
                set(config) - required - optional:
            raise ValueError("Invalid provenance evidence fields")
        results["provenance"] = verify_provenance(
            artifact_path, expected, _path(parent, config["path"]),
            config["expected_source_uri"], config["expected_builder_id"],
            **{key: config[key] for key in optional if key in config},
            allow_network_trust=allow_network_trust,
        )
    if "sbom" in data:
        config = data["sbom"]
        if not isinstance(config, dict) or not {"path", "scope"} <= set(config) or \
                set(config) - {"path", "scope", "subject_sha256"}:
            raise ValueError("Invalid SBOM evidence fields")
        if config["scope"] != "source_checkout" and expected is None:
            raise ValueError("Release SBOM binding needs an explicitly expected local artifact")
        results["sbom"] = ingest_spdx(
            _path(parent, config["path"]), config["scope"],
            subject_sha256=config.get("subject_sha256"), expected_sha256=expected,
        )
    return results


def vex_context(path, target):
    """Load unverified OpenVEX assertions; never authenticate an author from JSON."""
    data = _document(path, target, ("schema_version", "target", "documents"),
                     ("trusted_authors", "max_age_days"))
    if not isinstance(data["documents"], list) or not data["documents"]:
        raise ValueError("VEX documents must be a nonempty list")
    if len(data["documents"]) > 32:
        raise ValueError("At most 32 VEX documents can be supplied")
    authors = data.get("trusted_authors", [])
    if not isinstance(authors, list) or not all(
            isinstance(author, str) and 0 < len(author) <= 512 for author in authors):
        raise ValueError("Invalid VEX author policy")
    age = data.get("max_age_days")
    if age is not None and (type(age) is not int or age < 0):
        raise ValueError("VEX max_age_days must be a nonnegative integer")
    return {"vex_documents": data["documents"], "trusted_authors": authors,
            "authenticated_authors": (), "max_age_days": age}
