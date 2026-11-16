"""Verify one locally held npm distribution against an independently chosen policy.

Discovery and verification are separate: registry metadata is never a trust root,
expected digest, signer, or source policy. PyPI PEP 740 envelopes are not Sigstore
bundles and are deliberately unsupported by this Cosign-only verifier.
"""

import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit

try:
    from . import registry_evidence as registry
except ImportError:
    import registry_evidence as registry


PREDICATE = "https://slsa.dev/provenance/v1"
MAX_ARTIFACT = 256 * 1024 * 1024
_STATEMENT = "https://in-toto.io/Statement/v1"
_BUNDLE_MEDIA = {
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
}
_CONFIG_KEYS = {
    "filename", "artifact_path", "bundle_path", "expected_digest",
    "certificate_identity", "certificate_oidc_issuer", "source_repository",
    "source_ref", "source_path", "builder_id", "predicate_type", "trusted_root_path",
}
_REQUIRED = {
    "filename", "artifact_path", "bundle_path", "expected_digest",
    "certificate_identity", "certificate_oidc_issuer", "source_repository",
    "predicate_type",
}


def _result(status, facts, reason):
    return {"status": status, "facts": facts, "gaps": [reason] if reason else []}


def _safe_policy(value):
    return isinstance(value, str) and registry._claim(value) == value


def _https(value):
    if not _safe_policy(value):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.port \
            and not parsed.username and not parsed.password and not parsed.query \
            and not parsed.fragment
    except ValueError:
        return False


def _path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid local verification file path.")
    if ".." in Path(value).parts:
        raise ValueError("Verification paths cannot contain parent traversal.")
    path = Path(os.path.abspath(value))
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Verification input has a symlink component.")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Verification input is not a regular file.")
    return path


@contextmanager
def _private_snapshots():
    """Keep immutable verifier inputs private without requiring a writable target."""
    with tempfile.TemporaryDirectory(prefix="openssf-registry-verification-") as directory:
        yield Path(directory)


def _open_input(path):
    """Walk every directory component without following a swapped symlink."""
    parts = path.parts
    directory_fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("Verification input is not a regular file.")
        return fd
    finally:
        os.close(directory_fd)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_input(original, limit, *, destination=None, artifact=False):
    """Hash bounded regular-file bytes, optionally into an exclusive snapshot."""
    deadline = time.monotonic() + 12
    _path(str(original))
    source_fd = _open_input(original)
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Verification input is not a regular file.")
        if info.st_size > limit:
            raise ValueError("Verification input exceeds size limit.")
        hashes = {"sha256": hashlib.sha256()}
        if artifact:
            hashes["sha512"] = hashlib.sha512()
        total = 0
        output_fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                            0o600) if destination else None
        try:
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Verification input read timed out.")
                chunk = os.read(source_fd, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError("Verification input exceeds size limit.")
                if output_fd is not None:
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(output_fd, view):]
                for digest in hashes.values():
                    digest.update(chunk)
        finally:
            if output_fd is not None:
                os.close(output_fd)
        if _stamp(os.fstat(source_fd)) != _stamp(info):
            raise ValueError("Verification input changed while being read.")
        if destination:
            os.chmod(destination, 0o400)
        return {**{key: value.hexdigest() for key, value in hashes.items()},
                "_source_stamp": _stamp(info)}
    finally:
        os.close(source_fd)


def _read_json(path):
    with path.open("rb") as stream:
        return registry._json(stream.read(registry.MAX_BODY + 1), registry.MAX_BODY)


def _statement_from_bundle(bundle):
    if not isinstance(bundle, dict) or bundle.get("mediaType") not in _BUNDLE_MEDIA:
        raise ValueError("Unsupported Sigstore bundle version or layout.")
    envelope = bundle.get("dsseEnvelope")
    material = bundle.get("verificationMaterial")
    signatures = envelope.get("signatures") if isinstance(envelope, dict) else None
    if not isinstance(envelope, dict) or not isinstance(material, dict) or not material \
            or envelope.get("payloadType") != "application/vnd.in-toto+json" \
            or not isinstance(signatures, list) or len(signatures) != 1 \
            or not isinstance(signatures[0], dict) \
            or not registry._signature(signatures[0].get("sig")):
        raise ValueError("Unsupported or unsigned Sigstore DSSE envelope.")
    try:
        return registry._statement(envelope.get("payload"))
    except registry._DiscoveryError as exc:
        raise ValueError("Malformed Sigstore DSSE statement.") from exc


def _verify_captured(config, purl, filename, artifact, bundle_path, trusted_root,
                     expected_hex, facts, directory):
    snapshots = {
        "artifact": (artifact, directory / filename, MAX_ARTIFACT),
        "bundle": (bundle_path, directory / "bundle.sigstore.json", registry.MAX_BODY),
    }
    if trusted_root:
        snapshots["trusted_root"] = (
            trusted_root, directory / "trusted_root.json", registry.MAX_BODY)
    digests = {}
    try:
        for kind, (original, captured, limit) in snapshots.items():
            digests[kind] = _read_input(original, limit, destination=captured,
                                        artifact=kind == "artifact")
    except (OSError, ValueError, TimeoutError):
        return _result("unknown", facts, "Verification input cannot be safely snapshotted.")
    if trusted_root:
        try:
            root_data = _read_json(snapshots["trusted_root"][1])
            if not isinstance(root_data, dict) or \
                    root_data.get("mediaType") != \
                    "application/vnd.dev.sigstore.trustedroot+json;version=0.1" or \
                    not isinstance(root_data.get("certificateAuthorities"), list) or \
                    not root_data["certificateAuthorities"] or \
                    not isinstance(root_data.get("tlogs"), list) or not root_data["tlogs"]:
                raise ValueError("Invalid trusted root.")
        except (OSError, ValueError, registry._DiscoveryError):
            return _result("unknown", facts, "Local Sigstore trust root is malformed or unavailable.")
    facts["local_digest_match"] = digests["artifact"]["sha512"] == expected_hex
    if not facts["local_digest_match"]:
        return _result("error", facts, "Local distribution does not match the independently expected digest.")
    try:
        statement = _statement_from_bundle(_read_json(snapshots["bundle"][1]))
    except OSError:
        return _result("unknown", facts, "Local Sigstore bundle cannot be read.")
    except (registry._DiscoveryError, ValueError):
        return _result("unknown", facts, "Unsupported or malformed local Sigstore bundle.")
    if statement.get("_type") != _STATEMENT or statement.get("predicateType") != PREDICATE:
        return _result("unknown", facts, "Unsupported statement type or predicate.")
    subjects = statement["subject"]
    if len(subjects) != 1 or not isinstance(subjects[0], dict) or \
            subjects[0].get("name") != purl or \
            not isinstance(subjects[0].get("digest"), dict) or \
            subjects[0]["digest"].get("sha512") != expected_hex:
        return _result("error", facts, "Signed statement subject does not bind the exact package and local artifact digest.")
    predicate = statement.get("predicate")
    definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    parameters = definition.get("externalParameters") if isinstance(definition, dict) else None
    workflow = parameters.get("workflow") if isinstance(parameters, dict) else None
    if not isinstance(workflow, dict) or not _safe_policy(workflow.get("repository")):
        return _result("unknown", facts, "Unsupported or missing provenance source assertion.")
    for field, expected in (("repository", config["source_repository"]),
                            ("ref", config.get("source_ref")), ("path", config.get("source_path"))):
        if expected is not None and workflow.get(field) != expected:
            return _result("error", facts, "Provenance source assertion differs from independently expected source policy.")
    details = predicate.get("runDetails")
    builder = details.get("builder") if isinstance(details, dict) else None
    if "builder_id" in config and (not isinstance(builder, dict) or
                                   builder.get("id") != config["builder_id"]):
        return _result("error", facts, "Provenance builder assertion differs from independently expected builder policy.")
    cosign = shutil.which("cosign")
    if not cosign:
        return _result("unknown", facts, "Cosign verifier unavailable (requires Cosign 3.1.4).")
    command = [cosign, "verify-blob-attestation", "--bundle", str(snapshots["bundle"][1]),
               "--type", PREDICATE, "--certificate-identity",
               config["certificate_identity"], "--certificate-oidc-issuer",
               config["certificate_oidc_issuer"], "--digestAlg", "sha512"]
    if trusted_root:
        command.extend(["--trusted-root", str(snapshots["trusted_root"][1])])
    # Cosign checks DSSE, Fulcio certificate/identity, SCT and transparency log.
    # Pass the artifact itself: claim checking remains enabled (never --check-claims=false).
    command.extend(["--", str(snapshots["artifact"][1])])
    try:
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=18, check=False,
                              cwd=directory, env={
                                  "PATH": os.defpath, "HOME": str(directory),
                                  "XDG_CACHE_HOME": str(directory / "cache"),
                                  "XDG_CONFIG_HOME": str(directory),
                              })
    except FileNotFoundError:
        return _result("unknown", facts, "Cosign verifier unavailable.")
    except (OSError, subprocess.TimeoutExpired):
        return _result("unknown", facts, "Cosign verifier unavailable or timed out.")
    try:
        for kind, (original, captured, limit) in snapshots.items():
            current = _read_input(original, limit)
            if current["sha256"] != digests[kind]["sha256"] or \
                    current["_source_stamp"] != digests[kind]["_source_stamp"] or \
                    _read_input(captured, limit)["sha256"] != digests[kind]["sha256"]:
                return _result("error", facts, "Verification input changed during signature verification.")
    except (OSError, ValueError, TimeoutError):
        return _result("error", facts, "Verification input changed or became unavailable.")
    if proc.returncode != 0:
        return _result("error", facts, "Cosign rejected the signature, trust chain, identity, transparency log, or signed digest.")
    facts.update(verification="verified", signature="verified", signer="verified",
                 source_assertion="authenticated", predicate_type=PREDICATE,
                 subject_digest_match=True, source_repository=config["source_repository"],
                 trust="local_root" if trusted_root else "explicit_public_trust",
                 snapshot_sha256={kind: entry["sha256"] for kind, entry in digests.items()},
                 expected_certificate_identity=config["certificate_identity"],
                 expected_certificate_oidc_issuer=config["certificate_oidc_issuer"],
                 expected_policy={key: config[key] for key in (
                     "expected_digest", "certificate_identity", "certificate_oidc_issuer",
                     "source_repository", "source_ref", "source_path", "builder_id",
                     "predicate_type") if key in config},
                 verifier={"name": "cosign", "version": "unrecorded",
                           "captured_at": datetime.now(timezone.utc).isoformat()})
    if "builder_id" in config:
        facts["builder_assertion"] = "authenticated"
    return _result("ok", facts, None)


def verify_registry_distribution(identity, config, *, allow_network_trust=False):
    """Verify one npm tarball using Cosign 3.1.4's keyless DSSE verifier.

    identity is a resolved exact package target; config contains the filename,
    local artifact_path and bundle_path, independently expected sha512:<hex>,
    exact certificate_identity, certificate_oidc_issuer, source_repository,
    and predicate_type. Optional trusted_root_path enables offline trust;
    otherwise allow_network_trust=True explicitly opts into public Sigstore TUF.
    Optional source_ref, source_path, and builder_id constrain signed assertions.
    Caller must confine paths to its configured input directory if needed.
    """
    facts = {"verification": "not_verified", "signature": "not_verified",
             "signer": "not_verified", "source_assertion": "not_verified",
             "builder_assertion": "not_assessed"}
    if not isinstance(identity, dict) or identity.get("kind") != "package" or \
            identity.get("ecosystem") not in ("npm", "PyPI"):
        return _result("unknown", facts, "Only exact-version npm/PyPI package targets are supported.")
    name, version, ecosystem = (identity.get(k) for k in ("name", "version", "ecosystem"))
    name_pattern = registry._NAME_NPM if ecosystem == "npm" else registry._NAME_PYPI
    if not isinstance(name, str) or not isinstance(version, str) or len(name) > 214 or \
            not name_pattern.fullmatch(name) or not registry._VERSION.fullmatch(version) or \
            version.lower() in ("latest", "next", "stable"):
        return _result("error", facts, "Invalid exact-version package target.")
    purl = f"pkg:{'npm' if ecosystem == 'npm' else 'pypi'}/{quote(name, safe='/')}@{quote(version, safe='')}"
    if identity.get("purl", purl) != purl:
        return _result("error", facts, "Target purl conflicts with package identity.")
    if not isinstance(config, dict) or set(config) - _CONFIG_KEYS or _REQUIRED - set(config):
        return _result("error", facts, "Verification policy has missing or unrecognized fields.")
    filename = config["filename"]
    if not isinstance(filename, str) or not registry._FILENAME.fullmatch(filename):
        return _result("error", facts, "Invalid distribution filename.")
    if ecosystem == "PyPI":
        return _result("unknown", facts, "PyPI PEP 740 envelopes require a PEP 740 verifier; Cosign cannot verify them directly.")
    if os.name != "posix" or not all(hasattr(os, name) for name in (
            "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
        return _result("unknown", facts, "Safe local verification snapshots currently require POSIX file APIs.")
    if filename != f"{name.rsplit('/', 1)[-1]}-{version}.tgz":
        return _result("error", facts, "Distribution filename conflicts with exact npm package/version.")
    facts.update(package={"ecosystem": ecosystem, "name": name, "version": version},
                 distribution=filename)
    digest = config["expected_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha512:[0-9a-fA-F]{128}", digest):
        return _result("error", facts, "npm attestation requires an independent sha512:<hex> digest.")
    if config["predicate_type"] != PREDICATE:
        return _result("unknown", facts, "Only SLSA provenance v1 statements are understood.")
    if not _safe_policy(config["certificate_identity"]) or \
            not _https(config["certificate_oidc_issuer"]) or \
            not _https(config["source_repository"]) or \
            any(not _safe_policy(config[k]) for k in
                ("source_ref", "source_path", "builder_id") if k in config):
        return _result("error", facts, "Invalid independent signer, issuer, or source policy.")
    if not allow_network_trust and not config.get("trusted_root_path"):
        return _result("unknown", facts, "Offline verification requires an independently trusted local Sigstore root.")
    try:
        artifact = _path(config["artifact_path"])
        bundle_path = _path(config["bundle_path"])
        trusted_root = _path(config["trusted_root_path"]) if config.get("trusted_root_path") else None
    except (OSError, ValueError):
        return _result("unknown", facts, "A required local artifact, bundle, or trust root is unavailable.")
    if artifact.name != filename:
        return _result("error", facts, "Local artifact basename differs from the exact distribution filename.")
    expected_hex = digest.split(":", 1)[1].lower()
    try:
        with _private_snapshots() as directory:
            return _verify_captured(config, purl, filename, artifact, bundle_path,
                                    trusted_root, expected_hex, facts, directory)
    except (OSError, ValueError):
        return _result("unknown", facts, "Private verification snapshot unavailable.")
