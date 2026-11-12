"""Opt-in, read-only discovery of exact-version public npm/PyPI release evidence.

Registry metadata and attestation statements are untrusted observations, not
signature verification or an independently trusted expected signer.
"""

import base64
import binascii
from datetime import datetime, timezone
import json
import math
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_BODY = 512 * 1024
MAX_STATEMENT = 128 * 1024
MAX_DISTRIBUTIONS = 12
MAX_ATTESTATIONS = 16
TIMEOUT = 3
DEADLINE = 20
_SHA = {"sha256": 64, "sha512": 128}
_NAME_NPM = re.compile(r"(?:[a-z0-9][a-z0-9._~-]*|@[a-z0-9][a-z0-9._~-]*/[a-z0-9][a-z0-9._~-]*)\Z")
_NAME_PYPI = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}\Z")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,254}\Z")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|token|secret|password|credential|"
    r"authorization|bearer)\s*[:=]\s*\S+|"
    r"(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    r"npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{16,})")


class _DiscoveryError(Exception):
    pass


class _Unavailable(Exception):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _read_public(url):
    # No proxy inherited from the environment, credentials, cookies, or redirects.
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(Request(url, headers={"Accept": "application/json",
                                           "User-Agent": "openssf-skill-registry-discovery/1"}),
                     timeout=TIMEOUT) as response:
        if response.status != 200:
            raise _Unavailable(f"Registry returned HTTP {response.status}.")
        deadline = time.monotonic() + TIMEOUT
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise _Unavailable("Registry response time budget exhausted.")
            block = response.read1(min(65536, MAX_BODY + 1 - len(data)))
            if not block:
                return bytes(data)
            data.extend(block)
            if len(data) > MAX_BODY:
                raise _DiscoveryError("Registry response exceeds the size limit.")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DiscoveryError("Registry JSON contains duplicate keys.")
        result[key] = value
    return result


def _finite(value):
    result = float(value)
    if not math.isfinite(result):
        raise _DiscoveryError("Registry JSON contains a nonfinite number.")
    return result


def _invalid_constant(_):
    raise _DiscoveryError("Registry JSON contains a nonfinite number.")


def _json(data, limit=MAX_BODY):
    if not isinstance(data, bytes) or len(data) > limit:
        raise _DiscoveryError("Registry response is not bounded JSON bytes.")
    try:
        return json.loads(data, object_pairs_hook=_unique, parse_float=_finite,
                          parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise _DiscoveryError("Malformed registry JSON.") from exc


def _get(url, request, deadline):
    if time.monotonic() >= deadline:
        raise _Unavailable("Registry discovery time budget exhausted.")
    try:
        return _json(request(url))
    except HTTPError as exc:
        if exc.code == 404:
            raise _Unavailable("Registry resource not found (release withdrawn or no attestation).") from exc
        if exc.code in (301, 302, 303, 307, 308):
            raise _Unavailable("Registry redirect refused.") from exc
        raise _Unavailable(f"Registry returned HTTP {exc.code}.") from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise _Unavailable("Registry request unavailable or timed out.") from exc


def _location(value, host, path):
    if not isinstance(value, str) or len(value) > 1024 or \
            any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
        raise _DiscoveryError("Invalid registry evidence URL.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.netloc != host or parsed.query or parsed.fragment \
            or unquote(parsed.path) != path:
        raise _DiscoveryError("Registry evidence URL is not the expected public resource.")
    return value


def _digest(algorithm, value):
    if algorithm not in _SHA or not isinstance(value, str) or \
            len(value) != _SHA[algorithm] or not _HEX.fullmatch(value):
        raise _DiscoveryError("Registry digest is missing or malformed.")
    return {"algorithm": algorithm, "value": value.lower()}


def _expected(filename, digest, expected_digests):
    if filename not in expected_digests:
        return None
    value = expected_digests[filename]
    if not isinstance(value, str) or ":" not in value:
        raise _DiscoveryError("Expected digests must use sha256:<hex> or sha512:<hex>.")
    algorithm, hex_value = value.split(":", 1)
    return _digest(algorithm, hex_value)


def _association(filename, digest, expected_digests, gaps):
    expected = _expected(filename, digest, expected_digests)
    if expected is None:
        return None
    match = expected == digest
    if not match:
        gaps.append(f"{filename}: independently expected digest does not match registry metadata.")
    return match


def _statement(encoded):
    if not isinstance(encoded, str) or len(encoded) > MAX_STATEMENT * 2:
        raise _DiscoveryError("Attestation statement exceeds the size limit.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _DiscoveryError("Malformed attestation statement encoding.") from exc
    statement = _json(raw, MAX_STATEMENT)
    if not isinstance(statement, dict) or not isinstance(statement.get("subject"), list):
        raise _DiscoveryError("Malformed attestation statement subject.")
    return statement


def _claim(value):
    # Do not copy arbitrary untrusted publisher/source data into reports.
    if not isinstance(value, str) or not 0 < len(value) <= 512 or \
            not all(32 <= ord(ch) < 127 for ch in value) or _SECRET.search(value) or \
            re.fullmatch(r"[A-Za-z0-9_+/-]{40,}={0,2}", value):
        return None
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname or parsed.username or \
                    parsed.password or parsed.query or parsed.fragment or "%" in value or \
                    re.search(r"(?i)/(?:token|secret|api[_-]?key|password|credential)/[^/]+",
                              parsed.path):
                return None
        except ValueError:
            return None
    elif re.search(r"[^/\s:]+:[^/@\s]+@[^/\s]+", value):
        return None
    return value


def _signature(value):
    return isinstance(value, str) and 0 < len(value) <= 512 and \
        all(32 <= ord(ch) < 127 for ch in value)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _subject(statement, name, digest):
    subjects = statement["subject"]
    if not 0 < len(subjects) <= MAX_ATTESTATIONS:
        raise _DiscoveryError("Attestation statement has no bounded subjects.")
    matches = []
    for subject in subjects:
        if not isinstance(subject, dict):
            raise _DiscoveryError("Malformed attestation subject.")
        if subject.get("name") != name:
            continue
        hashes = subject.get("digest")
        if not isinstance(hashes, dict):
            raise _DiscoveryError("Malformed attestation subject digest.")
        value = hashes.get(digest["algorithm"])
        if value is None:
            matches.append(None)
        else:
            matches.append(isinstance(value, str) and value.lower() == digest["value"])
    if not matches:
        return False
    return False if False in matches else None if None in matches else True


def _npm_attestations(metadata, name, version, digest, request, deadline, gaps):
    att = metadata.get("attestations")
    if att is None:
        gaps.append("npm: no dist.attestations advertised for this exact version.")
        return {"status": "absent", "verification": "not_verified"}
    if not isinstance(att, dict):
        raise _DiscoveryError("Malformed npm dist.attestations.")
    path = f"/-/npm/v1/attestations/{name}@{version}"
    url = _location(att.get("url"), "registry.npmjs.org", path)
    result = {"status": "unknown", "verification": "not_verified",
              "reference": {"url": url, "schema": "npm attestation bundles"},
              "advertised_predicate_type": _claim((att.get("provenance") or {}).get("predicateType"))
              if isinstance(att.get("provenance"), dict) else None}
    try:
        payload = _get(url, request, deadline)
    except _Unavailable as exc:
        result["retrieved_at"] = _now()
        gaps.append(f"npm: advertised attestation unavailable: {exc}")
        return result
    result["retrieved_at"] = _now()
    entries = payload.get("attestations") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_ATTESTATIONS:
        raise _DiscoveryError("Malformed or excessive npm attestations.")
    summaries = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("bundle"), dict):
            raise _DiscoveryError("Malformed npm attestation bundle.")
        bundle = entry["bundle"]
        envelope = bundle.get("dsseEnvelope")
        material = bundle.get("verificationMaterial")
        if not isinstance(envelope, dict) or not isinstance(material, dict) or not material or \
                not isinstance(envelope.get("signatures"), list) or \
                not envelope["signatures"]:
            raise _DiscoveryError("npm attestation lacks a DSSE signature or verification material.")
        statement = _statement(envelope.get("payload"))
        predicate_type = _claim(statement.get("predicateType"))
        if predicate_type != entry.get("predicateType"):
            raise _DiscoveryError("npm attestation predicate types conflict.")
        purl_name = quote(name, safe="/")
        match = _subject(statement, f"pkg:npm/{purl_name}@{version}", digest)
        if match is False:
            gaps.append("npm: signed statement subject differs from registry package or digest.")
        elif match is None:
            gaps.append("npm: signed statement does not include the registry digest algorithm.")
        predicate = statement.get("predicate")
        definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
        parameters = definition.get("externalParameters") if isinstance(definition, dict) else None
        workflow = parameters.get("workflow") if isinstance(parameters, dict) else None
        source = {key: _claim(workflow.get(key)) for key in ("repository", "path", "ref")} \
            if isinstance(workflow, dict) else None
        summaries.append({"predicate_type": predicate_type, "subject_digest_match": match,
                          "verification_material_present": bool(material),
                          "source_claims_unverified": source})
    result.update(status="discovered", entries=summaries)
    return result


def _pypi_attestations(url, filename, digest, request, deadline, gaps):
    result = {"status": "unknown", "verification": "not_verified",
              "reference": {"url": url, "schema": "PyPI Integrity API provenance v1 (PEP 740)"}}
    try:
        payload = _get(url, request, deadline)
    except _Unavailable as exc:
        result["retrieved_at"] = _now()
        if "not found" in str(exc):
            result["status"] = "absent"
            gaps.append(f"{filename}: no PyPI provenance (HTTP 404).")
        else:
            gaps.append(f"{filename}: PyPI provenance unavailable: {exc}")
        return result
    result["retrieved_at"] = _now()
    bundles = payload.get("attestation_bundles") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("version") != 1 or \
            not isinstance(bundles, list) or not 0 < len(bundles) <= MAX_ATTESTATIONS:
        raise _DiscoveryError("Malformed or unsupported PyPI provenance.")
    entries = []
    for bundle in bundles:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("attestations"), list) or \
                not 0 < len(bundle["attestations"]) <= MAX_ATTESTATIONS:
            raise _DiscoveryError("Malformed PyPI attestation bundle.")
        publisher = bundle.get("publisher")
        claims = {key: _claim(publisher.get(key)) for key in
                  ("kind", "repository", "workflow", "environment")} \
            if isinstance(publisher, dict) else None
        for entry in bundle["attestations"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("envelope"), dict) or \
                    not isinstance(entry.get("verification_material"), dict) or \
                    not entry["verification_material"]:
                raise _DiscoveryError("Malformed PyPI attestation.")
            if not _signature(entry["envelope"].get("signature")):
                raise _DiscoveryError("PyPI attestation has no signature.")
            statement = _statement(entry["envelope"].get("statement"))
            match = _subject(statement, filename, digest)
            if match is False:
                gaps.append(f"{filename}: signed statement subject differs from registry file or digest.")
            elif match is None:
                gaps.append(f"{filename}: signed statement does not include the registry digest algorithm.")
            entries.append({"predicate_type": _claim(statement.get("predicateType")),
                            "subject_digest_match": match,
                            "verification_material_present": bool(entry["verification_material"]),
                            "publisher_claims_unverified": claims})
    result.update(status="discovered", entries=entries)
    return result


def _npm(name, version, request, deadline, expected_digests, gaps):
    host = "registry.npmjs.org"
    url = f"https://{host}/{quote(name, safe='')}/{quote(version, safe='')}"
    data = _get(url, request, deadline)
    retrieved_at = _now()
    if not isinstance(data, dict) or data.get("name") != name or data.get("version") != version \
            or not isinstance(data.get("dist"), dict):
        raise _DiscoveryError("npm metadata conflicts with the exact requested name/version.")
    dist = data["dist"]
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or not re.fullmatch(r"sha(?:256|512)-[A-Za-z0-9+/]+={0,2}", integrity):
        raise _DiscoveryError("npm distribution has no supported SRI digest.")
    algorithm, encoded = integrity.split("-", 1)
    try:
        digest = _digest(algorithm, base64.b64decode(encoded, validate=True).hex())
    except (ValueError, binascii.Error) as exc:
        raise _DiscoveryError("Malformed npm SRI digest.") from exc
    filename = f"{name.rsplit('/', 1)[-1]}-{version}.tgz"
    tarball = _location(dist.get("tarball"), host, f"/{name}/-/{filename}")
    result = {"filename": filename, "kind": "npm_tarball",
              "digest": {**digest, "source": url + "#dist.integrity"},
              "tarball_url": tarball,
              "expected_digest_match": _association(filename, digest, expected_digests, gaps),
              "metadata_source": url, "metadata_retrieved_at": retrieved_at,
              "publisher_claim_unverified": _claim(data.get("_npmUser", {}).get("name"))
              if isinstance(data.get("_npmUser"), dict) else None,
              "repository_claim_unverified": _claim(
                  data.get("repository", {}).get("url")) if isinstance(data.get("repository"), dict) else None}
    try:
        result["attestations"] = _npm_attestations(dist, name, version, digest,
                                                   request, deadline, gaps)
    except _DiscoveryError as exc:
        gaps.append(f"{filename}: {exc}")
        result["attestations"] = {"status": "error", "verification": "not_verified"}
    return [result]


def _pypi(name, version, request, deadline, expected_digests, gaps):
    host = "pypi.org"
    canonical = re.sub(r"[-_.]+", "-", name).lower()
    url = f"https://{host}/pypi/{quote(canonical, safe='')}/{quote(version, safe='')}/json"
    data = _get(url, request, deadline)
    retrieved_at = _now()
    info = data.get("info") if isinstance(data, dict) else None
    files = data.get("urls") if isinstance(data, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("name"), str) or \
            re.sub(r"[-_.]+", "-", info["name"]).lower() != canonical or \
            info.get("version") != version or not isinstance(files, list) or \
            not 0 < len(files) <= MAX_DISTRIBUTIONS:
        raise _DiscoveryError("PyPI metadata conflicts with the exact name/version or file bound.")
    result, seen = [], set()
    for file in files:
        if not isinstance(file, dict):
            raise _DiscoveryError("Malformed PyPI distribution.")
        filename = file.get("filename")
        kind = file.get("packagetype")
        if not isinstance(filename, str) or not _FILENAME.fullmatch(filename) or \
                not (filename.endswith((".whl", ".tar.gz", ".zip"))) or \
                (kind == "bdist_wheel") != filename.endswith(".whl") or \
                kind not in ("bdist_wheel", "sdist") or filename in seen:
            raise _DiscoveryError("PyPI distribution filename/type is unsafe or duplicated.")
        stem = filename.removesuffix(".whl" if kind == "bdist_wheel" else
                                     ".tar.gz" if filename.endswith(".tar.gz") else ".zip")
        # Wheel distribution names have no hyphens; PEP 625 sdists can.
        parts = stem.split("-") if kind == "bdist_wheel" else stem.rsplit("-", 1)
        if (kind == "bdist_wheel" and len(parts) not in (5, 6)) or \
                (kind == "sdist" and len(parts) != 2) or \
                re.sub(r"[-_.]+", "-", parts[0]).lower() != canonical or \
                parts[1] != version:
            raise _DiscoveryError("PyPI distribution filename conflicts with the exact package/version.")
        seen.add(filename)
        digests = file.get("digests")
        digest = _digest("sha256", digests.get("sha256") if isinstance(digests, dict) else None)
        provenance_url = f"https://{host}/integrity/{quote(canonical, safe='')}/{quote(version, safe='')}/{quote(filename, safe='')}/provenance"
        yanked = file.get("yanked")
        if not isinstance(yanked, (bool, str)):
            raise _DiscoveryError("Malformed PyPI yanked status.")
        item = {"filename": filename, "kind": "wheel" if kind == "bdist_wheel" else "sdist",
                "digest": {**digest, "source": url + "#urls"},
                "expected_digest_match": _association(filename, digest, expected_digests, gaps),
                "metadata_source": url, "metadata_retrieved_at": retrieved_at,
                "yanked": bool(yanked)}
        if yanked:
            gaps.append(f"{filename}: release distribution is yanked.")
        try:
            item["attestations"] = _pypi_attestations(provenance_url, filename, digest,
                                                      request, deadline, gaps)
        except _DiscoveryError as exc:
            gaps.append(f"{filename}: {exc}")
            item["attestations"] = {"status": "error", "verification": "not_verified",
                                    "reference": {"url": provenance_url,
                                                  "schema": "PyPI Integrity API provenance v1 (PEP 740)"}}
        result.append(item)
    return result


def discover_registry_evidence(target, *, allow_fetch=False, request=None,
                               expected_digests=None):
    """Discover official public evidence for an already resolved package target.

    Network is off unless allow_fetch=True. Injecting request(url)->bytes is an
    alternative explicit opt-in for offline tests; it must enforce its own bounds
    if used for real I/O. expected_digests maps *distribution filenames* to
    independently obtained 'sha256:<hex>' or 'sha512:<hex>' values.
    No downloaded distribution or signed statement is cryptographically verified.
    """
    facts = {"verification": "not_verified"}
    gaps = []
    if not isinstance(target, dict) or target.get("kind") != "package" or \
            target.get("ecosystem") not in ("npm", "PyPI"):
        return {"status": "unknown", "facts": facts,
                "gaps": ["Registry discovery supports only exact-version npm/PyPI package targets."]}
    ecosystem, name, version = (target.get(key) for key in ("ecosystem", "name", "version"))
    if not isinstance(name, str) or not isinstance(version, str) or len(name) > 214 or \
            not (_NAME_NPM if ecosystem == "npm" else _NAME_PYPI).fullmatch(name) or \
            not _VERSION.fullmatch(version) or version.lower() in ("latest", "next", "stable"):
        return {"status": "error", "facts": facts,
                "gaps": ["Unsafe or non-exact registry package name/version."]}
    if not allow_fetch and request is None:
        return {"status": "unknown", "facts": facts,
                "gaps": ["Registry discovery requires explicit allow_fetch=True."]}
    if request is not None and not callable(request):
        return {"status": "error", "facts": facts, "gaps": ["request must be callable."]}
    if not isinstance(expected_digests if expected_digests is not None else {}, dict):
        return {"status": "error", "facts": facts, "gaps": ["expected_digests must be a filename map."]}
    try:
        for filename, value in (expected_digests or {}).items():
            if not isinstance(filename, str) or not _FILENAME.fullmatch(filename) or \
                    not isinstance(value, str) or ":" not in value:
                raise _DiscoveryError("Expected digests require safe filenames and algorithm:hex values.")
            _digest(*value.split(":", 1))
    except _DiscoveryError as exc:
        return {"status": "error", "facts": facts, "gaps": [str(exc)]}
    purl = f"pkg:{'npm' if ecosystem == 'npm' else 'pypi'}/{quote(name, safe='/')}@{quote(version, safe='')}"
    if "purl" in target and target["purl"] != purl:
        return {"status": "error", "facts": facts, "gaps": ["Package purl conflicts with exact identity."]}
    facts.update(registry_host="registry.npmjs.org" if ecosystem == "npm" else "pypi.org",
                 retrieval_started_at=_now(),
                 package={"ecosystem": ecosystem, "name": name, "version": version,
                          "purl": purl})
    gaps.append("Signatures not verified; metadata/digest association is not trust.")
    expected = expected_digests or {}
    try:
        distributions = (_npm if ecosystem == "npm" else _pypi)(
            name, version, request or _read_public, time.monotonic() + DEADLINE, expected, gaps)
        facts["distributions"] = distributions
        if set(expected) - {d["filename"] for d in distributions}:
            gaps.append("An expected digest filename does not match an exact-version distribution.")
        unknown = any(d["attestations"]["status"] == "unknown" or
                      any(entry["subject_digest_match"] is None for entry in
                          d["attestations"].get("entries", [])) for d in distributions)
        conflict = bool(set(expected) - {d["filename"] for d in distributions}) or \
            any(d["expected_digest_match"] is False or
                       any(entry["subject_digest_match"] is False for entry in
                           d["attestations"].get("entries", [])) for d in distributions)
        malformed = any(d["attestations"]["status"] == "error" for d in distributions)
        status = "error" if conflict or malformed else "unknown" if unknown else "ok"
    except _Unavailable as exc:
        status = "unknown"
        gaps.append(str(exc))
    except (_DiscoveryError, TypeError, ValueError) as exc:
        status = "error"
        gaps.append(str(exc) if isinstance(exc, _DiscoveryError) else "Malformed registry response.")
    facts["retrieved_at"] = _now()
    return {"status": status, "facts": facts, "gaps": gaps}
