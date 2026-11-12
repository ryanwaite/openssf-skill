"""Registry contract fixtures captured from public exact-version npm/PyPI GETs."""

import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


_SPEC = importlib.util.spec_from_file_location(
    "registry_evidence", Path(__file__).resolve().parent.parent /
    "scripts" / "registry_evidence.py")
evidence = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(evidence)

NPM_NAME = "@sigstore/verify"
NPM_VERSION = "2.0.0"
NPM_SHA512 = "1a0b6ad86b09bb114d52f4332e85ea4704b871e45f2c0267ac81d40ebcc00f41a09ce870ba32642a4c4cfece416a4a34edcdd6b40b3fb19a393c9abb5478de0e"
NPM_META = "https://registry.npmjs.org/%40sigstore%2Fverify/2.0.0"
NPM_ATT = "https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fverify@2.0.0"
PYPI_META = "https://pypi.org/pypi/sampleproject/4.0.0/json"
WHEEL = "sampleproject-4.0.0-py3-none-any.whl"
SDIST = "sampleproject-4.0.0.tar.gz"
WHEEL_SHA = "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"
SDIST_SHA = "0ace7980f82c5815ede4cd7bf9f6693684cec2ae47b9b7ade9add533b8627c6b"


def _b64(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def _npm():
    metadata = {
        "name": NPM_NAME, "version": NPM_VERSION,
        "_npmUser": {"name": "npm-publisher", "email": "not-reported@example.org"},
        "repository": {"url": "git+https://github.com/sigstore/sigstore-js.git"},
        "dist": {
            "integrity": "sha512-" + base64.b64encode(bytes.fromhex(NPM_SHA512)).decode(),
            "tarball": "https://registry.npmjs.org/@sigstore/verify/-/verify-2.0.0.tgz",
            "attestations": {"url": NPM_ATT, "provenance": {
                "predicateType": "https://slsa.dev/provenance/v1"}}}}
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "predicateType": "https://slsa.dev/provenance/v1",
                 "subject": [{"name": "pkg:npm/%40sigstore/verify@2.0.0",
                              "digest": {"sha512": NPM_SHA512}}],
                 "predicate": {"buildDefinition": {"externalParameters": {
                     "workflow": {"repository": "https://github.com/sigstore/sigstore-js",
                                  "path": ".github/workflows/release.yml"}}}}}
    attestations = {"attestations": [{"predicateType": statement["predicateType"],
                    "bundle": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                               "verificationMaterial": {"x509CertificateChain": {}},
                               "dsseEnvelope": {"payload": _b64(statement),
                                                "payloadType": "application/vnd.in-toto+json",
                                                "signatures": [{"sig": "fixture"}]}}}]}
    return metadata, attestations


def _pypi():
    metadata = {"info": {"name": "sampleproject", "version": "4.0.0"},
                "urls": [{"filename": name, "packagetype": kind, "yanked": False,
                          "digests": {"sha256": sha}, "provenance": None}
                         for name, kind, sha in
                         [(WHEEL, "bdist_wheel", WHEEL_SHA), (SDIST, "sdist", SDIST_SHA)]]}
    payloads = {}
    for filename, sha in [(WHEEL, WHEEL_SHA), (SDIST, SDIST_SHA)]:
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "predicateType": "https://docs.pypi.org/attestations/publish/v1",
                     "subject": [{"name": filename, "digest": {"sha256": sha}}],
                     "predicate": None}
        payloads[f"https://pypi.org/integrity/sampleproject/4.0.0/{filename}/provenance"] = {
            "version": 1, "attestation_bundles": [{
                "publisher": {"kind": "GitHub", "repository": "pypa/sampleproject",
                              "workflow": "release.yml", "environment": "", "claims": None},
                "attestations": [{"version": 1, "envelope": {
                    "statement": _b64(statement), "signature": "fixture"},
                    "verification_material": {"certificate": "fixture"}}]}]}
    return metadata, payloads


def _request(responses, calls):
    def get(url):
        calls.append(url)
        value = responses[url]
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, bytes) else json.dumps(value).encode()
    return get


def _target(ecosystem="npm", name=NPM_NAME, version=NPM_VERSION):
    return {"kind": "package", "ecosystem": ecosystem, "name": name, "version": version}


class RegistryEvidenceTests(unittest.TestCase):
    def test_public_response_read_is_size_and_elapsed_time_bounded(self):
        with patch.object(evidence, "build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read1.side_effect = [b"{}", b""]
            self.assertEqual(evidence._read_public(NPM_META), b"{}")
            response.read1.side_effect = [b"12345"]
            with patch.object(evidence, "MAX_BODY", 4), \
                    self.assertRaisesRegex(evidence._DiscoveryError, "size limit"):
                evidence._read_public(NPM_META)
            response.read1.side_effect = [b"x", b""]
            with patch.object(evidence.time, "monotonic", side_effect=[0, 0, 4]), \
                    self.assertRaisesRegex(evidence._Unavailable, "time budget"):
                evidence._read_public(NPM_META)

    def test_offline_by_default_and_unknown_ecosystem(self):
        with patch.object(evidence, "_read_public", side_effect=AssertionError("network")):
            result = evidence.discover_registry_evidence(_target())
            unknown = evidence.discover_registry_evidence(_target(ecosystem="NuGet"),
                                                           allow_fetch=True)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["facts"]["verification"], "not_verified")
        self.assertEqual(unknown["status"], "unknown")

    def test_scoped_npm_digest_attestation_and_unverified_claims(self):
        metadata, att = _npm()
        calls = []
        result = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, calls),
            expected_digests={"verify-2.0.0.tgz": "sha512:" + NPM_SHA512})
        self.assertEqual(result["status"], "ok", result["gaps"])
        self.assertTrue(any("Signatures not verified" in gap for gap in result["gaps"]))
        self.assertEqual(calls, [NPM_META, NPM_ATT])
        dist = result["facts"]["distributions"][0]
        self.assertTrue(dist["expected_digest_match"])
        self.assertEqual(dist["digest"]["value"], NPM_SHA512)
        self.assertEqual(dist["attestations"]["status"], "discovered")
        self.assertTrue(dist["attestations"]["entries"][0]["subject_digest_match"])
        self.assertEqual(dist["attestations"]["verification"], "not_verified")
        self.assertEqual(dist["publisher_claim_unverified"], "npm-publisher")
        self.assertNotIn("not-reported@example.org", json.dumps(result))
        json.dumps(result, allow_nan=False)

    def test_pypi_wheel_sdist_independently_associated(self):
        metadata, attestations = _pypi()
        metadata["urls"][0]["provenance"] = "http://127.0.0.1/not-an-evidence-url"
        calls = []
        result = evidence.discover_registry_evidence(
            _target("PyPI", "sampleproject", "4.0.0"),
            request=_request({PYPI_META: metadata, **attestations}, calls),
            expected_digests={WHEEL: "sha256:" + WHEEL_SHA, SDIST: "sha256:" + SDIST_SHA})
        self.assertEqual(result["status"], "ok", result["gaps"])
        self.assertEqual(set(calls), {PYPI_META, *attestations})
        distributions = result["facts"]["distributions"]
        self.assertEqual({d["kind"] for d in distributions}, {"wheel", "sdist"})
        self.assertTrue(all(d["expected_digest_match"] for d in distributions))
        self.assertTrue(all(d["attestations"]["entries"][0]["subject_digest_match"]
                            for d in distributions))
        self.assertTrue(all(d["attestations"]["verification"] == "not_verified"
                            for d in distributions))
        self.assertEqual(distributions[0]["attestations"]["entries"][0]
                         ["publisher_claims_unverified"]["repository"], "pypa/sampleproject")

    def test_hyphenated_sdist_and_wheel_names(self):
        project, version = "my-package", "1.2.3"
        wheel = "my_package-1.2.3-py3-none-any.whl"
        sdist = "my-package-1.2.3.tar.gz"
        metadata_url = f"https://pypi.org/pypi/{project}/{version}/json"
        metadata = {"info": {"name": project, "version": version},
                    "urls": [{"filename": filename, "packagetype": kind,
                              "yanked": False, "digests": {"sha256": "a" * 64}}
                             for filename, kind in
                             [(wheel, "bdist_wheel"), (sdist, "sdist")]]}
        responses = {metadata_url: metadata}
        for filename in (wheel, sdist):
            url = f"https://pypi.org/integrity/{project}/{version}/{filename}/provenance"
            responses[url] = HTTPError(url, 404, "not found", {}, None)
        result = evidence.discover_registry_evidence(
            _target("PyPI", project, version), request=_request(responses, []))
        self.assertEqual(result["status"], "ok", result["gaps"])
        self.assertEqual({d["filename"] for d in result["facts"]["distributions"]},
                         {wheel, sdist})

    def test_credentials_in_publisher_and_source_claims_are_not_reported(self):
        metadata, att = _npm()
        metadata["_npmUser"]["name"] = "api_key=SECRET_PUBLISHER"
        metadata["repository"]["url"] = "git+https://alice:SECRET_REPO@github.com/org/repo.git"
        statement = json.loads(base64.b64decode(att["attestations"][0]
                                                ["bundle"]["dsseEnvelope"]["payload"]))
        workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        workflow["repository"] = "https://bob:SECRET_SOURCE@github.com/org/repo?token=SECRET_QUERY"
        workflow["ref"] = "token=SECRET_REF"
        workflow["path"] = "https://github.com/org/%74oken%3dSECRET_ENCODED"
        att["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = _b64(statement)
        result = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, []))
        self.assertEqual(result["status"], "ok", result["gaps"])
        dist = result["facts"]["distributions"][0]
        self.assertIsNone(dist["publisher_claim_unverified"])
        self.assertIsNone(dist["repository_claim_unverified"])
        self.assertIsNone(dist["attestations"]["entries"][0]
                          ["source_claims_unverified"]["repository"])
        self.assertIsNone(dist["attestations"]["entries"][0]
                          ["source_claims_unverified"]["ref"])
        self.assertIsNone(dist["attestations"]["entries"][0]
                          ["source_claims_unverified"]["path"])
        for secret in ("SECRET_PUBLISHER", "SECRET_REPO", "SECRET_SOURCE",
                       "SECRET_QUERY", "SECRET_REF", "SECRET_ENCODED"):
            self.assertNotIn(secret, json.dumps(result))

        pypi, provenance = _pypi()
        for value in provenance.values():
            value["attestation_bundles"][0]["publisher"]["repository"] = \
                "https://user:SECRET_PYPI@example.com/repo"
            value["attestation_bundles"][0]["publisher"]["workflow"] = \
                "https://github.com/repo/workflow?token=SECRET_WORKFLOW"
        result = evidence.discover_registry_evidence(
            _target("PyPI", "sampleproject", "4.0.0"),
            request=_request({PYPI_META: pypi, **provenance}, []))
        self.assertEqual(result["status"], "ok")
        for dist in result["facts"]["distributions"]:
            claims = dist["attestations"]["entries"][0]["publisher_claims_unverified"]
            self.assertEqual(claims["kind"], "GitHub")
            self.assertIsNone(claims["repository"])
            self.assertIsNone(claims["workflow"])
        self.assertNotIn("SECRET_PYPI", json.dumps(result))
        self.assertNotIn("SECRET_WORKFLOW", json.dumps(result))

        metadata["repository"]["url"] = "https://[malformed"
        result = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, []))
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["facts"]["distributions"][0]["repository_claim_unverified"])

    def test_missing_attestations_and_yanked_file(self):
        metadata, _ = _pypi()
        metadata["urls"][0]["yanked"] = "withdrawn"
        urls = {PYPI_META: metadata}
        for filename in (WHEEL, SDIST):
            url = f"https://pypi.org/integrity/sampleproject/4.0.0/{filename}/provenance"
            urls[url] = HTTPError(url, 404, "not found", {}, None)
        result = evidence.discover_registry_evidence(
            _target("PyPI", "sampleproject", "4.0.0"), request=_request(urls, []))
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["facts"]["distributions"][0]["yanked"])
        self.assertTrue(all(d["attestations"]["status"] == "absent"
                            for d in result["facts"]["distributions"]))
        self.assertTrue(any("yanked" in gap for gap in result["gaps"]))

    def test_npm_without_advertised_attestations(self):
        metadata, _ = _npm()
        del metadata["dist"]["attestations"]
        calls = []
        result = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata}, calls))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["facts"]["distributions"][0]["attestations"]["status"], "absent")
        self.assertEqual(calls, [NPM_META])

    def test_one_inaccessible_file_does_not_hide_other_distribution(self):
        metadata, attestations = _pypi()
        wheel_url = next(url for url in attestations if WHEEL in url)
        attestations[wheel_url] = HTTPError(wheel_url, 403, "disabled", {}, None)
        result = evidence.discover_registry_evidence(
            _target("PyPI", "sampleproject", "4.0.0"),
            request=_request({PYPI_META: metadata, **attestations}, []))
        self.assertEqual(result["status"], "unknown")
        self.assertEqual([d["attestations"]["status"]
                          for d in result["facts"]["distributions"]], ["unknown", "discovered"])

    def test_digest_and_signed_subject_conflicts_are_not_success(self):
        metadata, att = _npm()
        bad = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, []),
            expected_digests={"verify-2.0.0.tgz": "sha512:" + "f" * 128})
        self.assertEqual(bad["status"], "error")
        self.assertFalse(bad["facts"]["distributions"][0]["expected_digest_match"])
        statement = json.loads(base64.b64decode(att["attestations"][0]
                                                ["bundle"]["dsseEnvelope"]["payload"]))
        statement["subject"][0]["digest"]["sha512"] = "f" * 128
        att["attestations"][0]["bundle"]["dsseEnvelope"]["payload"] = _b64(statement)
        bad = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, []))
        self.assertEqual(bad["status"], "error")
        self.assertFalse(bad["facts"]["distributions"][0]
                         ["attestations"]["entries"][0]["subject_digest_match"])

    def test_unmatched_expected_filename_is_conflict(self):
        metadata, att = _npm()
        result = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META: metadata, NPM_ATT: att}, []),
            expected_digests={"another-file.tgz": "sha256:" + "0" * 64})
        self.assertEqual(result["status"], "error")

    def test_malformed_expected_digest_rejected_without_fetch(self):
        calls = []
        result = evidence.discover_registry_evidence(
            _target(), request=_request({}, calls),
            expected_digests={"../verify-2.0.0.tgz": "sha256:" + "0" * 64})
        self.assertEqual(result["status"], "error")
        self.assertEqual(calls, [])

    def test_unsafe_attestation_url_never_requested(self):
        for url in ("http://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fverify@2.0.0",
                    "https://127.0.0.1/-/npm/v1/attestations/@sigstore%2fverify@2.0.0",
                    NPM_ATT + "?auth=token", NPM_ATT + "/../other",
                    "https://registry.npmjs.org@127.0.0.1/-/npm/v1/attestations/x"):
            with self.subTest(url=url):
                metadata, _ = _npm()
                metadata["dist"]["attestations"]["url"] = url
                calls = []
                result = evidence.discover_registry_evidence(
                    _target(), request=_request({NPM_META: metadata}, calls))
                self.assertEqual(result["status"], "error")
                self.assertEqual(calls, [NPM_META])

    def test_redirect_oversized_nonfinite_and_malformed_evidence(self):
        metadata, att = _npm()
        cases = [
            ({NPM_META: HTTPError(NPM_META, 302, "redirect", {"Location": "http://127.0.0.1"}, None)},
             "unknown"),
            ({NPM_META: b" " * (evidence.MAX_BODY + 1)}, "error"),
            ({NPM_META: b'{"name":NaN}'}, "error"),
            ({NPM_META: b'{"name":1e9999}'}, "error"),
            ({NPM_META: dict(metadata, version="1.0.0")}, "error"),
            ({NPM_META: metadata, NPM_ATT: b'{"attestations": []}'}, "error"),
        ]
        for responses, expected in cases:
            with self.subTest(responses=list(responses)):
                result = evidence.discover_registry_evidence(
                    _target(), request=_request(responses, []))
                self.assertEqual(result["status"], expected)
                json.dumps(result, allow_nan=False)
        self.assertEqual(att["attestations"][0]["predicateType"],
                         "https://slsa.dev/provenance/v1")

    def test_malformed_pypi_attestation_preserves_other_distribution(self):
        metadata, attestations = _pypi()
        wheel_url = next(url for url in attestations if WHEEL in url)
        attestations[wheel_url]["version"] = 2
        result = evidence.discover_registry_evidence(
            _target("PyPI", "sampleproject", "4.0.0"),
            request=_request({PYPI_META: metadata, **attestations}, []))
        self.assertEqual(result["status"], "error")
        self.assertEqual([d["attestations"]["status"]
                          for d in result["facts"]["distributions"]], ["error", "discovered"])

    def test_missing_release_and_conflicting_identity(self):
        missing = evidence.discover_registry_evidence(
            _target(), request=_request({NPM_META:
                HTTPError(NPM_META, 404, "not found", {}, None)}, []))
        self.assertEqual(missing["status"], "unknown")
        conflict = evidence.discover_registry_evidence(
            dict(_target(), purl="pkg:npm/other@2.0.0"), request=lambda _: b"{}")
        self.assertEqual(conflict["status"], "error")


if __name__ == "__main__":
    unittest.main()
