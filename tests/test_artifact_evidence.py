"""Local synthetic verification: no signing, publishing, or live trust lookup."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "artifact_evidence", Path(__file__).resolve().parent.parent /
    "scripts" / "artifact_evidence.py")
ae = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ae)

SOURCE = "github.com/example/project"
BUILDER = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
SIGNER = "maintainer@example.org"
ISSUER = "https://accounts.google.com"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name)
        self.artifact = self.write("artifact.tar", b"release binary")
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.bundle = self.write("bundle.json", json.dumps({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"certificate": {}},
            "messageSignature": {"signature": "synthetic"}
        }))
        self.root = self.write("root.json", '{"mediaType":"synthetic"}')
        self.provenance = self.write("provenance.intoto.jsonl", b"local fixture")

    def write(self, name, content):
        path = self.path / name
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def signature(self, **kw):
        return ae.verify_signature(self.artifact, self.digest, self.bundle,
                                   SIGNER, ISSUER, trusted_root_path=self.root, **kw)

    def statement(self, digest=None, builder=BUILDER, predicate=ae.PREDICATE,
                  commit=None):
        source = "git+https://" + SOURCE + "@refs/tags/v1.0.0"
        if predicate == ae.PREDICATE_V02:
            details = {"builder": {"id": builder}, "invocation": {
                "configSource": {"uri": source, "digest": {"sha1": commit or "a" * 40}}}}
        else:
            details = {"buildDefinition": {"resolvedDependencies": [{
                "uri": source, "digest": {"gitCommit": commit or "a" * 40}}]},
                "runDetails": {"builder": {"id": builder}}}
        return json.dumps({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": predicate,
            "subject": [{"name": "artifact.tar", "digest": {
                "sha256": digest or self.digest}}],
            "predicate": details
        }).encode()

    def provenance_result(self, **kw):
        return ae.verify_provenance(self.artifact, self.digest, self.provenance,
                                    SOURCE, BUILDER, expected_source_tag="v1.0.0",
                                    allow_network_trust=True, **kw)

    def sbom(self, scope="build_output", **changes):
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": "https://spdx.org/spdxdocs/example-uuid",
            "name": "example",
            "dataLicense": "CC0-1.0",
            "creationInfo": {"created": "2026-11-09T12:00:00Z",
                             "creators": ["Tool: SyntheticTest-1.0"]},
            "packages": [
                {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0",
                 "checksums": [{"algorithm": "SHA256", "checksumValue": self.digest}]},
                {"SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "2.0.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lib@2.0.0"}]}
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT",
                 "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DESCRIBES"},
                {"spdxElementId": "SPDXRef-app",
                 "relatedSpdxElement": "SPDXRef-lib", "relationshipType": "DEPENDS_ON"}
            ],
        }
        document.update(changes)
        return ae.ingest_spdx(self.write("sbom.json", json.dumps(document)), scope,
                              subject_sha256=self.digest, expected_sha256=self.digest)

    def test_signature_binds_digest_signer_issuer_and_supplied_root(self):
        with patch.object(ae.shutil, "which", return_value="/usr/bin/cosign"), \
                patch.object(ae, "_execute", return_value=(0, b"verified")) as run:
            result = self.signature()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["facts"]["signed_identity_verified"])
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--certificate-identity") + 1], SIGNER)
        self.assertEqual(cmd[cmd.index("--certificate-oidc-issuer") + 1], ISSUER)
        self.assertEqual(cmd[cmd.index("--trusted-root") + 1], str(self.root))
        self.assertNotIn("slsa_level", result["facts"])

    def test_wrong_digest_prevents_tool_execution(self):
        with patch.object(ae, "_execute") as run:
            result = ae.verify_signature(self.artifact, "f" * 64, self.bundle,
                                         SIGNER, ISSUER, trusted_root_path=self.root)
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    def test_wrong_signer_and_issuer_are_rejected_by_verifier(self):
        def verify(cmd, **_):
            return (0 if cmd[cmd.index("--certificate-identity") + 1] == SIGNER and
                    cmd[cmd.index("--certificate-oidc-issuer") + 1] == ISSUER
                    else 1, b"secret=never-return-this")

        with patch.object(ae.shutil, "which", return_value="/usr/bin/cosign"), \
                patch.object(ae, "_execute", side_effect=verify):
            for signer, issuer in (("other@example.org", ISSUER),
                                   (SIGNER, "https://other.example")):
                result = ae.verify_signature(self.artifact, self.digest, self.bundle,
                                             signer, issuer, trusted_root_path=self.root)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("secret", json.dumps(result))

    def test_missing_tool_and_explicit_trust_opt_in(self):
        with patch.object(ae.shutil, "which", return_value=None):
            self.assertEqual(self.signature()["status"], "unknown")
            self.assertEqual(self.provenance_result()["status"], "unknown")
        self.assertEqual(ae.verify_signature(self.artifact, self.digest, self.bundle,
                                             SIGNER, ISSUER)["status"], "unknown")
        self.assertEqual(ae.verify_provenance(self.artifact, self.digest, self.provenance,
                                              SOURCE, BUILDER,
                                              expected_source_tag="v1.0.0")["status"], "unknown")

    def test_provenance_policy_and_subject(self):
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", return_value=(0, self.statement())) as run:
            result = self.provenance_result()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["facts"]["provenance_verified"])
        self.assertNotIn("slsa_level", result["facts"])
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--source-uri") + 1], SOURCE)
        self.assertEqual(cmd[cmd.index("--builder-id") + 1], BUILDER)
        self.assertEqual(cmd[cmd.index("--source-tag") + 1], "v1.0.0")
        self.assertIn("--print-provenance", cmd)

    def test_provenance_rejects_wrong_subject_builder_and_predicate(self):
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"):
            for content in (self.statement(digest="f" * 64),
                            self.statement(builder="https://example.org/other"),
                            self.statement(predicate="https://example.org/other-predicate"),
                            b"not-json", b"x" * (ae.MAX_OUTPUT + 1)):
                with patch.object(ae, "_execute", return_value=(0, content)):
                    self.assertEqual(self.provenance_result()["status"], "error")

    def test_provenance_v02_and_v1_source_commit_when_supplied(self):
        commit = "a" * 40
        for predicate in (ae.PREDICATE, ae.PREDICATE_V02):
            with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                    patch.object(ae, "_execute",
                                 return_value=(0, self.statement(predicate=predicate,
                                                                  commit=commit))):
                result = self.provenance_result(expected_source_commit=commit)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["facts"]["source_commit"], commit)
                self.assertEqual(result["facts"]["predicate_type"], predicate)
                self.assertEqual(self.provenance_result(expected_source_commit="b" * 40)
                                 ["status"], "error")

    def test_provenance_requires_matching_source_even_without_commit(self):
        statement = json.loads(self.statement(predicate=ae.PREDICATE_V02))
        statement["predicate"]["invocation"]["configSource"]["uri"] = (
            "git+https://github.com/wrong/repo@refs/tags/v1.0.0")
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", return_value=(0, json.dumps(statement).encode())):
            self.assertEqual(self.provenance_result()["status"], "error")

    def test_v1_resolved_dependency_commit_rejects_ambiguous_source(self):
        statement = json.loads(self.statement(commit="a" * 40))
        dependencies = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
        dependencies.append({"uri": dependencies[0]["uri"],
                             "digest": {"gitCommit": "b" * 40}})
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", return_value=(0, json.dumps(statement).encode())):
            self.assertEqual(self.provenance_result(expected_source_commit="a" * 40)
                             ["status"], "error")

    def test_provenance_rejects_wrong_source_and_ref_via_cli(self):
        def verify(cmd, **_):
            valid = (cmd[cmd.index("--source-uri") + 1] == SOURCE and
                     cmd[cmd.index("--source-tag") + 1] == "v1.0.0")
            return (0 if valid else 1, self.statement() if valid else b"token=hidden")

        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", side_effect=verify):
            for source, ref in (("github.com/wrong/repo", "v1.0.0"),
                                (SOURCE, "v2.0.0")):
                result = ae.verify_provenance(self.artifact, self.digest,
                                              self.provenance, source, BUILDER,
                                              expected_source_tag=ref,
                                              allow_network_trust=True)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("token=hidden", json.dumps(result))

    def test_invalid_inputs_and_oversized_bundle(self):
        for value in ("--danger", "https://example.org/?token=secret"):
            result = ae.verify_signature(self.artifact, self.digest, self.bundle,
                                         value, ISSUER, trusted_root_path=self.root)
            self.assertEqual(result["status"], "error")
            self.assertNotIn("secret", json.dumps(result))
        self.write("bundle.json", b"x" * (ae.MAX_EVIDENCE + 1))
        self.assertEqual(self.signature()["status"], "error")
        self.assertEqual(ae.verify_signature("https://example.org/asset", self.digest,
                                             self.bundle, SIGNER, ISSUER)["status"], "error")
        self.assertEqual(ae.verify_signature("../artifact.tar", self.digest,
                                             self.bundle, SIGNER, ISSUER)["status"], "error")
        link = self.path / "alias"
        link.symlink_to(self.artifact)
        self.assertEqual(ae.verify_signature(link, self.digest, self.bundle,
                                             SIGNER, ISSUER)["status"], "error")

    def test_spdx_scope_binding_and_quality(self):
        result = self.sbom()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["facts"]["independent_digest_match"])
        self.assertEqual(result["facts"]["quality"]["missing_purl_count"], 1)
        self.assertEqual(result["facts"]["quality"]["dependency_relationship_count"], 1)
        self.assertEqual(result["facts"]["packages"][1]["purls"], ["pkg:npm/lib@2.0.0"])
        self.assertEqual(self.sbom("source_checkout")["facts"]["scope"], "source_checkout")
        self.assertIn("source checkout", " ".join(self.sbom("source_checkout")["gaps"]))

    def test_spdx_release_subject_mismatch_or_missing_bind_is_not_coverage(self):
        different = self.sbom("build_output", packages=[
            {"SPDXID": "SPDXRef-app", "name": "app",
             "checksums": [{"algorithm": "SHA256", "checksumValue": "f" * 64}]},
            {"SPDXID": "SPDXRef-lib", "name": "lib"}])
        self.assertFalse(different["facts"]["subject_bound"])
        self.assertEqual(different["status"], "partial")
        self.assertEqual(ae.ingest_spdx(self.path / "sbom.json", "oci_image",
                                        subject_sha256="f" * 64,
                                        expected_sha256=self.digest)["status"], "error")
        self.assertFalse(self.sbom("source_checkout")["facts"]["scope"] == "build_output")

    def test_spdx_rejects_duplicate_dangling_and_bad_schema(self):
        for change in (
                {"packages": [{"SPDXID": "SPDXRef-app", "name": "one"},
                              {"SPDXID": "SPDXRef-app", "name": "two"}]},
                {"relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                                    "relatedSpdxElement": "SPDXRef-missing",
                                    "relationshipType": "DESCRIBES"}]},
                {"spdxVersion": "SPDX-3.0.1"},
                {"spdxVersion": "SPDX-2.2"},
                {"creationInfo": {}},
                {"documentDescribes": ["SPDXRef-not-in-graph"]}):
            self.assertEqual(self.sbom(**change)["status"], "error")
        self.write("sbom.json", "{broken")
        self.assertEqual(ae.ingest_spdx(self.path / "sbom.json", "build_output")["status"],
                         "error")
        self.write("sbom.json", '{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-3.0"}')
        self.assertIn("Duplicate", ae.ingest_spdx(self.path / "sbom.json",
                                                   "build_output")["gaps"][0])

    def test_spdx_missing_version_and_purl_are_quality_gaps(self):
        result = self.sbom(packages=[{"SPDXID": "SPDXRef-app", "name": "app",
                                      "checksums": [{"algorithm": "SHA256",
                                                     "checksumValue": self.digest}]},
                                     {"SPDXID": "SPDXRef-lib", "name": "lib"}])
        self.assertEqual(result["facts"]["quality"]["missing_version_count"], 2)
        self.assertEqual(result["facts"]["quality"]["missing_purl_count"], 2)
        self.assertEqual(result["status"], "partial")

    def test_spdx_disconnected_dependency_is_not_full_inventory(self):
        result = self.sbom(relationships=[
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app",
             "relationshipType": "DESCRIBES"}])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["quality"]["disconnected_package_count"], 1)

    def test_spdx_rejects_malformed_graph_types_and_sensitive_identifiers(self):
        for change in (
                {"relationships": [{"spdxElementId": [], "relatedSpdxElement": "SPDXRef-app",
                                    "relationshipType": "DEPENDS_ON"}]},
                {"documentDescribes": [{"id": "SPDXRef-app"}]},
                {"documentNamespace": "https://spdx.org/docs/example?token=hidden"},
                {"packages": [{"SPDXID": "SPDXRef-app", "name": "password=hidden"},
                              {"SPDXID": "SPDXRef-lib", "name": "lib"}]}):
            result = self.sbom(**change)
            self.assertEqual(result["status"], "error")
            self.assertNotIn("hidden", json.dumps(result))

    def test_subprocess_output_and_time_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "exceeds the size limit"):
            ae._execute([sys.executable, "-c",
                         f"import sys; sys.stdout.write('x' * {ae.MAX_OUTPUT + 1})"])
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            ae._execute([sys.executable, "-c", "import time; time.sleep(2)"],
                        timeout=0.1)

    def test_public_tuf_dns_failure_is_unknown_without_leaking_diagnostics(self):
        diagnostic = ('tuf refresh failed: Get '
                      '"https://tuf-repo-cdn.sigstore.dev/10.root.json": '
                      'dial tcp: lookup tuf-repo-cdn.sigstore.dev: server misbehaving; '
                      'token=not-for-results')
        with self.assertRaises(ae.TrustLookupUnavailable):
            ae._execute([sys.executable, "-c",
                         "import sys; sys.stderr.write(" + repr(diagnostic) +
                         "); sys.exit(1)"], public_trust=True)
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", side_effect=ae.TrustLookupUnavailable(
                    "Public Sigstore TUF trust lookup is unavailable.")):
            result = self.provenance_result()
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("token", json.dumps(result))
        with patch.object(ae.shutil, "which", return_value="/usr/bin/cosign"), \
                patch.object(ae, "_execute", side_effect=ae.TrustLookupUnavailable(
                    "Public Sigstore TUF trust lookup is unavailable.")):
            result = ae.verify_signature(self.artifact, self.digest, self.bundle,
                                         SIGNER, ISSUER, allow_network_trust=True)
        self.assertEqual(result["status"], "unknown")

    def test_tool_error_and_timeout_never_leak_secrets(self):
        with patch.object(ae.shutil, "which", return_value="/usr/bin/cosign"), \
                patch.object(ae, "_execute", side_effect=TimeoutError("Verification tool timed out.")):
            self.assertNotIn("token", json.dumps(self.signature()))
        with patch.object(ae.shutil, "which", return_value="/usr/bin/slsa-verifier"), \
                patch.object(ae, "_execute", return_value=(1, b"secret-token")):
            self.assertNotIn("secret-token", json.dumps(self.provenance_result()))


if __name__ == "__main__":
    unittest.main()
