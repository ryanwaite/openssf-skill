"""Focused policy and fail-closed tests for local registry attestation verification."""

import base64
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from uuid import uuid4


_SPEC = importlib.util.spec_from_file_location(
    "registry_verification", Path(__file__).resolve().parent.parent /
    "scripts" / "registry_verification.py")
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
verification = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verification)

IDENTITY = {"kind": "package", "ecosystem": "npm", "name": "semver",
            "version": "7.7.3", "purl": "pkg:npm/semver@7.7.3"}
SOURCE = "https://github.com/npm/node-semver"
ISSUER = "https://token.actions.githubusercontent.com"
SIGNER = "https://github.com/npm/node-semver/.github/workflows/release.yml@refs/heads/main"


class RegistryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path.cwd() / f".registry-verification-test-data-{uuid4().hex}"
        self.directory.mkdir()
        self.artifact = self.directory / "semver-7.7.3.tgz"
        self.artifact.write_bytes(b"synthetic distribution; not a public release")
        self.bundle = self.directory / "attestation.sigstore.json"
        self.root = self.directory / "trusted_root.json"
        self.root.write_text(json.dumps({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{}], "tlogs": [{}],
        }))
        self.sha = hashlib.sha512(self.artifact.read_bytes()).hexdigest()
        self.config = {
            "filename": self.artifact.name, "artifact_path": str(self.artifact),
            "bundle_path": str(self.bundle), "trusted_root_path": str(self.root),
            "expected_digest": f"sha512:{self.sha}",
            "certificate_identity": SIGNER, "certificate_oidc_issuer": ISSUER,
            "source_repository": SOURCE, "source_ref": "refs/heads/main",
            "predicate_type": verification.PREDICATE,
        }
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": verification.PREDICATE,
            "subject": [{"name": IDENTITY["purl"], "digest": {"sha512": self.sha}}],
            "predicate": {"buildDefinition": {"externalParameters": {"workflow": {
                "repository": SOURCE, "ref": "refs/heads/main",
                "path": ".github/workflows/release.yml"}}}},
        }
        self.write_bundle()

    def tearDown(self):
        shutil.rmtree(self.directory)

    def write_bundle(self, *, signature="not-a-valid-signature"):
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(self.statement).encode()).decode(),
            "signatures": [{"sig": signature}],
        }
        self.bundle.write_text(json.dumps({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": envelope,
            "verificationMaterial": {"certificate": {"rawBytes": "not-a-valid-certificate"}},
        }))

    def verify(self, *, returncode=0, network=False):
        with patch.object(verification.shutil, "which", return_value="/usr/bin/cosign"), \
             patch.object(verification.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], returncode)) as run:
            result = verification.verify_registry_distribution(
                IDENTITY, self.config, allow_network_trust=network)
        return result, run

    def test_verifier_success_requires_full_signed_policy(self):
        result, run = self.verify()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["facts"]["signature"], "verified")
        self.assertEqual(result["facts"]["source_assertion"], "authenticated")
        self.assertEqual(result["facts"]["expected_policy"]["expected_digest"],
                         self.config["expected_digest"])
        self.assertEqual(result["facts"]["expected_policy"]["source_ref"], "refs/heads/main")
        args = run.call_args.args[0]
        self.assertEqual(args[1], "verify-blob-attestation")
        self.assertIn("--certificate-identity", args)
        self.assertIn("--certificate-oidc-issuer", args)
        self.assertIn("--trusted-root", args)
        self.assertIn("--digestAlg", args)
        self.assertNotIn("--insecure-ignore-tlog", args)
        self.assertNotIn("--check-claims=false", args)
        self.assertEqual(Path(args[-1]).name, self.artifact.name)
        self.assertNotEqual(args[-1], str(self.artifact.resolve()))
        self.assertFalse(Path(args[-1]).parent.exists())
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(result["facts"]["snapshot_sha256"]["artifact"],
                         hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.assertEqual(result["facts"]["snapshot_sha256"]["bundle"],
                         hashlib.sha256(self.bundle.read_bytes()).hexdigest())
        self.assertEqual(result["facts"]["snapshot_sha256"]["trusted_root"],
                         hashlib.sha256(self.root.read_bytes()).hexdigest())
        self.assertEqual(result["facts"]["expected_certificate_identity"], SIGNER)
        self.assertEqual(result["facts"]["expected_certificate_oidc_issuer"], ISSUER)
        self.assertEqual(result["facts"]["verifier"]["version"], "unrecorded")
        datetime.fromisoformat(result["facts"]["verifier"]["captured_at"])

    def test_private_snapshots_do_not_require_writable_caller_directory(self):
        with patch.object(verification.Path, "cwd", side_effect=OSError("read-only")):
            with verification._private_snapshots() as path:
                self.assertTrue(path.is_dir())
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertFalse(path.exists())
        with patch.object(verification.os, "name", "nt"), \
                patch.object(verification, "_private_snapshots") as snapshot:
            result = verification.verify_registry_distribution(IDENTITY, self.config)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("POSIX", result["gaps"][0])
        snapshot.assert_not_called()

    def test_rejected_signature_certificate_or_identity_is_error(self):
        result, _ = self.verify(returncode=1)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["facts"]["signature"], "not_verified")
        self.assertNotIn(SIGNER, str(result["gaps"]))

    def test_artifact_digest_mismatch_fails_before_verifier(self):
        self.artifact.write_bytes(b"changed")
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["facts"]["local_digest_match"])
        run.assert_not_called()

    def test_unrelated_distribution_version_and_signed_subject_fail(self):
        self.config["filename"] = "semver-7.7.2.tgz"
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()
        self.config["filename"] = self.artifact.name
        self.statement["subject"][0]["name"] = "pkg:npm/semver@7.7.2"
        self.write_bundle()
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    def test_signed_digest_and_multiple_subjects_fail(self):
        self.statement["subject"][0]["digest"]["sha512"] = "0" * 128
        self.write_bundle()
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()
        self.statement["subject"][0]["digest"]["sha512"] = self.sha
        self.statement["subject"].append({"name": "pkg:npm/other@1.0.0",
                                          "digest": {"sha512": self.sha}})
        self.write_bundle()
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    def test_source_policy_mismatch_rejects_unsigned_claim(self):
        self.config["source_repository"] = "https://github.com/other/project"
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    def test_unrecognized_predicate_and_layout_unknown(self):
        self.statement["predicateType"] = "https://example.org/unrecognized"
        self.write_bundle()
        result, run = self.verify()
        self.assertEqual(result["status"], "unknown")
        run.assert_not_called()
        self.statement["predicateType"] = verification.PREDICATE
        self.write_bundle()
        payload = json.loads(self.bundle.read_text())
        payload["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
        self.bundle.write_text(json.dumps(payload))
        result, run = self.verify()
        self.assertEqual(result["status"], "unknown")
        run.assert_not_called()

    def test_missing_verifier_and_root_are_unknown(self):
        with patch.object(verification.shutil, "which", return_value=None):
            result = verification.verify_registry_distribution(IDENTITY, self.config)
        self.assertEqual(result["status"], "unknown")
        self.config.pop("trusted_root_path")
        with patch.object(verification.shutil, "which") as which:
            result = verification.verify_registry_distribution(IDENTITY, self.config)
        self.assertEqual(result["status"], "unknown")
        which.assert_not_called()
        self.config["trusted_root_path"] = str(self.root)
        self.root.write_text("{}")
        result, run = self.verify()
        self.assertEqual(result["status"], "unknown")
        run.assert_not_called()

    def test_explicit_public_trust_opt_in_only(self):
        self.config.pop("trusted_root_path")
        result, run = self.verify(network=True)
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("--trusted-root", run.call_args.args[0])
        self.assertEqual(result["facts"]["trust"], "explicit_public_trust")

    def test_pypi_envelope_is_not_misrepresented_as_sigstore_bundle(self):
        result = verification.verify_registry_distribution(
            {"kind": "package", "ecosystem": "PyPI", "name": "sampleproject",
             "version": "4.0.0"}, self.config)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["facts"]["verification"], "not_verified")

    def test_missing_independent_signer_never_promotes_verification(self):
        self.config["certificate_identity"] = ""
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["facts"]["verification"], "not_verified")
        run.assert_not_called()

    def test_no_verifier_output_or_secret_in_diagnostics(self):
        with patch.object(verification.shutil, "which", return_value="/usr/bin/cosign"), \
             patch.object(verification.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("secret-token", 18)):
            result = verification.verify_registry_distribution(IDENTITY, self.config)
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("secret-token", str(result))

    def test_independently_expected_builder_id_must_match(self):
        self.config["builder_id"] = "https://github.com/actions/runner/github-hosted"
        self.statement["predicate"]["runDetails"] = {
            "builder": {"id": self.config["builder_id"]}}
        self.write_bundle()
        result, _ = self.verify()
        self.assertEqual(result["facts"]["builder_assertion"], "authenticated")
        self.config["builder_id"] = "https://example.org/different-builder"
        result, run = self.verify()
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    def test_original_bundle_or_root_swap_cannot_promote_result(self):
        for original in (self.bundle, self.root):
            with self.subTest(path=original.name):
                original_content = original.read_bytes()
                captured_paths = []

                def swap(command, **_):
                    captured = Path(command[command.index(
                        "--bundle" if original == self.bundle else "--trusted-root") + 1])
                    captured_paths.append(captured)
                    self.assertEqual(captured.read_bytes(), original_content)
                    replacement = self.directory / f"replacement-{original.name}"
                    replacement.write_bytes(
                        b"replaced while Cosign verified the snapshot"
                        if original == self.bundle else original_content)
                    replacement.replace(original)
                    return subprocess.CompletedProcess(command, 0)

                with patch.object(verification.shutil, "which", return_value="/usr/bin/cosign"), \
                     patch.object(verification.subprocess, "run", side_effect=swap):
                    result = verification.verify_registry_distribution(IDENTITY, self.config)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["facts"]["verification"], "not_verified")
                self.assertFalse(captured_paths[0].parent.exists())
                original.write_bytes(original_content)

    def test_original_artifact_mutation_cannot_promote_result(self):
        original_content = self.artifact.read_bytes()
        captured_paths = []

        def mutate(command, **_):
            captured = Path(command[-1])
            captured_paths.append(captured)
            self.assertEqual(captured.read_bytes(), original_content)
            self.artifact.write_bytes(b"changed while Cosign verified the snapshot")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(verification.shutil, "which", return_value="/usr/bin/cosign"), \
             patch.object(verification.subprocess, "run", side_effect=mutate):
            result = verification.verify_registry_distribution(IDENTITY, self.config)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["facts"]["verification"], "not_verified")
        self.assertFalse(captured_paths[0].parent.exists())

    def test_reject_symlink_and_special_input_without_process(self):
        linked = self.directory / "linked.sigstore.json"
        linked.symlink_to(self.bundle)
        self.config["bundle_path"] = str(linked)
        result, run = self.verify()
        self.assertNotEqual(result["status"], "ok")
        run.assert_not_called()
        self.config["bundle_path"] = str(self.bundle)
        self.config["artifact_path"] = str(self.directory)
        result, run = self.verify()
        self.assertNotEqual(result["status"], "ok")
        run.assert_not_called()

    def test_copied_bytes_not_only_stat_size_are_bounded(self):
        original_limit = verification.MAX_ARTIFACT
        real_read = verification.os.read
        grew = False

        def grow_before_read(fd, count):
            nonlocal grew
            if not grew:
                grew = True
                with self.artifact.open("ab") as stream:
                    stream.write(b"more than the remaining byte")
            return real_read(fd, count)

        try:
            verification.MAX_ARTIFACT = self.artifact.stat().st_size + 1
            with patch.object(verification.os, "read", side_effect=grow_before_read):
                result, run = self.verify()
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(grew)
            run.assert_not_called()
        finally:
            verification.MAX_ARTIFACT = original_limit


if __name__ == "__main__":
    unittest.main()
