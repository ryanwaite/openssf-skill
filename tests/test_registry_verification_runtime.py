"""Registry discovery and explicit verification must remain separate decisions."""

import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("registry_verify_runner", ROOT / "scripts/ensemble-eval.py")
ee = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ee)


class RegistryVerificationRuntimeTests(unittest.TestCase):
    def policy(self, directory, target="example@1.2.3", filename="example-1.2.3.tgz"):
        artifact = directory / filename
        artifact.write_bytes(b"synthetic distribution")
        (directory / "bundle.json").write_text("{}")
        config = {
            "schema_version": 1, "target": target, "distributions": [{
                "filename": filename, "artifact_path": filename,
                "bundle_path": "bundle.json",
                "expected_digest": "sha512:" + hashlib.sha512(artifact.read_bytes()).hexdigest(),
                "certificate_identity": "https://github.com/example/project/.github/workflows/release.yml@refs/heads/main",
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                "source_repository": "https://github.com/example/project",
                "predicate_type": "https://slsa.dev/provenance/v1",
            }],
        }
        path = directory / "policy.json"
        path.write_text(json.dumps(config))
        return path, config

    def test_existing_discovery_cannot_authenticate_itself(self):
        discovery = {"status": "ok", "facts": {
            "verification": "not_verified", "distributions": [],
        }, "gaps": ["Metadata is not signature verification."]}
        with patch.object(ee, "_have", return_value=False), \
                patch.object(ee, "discover_registry_evidence", return_value=discovery):
            report = ee.evaluate("example@1.2.3", "consume",
                                 ecosystem="npm", fetch_registry=True)
        self.assertEqual(report["registry_evidence"]["facts"]["verification"], "not_verified")
        self.assertNotIn("registry_verification", report)
        self.assertNotEqual(report["verdict"]["outcome"], "Adopt")
        self.assertIn("discovery, not verification", ee.to_markdown(report))
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / "snapshot.json"
            snapshot.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(ee, "discover_registry_evidence") as fetch:
                replayed = ee.replay(snapshot)
            fetch.assert_not_called()
            self.assertEqual(replayed, report)

    def test_explicit_verification_does_not_change_discovery_or_score_and_replays_offline(self):
        verified = {"status": "ok", "facts": {
            "verification": "verified", "signature": "verified", "signer": "verified",
            "source_assertion": "authenticated",
        }, "gaps": []}
        discovery = {"status": "ok", "facts": {
            "verification": "not_verified", "distributions": [],
        }, "gaps": ["Metadata is not signature verification."]}
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.policy(Path(temporary))
            with patch.object(ee, "_have", return_value=False), \
                    patch.object(ee, "discover_registry_evidence", return_value=discovery) as fetch, \
                    patch("registry_verification.verify_registry_distribution",
                          return_value=verified) as verify:
                plain = ee.evaluate("example@1.2.3", "consume", ecosystem="npm")
                verify.assert_not_called()
                report = ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                                     registry_verification=path)
                fetch.assert_not_called()
                self.assertFalse(verify.call_args.kwargs["allow_network_trust"])
                self.assertTrue(Path(verify.call_args.args[1]["artifact_path"]).is_absolute())
                combined = ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                                       registry_verification=path, fetch_registry=True)
            self.assertEqual(report["verdict"], plain["verdict"])
            self.assertEqual(report["registry_verification"]["facts"]["verification"], "verified")
            self.assertEqual(combined["registry_evidence"]["facts"]["verification"], "not_verified")
            self.assertIn("selected local files", ee.to_markdown(report))
            snapshot = Path(temporary) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            with patch("registry_verification.verify_registry_distribution") as verify, \
                    patch.object(ee, "_run") as run:
                self.assertEqual(ee.replay(snapshot), report)
                verify.assert_not_called()
                run.assert_not_called()

    def test_missing_trust_does_not_trigger_network_or_block_other_advice(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.policy(Path(temporary))
            with patch.object(ee, "_have", return_value=False), \
                    patch("registry_verification.subprocess.run") as execute:
                report = ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                                     registry_verification=path)
            execute.assert_not_called()
            self.assertEqual(report["registry_verification"]["status"], "unknown")
            self.assertTrue(report["actions"])
            self.assertEqual(report["verdict"]["outcome"], "INCOMPLETE")
            with self.assertRaisesRegex(ValueError, "cannot be backdated"):
                ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                            registry_verification=path, evaluated_at="2026-01-01T00:00:00Z")

    def test_policy_paths_binding_duplicates_and_unknown_fields_checked_before_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path, config = self.policy(directory)
            changes = [
                {**config, "target": "other@1.2.3"},
                {**config, "verified": True},
                {**config, "distributions": config["distributions"] * 2},
                {**config, "distributions": []},
                {**config, "distributions": [{**config["distributions"][0],
                                            "bundle_path": "../unapproved.json"}]},
                {**config, "distributions": [{**config["distributions"][0],
                                            "trusted_signer_from_registry": True}]},
            ]
            for value in changes:
                path.write_text(json.dumps(value))
                with self.subTest(value=value), patch.object(ee, "_have", return_value=False), \
                        patch("registry_verification.verify_registry_distribution") as verify, \
                        self.assertRaises(ValueError):
                    ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                                registry_verification=path)
                verify.assert_not_called()
            nested = directory / "inputs"
            nested.mkdir()
            (nested / "bundle.json").write_text("{}")
            (directory / "linked-inputs").symlink_to(nested, target_is_directory=True)
            config["distributions"][0]["bundle_path"] = "linked-inputs/bundle.json"
            path.write_text(json.dumps(config))
            with patch.object(ee, "_have", return_value=False), \
                    patch("registry_verification.verify_registry_distribution") as verify, \
                    self.assertRaisesRegex(ValueError, "symlink"):
                ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                            registry_verification=path)
            verify.assert_not_called()

    def test_error_prompts_action_and_pypi_is_not_falsely_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.policy(Path(temporary))
            failure = {"status": "error", "facts": {"verification": "not_verified"},
                       "gaps": ["Signature rejected."]}
            with patch.object(ee, "_have", return_value=False), \
                    patch("registry_verification.verify_registry_distribution", return_value=failure):
                result = ee.evaluate("example@1.2.3", "consume", ecosystem="npm",
                                     registry_verification=path)
            self.assertEqual(result["registry_verification"]["status"], "error")
            self.assertIn("mismatch", result["actions"][0])
            path, _ = self.policy(Path(temporary), target="example@1.2.3",
                                  filename="example-1.2.3-py3-none-any.whl")
            with patch.object(ee, "_have", return_value=False):
                unsupported = ee.evaluate("example@1.2.3", "consume", ecosystem="PyPI",
                                          registry_verification=path)
            self.assertEqual(unsupported["registry_verification"]["status"], "unknown")
            self.assertEqual(unsupported["registry_verification"]["facts"]["verification"], "not_verified")


if __name__ == "__main__":
    unittest.main()
