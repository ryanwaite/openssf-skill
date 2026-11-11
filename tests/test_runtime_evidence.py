"""End-to-end boundaries between optional evidence and the scored ensemble."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("runtime_evaluator", ROOT / "scripts/ensemble-eval.py")
ee = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ee)
AT = "2026-11-11T00:00:00Z"


class TestRuntimeEvidence(unittest.TestCase):
    def test_baseline_changes_conformance_not_numeric_risk_and_survives_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = str(Path(temporary) / "target")
            Path(target).mkdir()
            path = Path(temporary) / "baseline.json"
            path.write_text(json.dumps({
                "schema_version": 1, "catalog_version": "2026.08.28",
                "target": target, "revision": "reviewed-copy", "scope": "Single repository",
                "level": 1, "observations": [],
            }))
            with patch.object(ee, "_have", return_value=False):
                plain = ee.evaluate(target, "produce", evaluated_at=AT)
                report = ee.evaluate(target, "produce", evaluated_at=AT, baseline_evidence=path)
            self.assertEqual(plain["verdict"], report["verdict"])
            self.assertNotIn("baseline", [s["name"] for s in report["signals"]])
            self.assertEqual(report["baseline_conformance"]["counts"]["unknown"], 24)
            self.assertEqual(report["policy_version"], "2")
            self.assertIn("OSPS Baseline conformance (not weighted)", ee.to_markdown(report))
            snapshot = Path(temporary) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            with patch.object(ee, "_run") as run:
                self.assertEqual(ee.replay(snapshot), report)
                run.assert_not_called()

    def test_signature_is_optional_and_network_lookup_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "release.bin"
            target.write_bytes(b"synthetic release")
            bundle = Path(temporary) / "bundle.json"
            bundle.write_text(json.dumps({"verificationMaterial": {}, "messageSignature": {}}))
            config = Path(temporary) / "artifact.json"
            config.write_text(json.dumps({
                "schema_version": 1, "target": str(target),
                "artifact": {"path": "release.bin",
                             "sha256": hashlib.sha256(target.read_bytes()).hexdigest()},
                "signature": {"bundle": "bundle.json", "expected_signer": "maintainer@example.org",
                              "expected_issuer": "https://accounts.google.com"},
            }))
            with patch.object(ee, "_have", return_value=False), \
                    patch("artifact_evidence._execute") as execute:
                report = ee.evaluate(str(target), "produce", evaluated_at=AT, artifact_input=config)
                execute.assert_not_called()
            self.assertEqual(report["artifact_evidence"]["signature"]["status"], "unknown")
            self.assertTrue(report["actions"])
            self.assertEqual(report["verdict"]["outcome"], "INCOMPLETE")
            self.assertIn("public trust lookup", ee.to_markdown(report))

    def test_artifact_failure_cannot_be_overwritten_by_manual_provenance(self):
        with tempfile.TemporaryDirectory() as target:
            manual = Path(target) / "manual.json"
            manual.write_text(json.dumps({
                "schema_version": 1, "target": target, "mode": "produce",
                "observations": [{
                    "name": "provenance", "facts": {"slsa_level": 3},
                    "evidence_type": "manual_observation", "source": "Human review",
                    "captured_at": AT, "tool": {"name": "manual", "version": "1"},
                }],
            }))
            failure = {"signature": {"status": "error", "facts": {}, "gaps": ["Digest mismatch"]}}
            with patch.object(ee, "_have", return_value=False), \
                    patch.object(ee, "artifact_evidence", return_value=failure):
                report = ee.evaluate(target, "produce", manual, AT, artifact_input=Path("config.json"))
            provenance = next(s for s in report["signals"] if s["name"] == "provenance")
            self.assertEqual(provenance["status"], "error")
            self.assertIsNone(provenance["subscore"])
            self.assertIn("signature evidence mismatch", report["actions"][0])

    def test_existing_source_spdx_can_be_inspected_without_scanners(self):
        with tempfile.TemporaryDirectory() as target:
            inventory = Path(target) / "inventory.spdx.json"
            inventory.write_text(json.dumps({
                "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "source inventory", "documentNamespace": "https://example.org/sbom/1",
                "dataLicense": "CC0-1.0",
                "creationInfo": {"created": AT, "creators": ["Tool: test-fixture"]},
                "documentDescribes": ["SPDXRef-demo"],
                "packages": [{
                    "SPDXID": "SPDXRef-demo", "name": "demo", "versionInfo": "1.0.0",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/demo@1.0.0"}],
                }],
            }))
            config = Path(target) / "artifact.json"
            config.write_text(json.dumps({
                "schema_version": 1, "target": target,
                "sbom": {"path": "inventory.spdx.json", "scope": "source_checkout"},
            }))
            with patch.object(ee, "_have", return_value=False), \
                    patch("artifact_evidence._execute") as execute:
                report = ee.evaluate(target, "consume", evaluated_at=AT, artifact_input=config)
                execute.assert_not_called()
            sbom = report["artifact_evidence"]["sbom"]
            self.assertEqual(sbom["facts"]["quality"]["package_count"], 1)
            self.assertEqual(sbom["facts"]["quality"]["completeness"], "unknown")
            self.assertEqual(sbom["facts"]["scope"], "source_checkout")
            self.assertNotEqual(report["verdict"]["outcome"], "Adopt")
            self.assertIn("source checkout inventory", ee.to_markdown(report))
            snapshot = Path(target) / "snapshot.json"
            command = [sys.executable, "-S", str(ROOT / "scripts/ensemble-eval.py"),
                       "--target", target, "--mode", "consume", "--at", AT,
                       "--artifact-evidence", str(config), "--snapshot-out", str(snapshot)]
            run = subprocess.run(command, cwd=target, env={**os.environ, "PATH": ""},
                                 check=True, capture_output=True, text=True)
            saved = json.loads(run.stdout)
            self.assertEqual(saved["artifact_evidence"], report["artifact_evidence"])
            replay = subprocess.run(
                [sys.executable, "-S", str(ROOT / "scripts/ensemble-eval.py"),
                 "--replay", str(snapshot)],
                env={**os.environ, "PATH": ""}, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(replay.stdout), saved)

    def test_scoped_osv_fixes_and_untrusted_vex_reach_report_without_suppression(self):
        document = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.org/vex/1", "author": "supplier", "version": 1,
            "timestamp": AT, "statements": [{
                "vulnerability": {"name": "MAL-2026-1"}, "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "products": [{"@id": "pkg:npm/demo@1.0.0"}],
            }],
        }
        advisory = {
            "id": "MAL-2026-1", "database_specific": {"severity": "CRITICAL"},
            "affected": [
                {"package": {"ecosystem": "npm", "name": "other"},
                 "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.0.0"}]}]},
                {"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.0.0"]},
            ],
        }
        scan = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{
            "package": {"ecosystem": "npm", "name": "demo", "version": "1.0.0",
                        "purl": "pkg:npm/demo@1.0.0"},
            "vulnerabilities": [advisory],
        }]}]}
        with tempfile.TemporaryDirectory() as target:
            config = Path(target) / "vex.json"
            config.write_text(json.dumps({
                "schema_version": 1, "target": target, "documents": [document],
                "trusted_authors": ["supplier"], "max_age_days": 30,
            }))

            def scanner(command, timeout=180):
                return subprocess.CompletedProcess(command, 1, json.dumps(scan), "")

            with patch.object(ee, "_have", side_effect=lambda name: name == "osv-scanner"), \
                    patch.object(ee, "_run", side_effect=scanner):
                report = ee.evaluate(target, "consume", evaluated_at=AT, vex_input=config)
            known = next(s for s in report["signals"] if s["name"] == "known_vulns")
            self.assertEqual(known["subscore"], 60)
            self.assertEqual(known["raw"]["findings"][0]["fixed_versions"], [])
            contexts = known["raw"]["triage"][0]["findings"][0]["vex"]
            self.assertEqual(contexts[0]["assessment"], "context_only")
            self.assertFalse(contexts[0]["authenticated"])
            self.assertFalse(report["verdict"]["escalations"])
            self.assertIn("not automatic exclusions", ee.to_markdown(report))

    def test_import_cannot_grant_vex_authentication_and_policy_v1_is_explicit(self):
        with tempfile.TemporaryDirectory() as target:
            path = Path(target) / "vex.json"
            path.write_text(json.dumps({
                "schema_version": 1, "target": target, "documents": [{}],
                "authenticated_authors": ["supplier"],
            }))
            with self.assertRaisesRegex(ValueError, "fields"):
                ee.evaluate(target, "consume", evaluated_at=AT, vex_input=path)
        with self.assertRaisesRegex(ValueError, "baseline-evidence"):
            ee._manual_signal({"name": "baseline"})


if __name__ == "__main__":
    unittest.main()
