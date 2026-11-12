"""Optional supply-chain inputs stay contextual through CLI/report/replay."""

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
SPEC = importlib.util.spec_from_file_location("supply_metadata_runner", ROOT / "scripts/ensemble-eval.py")
ee = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ee)
AT = "2026-11-12T16:00:00Z"


def inventory():
    return {"status": "partial", "facts": {
        "scope": "build_output", "described_ids": ["SPDXRef-app"],
        "packages": [
            {"id": "SPDXRef-app", "name": "app", "version": "1", "purls": ["pkg:npm/app@1"]},
            {"id": "SPDXRef-dep", "name": "dep", "version": "2", "purls": ["pkg:npm/dep@2"]},
        ],
        "relationships": [{"from": "SPDXRef-app", "to": "SPDXRef-dep", "type": "DEPENDS_ON"}],
        "quality": {"schema_validated": False, "completeness": "unknown"},
    }, "gaps": ["Synthetic fixture; inventory completeness is unknown."]}


class SupplyMetadataRuntimeTests(unittest.TestCase):
    def test_explicit_generated_artifact_and_graph_do_not_double_score(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "release.bin"
            target.write_bytes(b"synthetic release")
            config = Path(directory) / "artifact.json"
            config.write_text(json.dumps({
                "schema_version": 1, "target": str(target),
                "artifact": {"path": "release.bin",
                             "sha256": hashlib.sha256(target.read_bytes()).hexdigest()},
                "sbom": {"generate": True, "scope": "build_output"},
            }))
            known = ee.signal("known_vulns", "ok", 80, "high", "Existing advisory",
                              raw={"findings": [{
                                  "id": "GHSA-synthetic", "aliases": ["GHSA-synthetic"],
                                  "ecosystem": "npm", "package": "dep", "version": "2",
                                  "severity": "HIGH", "fixed_versions": [],
                              }], "triage": []}, source="OSV-Scanner")
            with patch.object(ee, "_have", return_value=False), \
                    patch.object(ee, "probe_known_vulns", return_value=known), \
                    patch("sbom_analysis.generate_sbom", return_value=inventory()) as generate:
                plain = ee.evaluate(str(target), "consume", evaluated_at=AT)
                generate.assert_not_called()
                report = ee.evaluate(str(target), "consume", evaluated_at=AT, artifact_input=config)
            self.assertEqual(report["verdict"], plain["verdict"])
            self.assertEqual(generate.call_args.args[1], "build_output")
            self.assertEqual(report["supply_chain_analysis"]["facts"]["matched"][0]["relation"],
                             "direct_dependency")
            self.assertIsNone(report["supply_chain_analysis"]["facts"]["score_adjustment"])
            self.assertIn("not a second risk score", ee.to_markdown(report))
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            with patch("sbom_analysis.generate_sbom") as generate, patch.object(ee, "_run") as run:
                self.assertEqual(ee.replay(snapshot), report)
                generate.assert_not_called()
                run.assert_not_called()

    def test_source_generation_is_explicit_missing_tool_does_not_block_advice(self):
        with tempfile.TemporaryDirectory() as target:
            config = Path(target) / "evidence.json"
            config.write_text(json.dumps({"schema_version": 1, "target": target,
                                          "sbom": {"generate": True, "scope": "source_checkout"}}))
            with patch.object(ee, "_have", return_value=False), \
                    patch("sbom_analysis.shutil.which", return_value=None):
                result = ee.evaluate(target, "produce", evaluated_at=AT, artifact_input=config)
            self.assertEqual(result["artifact_evidence"]["sbom"]["status"], "unknown")
            self.assertEqual(result["verdict"]["outcome"], "INCOMPLETE")
            self.assertTrue(result["actions"])
            data = json.loads(config.read_text())
            data["sbom"]["path"] = "unused.spdx.json"
            config.write_text(json.dumps(data))
            with patch.object(ee, "_have", return_value=False), \
                    self.assertRaisesRegex(ValueError, "exactly one"):
                ee.evaluate(target, "produce", evaluated_at=AT, artifact_input=config)

    def test_insights_explicit_local_discovery_without_tools_is_not_a_score(self):
        with tempfile.TemporaryDirectory() as target:
            command = [sys.executable, "-S", str(ROOT / "scripts/ensemble-eval.py"),
                       "--target", target, "--mode", "produce", "--at", AT,
                       "--security-insights", target]
            completed = subprocess.run(
                command, cwd=target, env={**os.environ, "PATH": ""},
                capture_output=True, text=True, check=True)
            result = json.loads(completed.stdout)
            self.assertEqual(result["security_insights"]["status"], "not_reported")
            self.assertNotIn("security_insights", result["verdict"]["effective_weights"])
            self.assertTrue(result["actions"])
            self.assertIn("maintainer self-report", ee.to_markdown(result))

    def test_registry_fetch_is_explicit_separate_from_advisory_scans_and_replay(self):
        package = "@example/demo@1.2.3"
        registry = {"status": "ok", "facts": {"verification": "not_verified",
                    "distributions": [{"filename": "demo-1.2.3.tgz",
                                       "digest": {"algorithm": "sha512", "value": "a" * 128},
                                       "expected_digest_match": True,
                                       "attestations": {"status": "discovered"}}]},
                    "gaps": ["Signatures are not verified."]}
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "digests.json"
            expected.write_text(json.dumps({
                "schema_version": 1, "target": package,
                "expected_digests": {"demo-1.2.3.tgz": "sha512:" + "a" * 128},
            }))
            with patch.object(ee, "_have", return_value=False), \
                    patch.object(ee, "discover_registry_evidence", return_value=registry) as fetch, \
                    patch.object(ee, "query_package") as query:
                plain = ee.evaluate(package, "consume", ecosystem="npm")
                fetch.assert_not_called()
                result = ee.evaluate(package, "consume", ecosystem="npm", fetch_registry=True,
                                     registry_digests=expected)
                self.assertTrue(fetch.call_args.kwargs["allow_fetch"])
                self.assertEqual(fetch.call_args.kwargs["expected_digests"],
                                 {"demo-1.2.3.tgz": "sha512:" + "a" * 128})
                query.assert_not_called()
            self.assertEqual(result["verdict"], plain["verdict"])
            self.assertIn("discovery, not verification", ee.to_markdown(result))
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(result))
            with patch.object(ee, "discover_registry_evidence") as fetch:
                self.assertEqual(ee.replay(snapshot), result)
                fetch.assert_not_called()
            with self.assertRaisesRegex(ValueError, "cannot be combined with --at"):
                ee.evaluate(package, "consume", ecosystem="npm", fetch_registry=True, evaluated_at=AT)
            with self.assertRaisesRegex(ValueError, "requires --registry-evidence"):
                ee.evaluate(package, "consume", ecosystem="npm", registry_digests=expected)


if __name__ == "__main__":
    unittest.main()
