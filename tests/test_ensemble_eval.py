"""Scanner, evidence, and fusion regression tests for the ensemble evaluator."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "ensemble_eval", Path(__file__).resolve().parent.parent / "scripts" / "ensemble-eval.py"
)
ee = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ee)

AT = "2026-11-09T12:00:00+00:00"


def sig(name, subscore, status="ok", raw=None, confidence="high", evidence_type="observation"):
    return ee.signal(name, status, subscore, confidence, name, raw=raw,
                     evidence_type=evidence_type)


def process(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class TestFusion(unittest.TestCase):
    def test_consume_worked_example(self):
        signals = [
            sig("scorecard", 65), sig("known_vulns", 60), sig("maintenance", 100),
            sig("supply_chain", None, status="unknown"), sig("provenance", 40),
            sig("baseline", 60),
        ]
        result = ee.fuse(signals, "consume")
        self.assertEqual(result["base_score"], 68.5)
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertEqual(result["provisional_outcome"], "Adopt with mitigations")
        self.assertEqual(result["confidence"], "low")

    def test_partial_never_claims_positive_assurance(self):
        for mode, name in (("consume", "maintenance"), ("produce", "secrets")):
            with self.subTest(mode=mode):
                result = ee.fuse([sig(name, 100)], mode)
                self.assertEqual(result["outcome"], "INCOMPLETE")
                self.assertEqual(result["confidence"], "low")
        # A low score derived from one non-blocking probe is also only provisional.
        self.assertEqual(ee.fuse([sig("maintenance", 0)], "consume")["outcome"],
                         "INCOMPLETE")

    def test_low_quality_at_high_coverage_is_not_high_confidence(self):
        signals = [sig(name, 100, confidence="low")
                   for name in ee.MODE_WEIGHTS["produce"] if name != "known_vulns"]
        result = ee.fuse(signals, "produce")
        self.assertEqual(result["active_weight_covered"], 0.88)
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["outcome"], "INCOMPLETE")

    def test_only_verified_live_secret_caps(self):
        findings = [sig("secrets", 50, raw={"potential_count": 1, "verified_live": False}),
                    sig("scorecard", 100)]
        self.assertFalse(ee.fuse(findings, "produce")["escalations"])
        verified = [sig("secrets", 0, raw={"verified_live": True},
                        evidence_type="verified_finding"), sig("scorecard", 100)]
        result = ee.fuse(verified, "produce")
        self.assertEqual(result["outcome"], "F")
        self.assertEqual(result["final_score"], 0)

    def test_critical_fix_and_dependency_context_caps(self):
        vuln = sig("known_vulns", 20, raw={"findings": [
            {"severity": "CRITICAL", "fixed_versions": ["2.0"]}]})
        self.assertEqual(ee.fuse([vuln, sig("maintenance", 100)], "consume")["outcome"], "Avoid")
        no_fix = sig("known_vulns", 20, raw={"findings": [
            {"severity": "CRITICAL", "fixed_versions": []}]})
        self.assertFalse(ee.fuse([no_fix], "consume")["escalations"])
        archived = sig("maintenance", 0, raw={"archived": True, "critical_dependency": True})
        self.assertTrue(ee.fuse([archived], "consume")["escalations"])
        self.assertFalse(ee.fuse([sig("maintenance", 0, raw={"archived": True})],
                                 "consume")["escalations"])

    def test_reject_invalid_or_duplicate_scores(self):
        for signals in ([sig("maintenance", 101)], [sig("maintenance", float("nan"))],
                        [sig("maintenance", None)], [sig("maintenance", 50),
                                                    sig("maintenance", 75)]):
            with self.subTest(signals=signals), self.assertRaises(ValueError):
                ee.fuse(signals, "consume")

    def test_complete_outcomes(self):
        for mode, outcome in (("consume", "Adopt"), ("produce", "A")):
            signals = [sig(name, 100) for name in ee.MODE_WEIGHTS[mode]]
            result = ee.fuse(signals, mode)
            self.assertEqual(result["outcome"], outcome)
            self.assertEqual(result["confidence"], "high")


class TestAdapters(unittest.TestCase):
    def test_osv_failures_and_bad_shapes_never_clean(self):
        with patch.object(ee, "_have", return_value=True):
            for proc in (process(2, "{}", "bad configuration"),
                         process(0, "null"), process(0, "[]"),
                         process(0, "{}"), process(0, "{invalid")):
                with self.subTest(proc=proc.stdout), patch.object(ee, "_run", return_value=proc):
                    result = ee.probe_known_vulns(".", True)
                    self.assertNotEqual(result["status"], "ok")
                    self.assertIsNone(result["subscore"])

    def test_scorecard_missing_or_out_of_range_aggregate_not_observed(self):
        with patch.object(ee, "_have", return_value=True):
            for raw in ('{}', '{"score": -1}', '{"score": 11}'):
                with self.subTest(raw=raw), \
                        patch.object(ee, "_run", return_value=process(0, raw)):
                    result = ee.probe_scorecard("https://github.com/example/repo", True)
                    self.assertEqual(result["status"], "error")
                    self.assertIsNone(result["subscore"])

    def test_osv_alias_group_dedup_fix_severity_and_identity(self):
        advisory = {
            "id": "GHSA-123", "aliases": ["CVE-123"],
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{"ranges": [{"events": [{"fixed": "2.0"}]}]}],
        }
        data = {"results": [
            {"source": {"path": "a.lock", "type": "lockfile"}, "packages": [{
                "package": {"name": "demo", "version": "1.0", "ecosystem": "npm"},
                "vulnerabilities": [advisory, {"id": "OSV-123", "aliases": ["CVE-123"],
                                                "database_specific": {"severity": "HIGH"}}],
                "groups": [{"ids": ["GHSA-123", "OSV-123"]}],
            }]},
            {"source": {"path": "b.lock", "type": "lockfile"}, "packages": [{
                "package": {"name": "demo", "version": "1.0", "ecosystem": "npm"},
                "vulnerabilities": [advisory],
            }]},
        ]}
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(1, json.dumps(data))):
            result = ee.probe_known_vulns(".", True)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["subscore"], 20)
        finding, = result["raw"]["findings"]
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["aliases"], ["CVE-123", "GHSA-123", "OSV-123"])
        self.assertEqual(finding["fixed_versions"], ["2.0"])
        self.assertEqual(finding["paths"], ["a.lock", "b.lock"])

    def test_vector_only_not_misclassified_medium(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        data = {"results": [{"source": {"path": "a.lock"}, "packages": [{
            "package": {"name": "demo", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "CVE-123", "severity": [{"score": vector}]}],
        }]}]}
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(1, json.dumps(data))):
            result = ee.probe_known_vulns(".", True)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["subscore"])
        self.assertEqual(result["raw"]["findings"][0]["severity"], None)

    def test_package_target_not_passed_as_lockfile(self):
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run") as run:
            result = ee.probe_known_vulns("requests@2.31.0", False)
        self.assertEqual(result["status"], "unknown")
        run.assert_not_called()

    def test_old_gh_push_is_not_reported_as_recent(self):
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(
                    0, '{"archived":false,"pushed":"2010-01-01T00:00:00Z"}')):
            result = ee.probe_maintenance("https://github.com/example/repo", False)
        self.assertEqual(result["subscore"], 50)
        self.assertEqual(result["confidence"], "low")

    def test_gitleaks_failures_and_malformed_report_never_clean(self):
        with tempfile.TemporaryDirectory() as target, patch.object(ee, "_have", return_value=True):
            for proc in (process(2, "", "secret=do-not-log"), process(0, "not json")):
                with self.subTest(code=proc.returncode), \
                        patch.object(ee, "_run", return_value=proc):
                    result = ee.probe_secrets(target, True)
                    self.assertEqual(result["status"], "error")
                    self.assertIsNone(result["subscore"])
                    self.assertNotIn("do-not-log", str(result))

    def test_gitleaks_scans_history_and_tree_and_redacts(self):
        with tempfile.TemporaryDirectory() as target:
            (Path(target) / ".git").mkdir()

            def fake_run(cmd, timeout=180):
                report = Path(cmd[cmd.index("--report-path") + 1])
                findings = [{"Secret": "sensitive-content"}] if cmd[1] == "git" else []
                report.write_text(json.dumps(findings))
                self.assertIn("--redact=100", cmd)
                return process(1 if findings else 0)

            with patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", side_effect=fake_run):
                result = ee.probe_secrets(target, True)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["subscore"], 50)
            self.assertNotIn("sensitive-content", json.dumps(result))
            self.assertEqual(result["raw"]["scopes"], {"git": 1, "dir": 0})

    def test_gitleaks_nil_clean_report_and_partial_failure(self):
        with tempfile.TemporaryDirectory() as target:
            def fake_run(cmd, timeout=180):
                Path(cmd[cmd.index("--report-path") + 1]).write_text("null")
                return process(0)

            with patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", side_effect=fake_run):
                self.assertEqual(ee.probe_secrets(target, True)["subscore"], 100)

            def partial_run(cmd, timeout=180):
                Path(cmd[cmd.index("--report-path") + 1]).write_text(
                    '[{"Secret":"do-not-log"}]')
                return process(1, stderr="partial scan completed")

            with patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", side_effect=partial_run):
                result = ee.probe_secrets(target, True)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("do-not-log", str(result))


class TestEvidence(unittest.TestCase):
    def test_no_external_tools_still_actionable(self):
        with tempfile.TemporaryDirectory() as target, patch.object(ee, "_have", return_value=False):
            report = ee.evaluate(target, "produce", evaluated_at=AT)
        self.assertEqual(report["verdict"]["outcome"], "INCOMPLETE")
        self.assertEqual(report["verdict"]["active_weight_covered"], 0)
        self.assertTrue(report["actions"])
        self.assertIn("Required actions", ee.to_markdown(report))

    def test_manual_evidence_binding_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "target")
            Path(target).mkdir()
            evidence = Path(directory) / "evidence.json"
            evidence.write_text(json.dumps({
                "schema_version": 1, "target": target, "mode": "produce",
                "observations": [{
                    "name": "baseline", "evidence_type": "manual_observation",
                    "facts": {"controls_met": 3, "controls_total": 4,
                              "catalog_version": "v2026.08.28"},
                    "source": "local checklist", "captured_at": AT,
                    "tool": {"name": "manual", "version": "1"},
                }],
            }))
            with patch.object(ee, "_have", return_value=False):
                report = ee.evaluate(target, "produce", evidence, evaluated_at=AT)
            self.assertEqual(next(s for s in report["signals"] if s["name"] == "baseline")
                             ["subscore"], 75)
            self.assertEqual(report["verdict"]["outcome"], "INCOMPLETE")
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            with patch.object(ee, "_run") as run:
                self.assertEqual(ee.replay(snapshot), report)
                run.assert_not_called()
            cli = subprocess.run(
                ["python3", str(Path(ee.__file__)), "--replay", str(snapshot),
                 "--at", AT, "--format", "json"],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(json.loads(cli.stdout), report)
            data = json.loads(evidence.read_text())
            data["target"] = "different"
            evidence.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                ee._import_evidence(evidence, target, "produce")

    def test_self_report_does_not_count_as_verified(self):
        item = {"name": "provenance", "facts": {"slsa_level": 3},
                "evidence_type": "self_report", "source": "project homepage",
                "captured_at": AT, "tool": {"name": "manual", "version": "1"}}
        result = ee._manual_signal(item)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["subscore"])


if __name__ == "__main__":
    unittest.main()
