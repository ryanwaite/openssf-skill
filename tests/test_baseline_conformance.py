"""Behavioral coverage for versioned, partial Baseline observations."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "baseline_conformance", ROOT / "scripts/baseline_conformance.py")
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)
AT = "2026-11-11T00:00:00Z"


def record():
    return {
        "schema_version": 1, "catalog_version": "2026.08.28",
        "target": "example/project", "revision": "release-1", "scope": "Primary repository",
        "level": 1, "observations": [{
            "requirement_id": "OSPS-VM-02.01", "status": "met",
            "evidence_type": "manual_observation",
            "source": "Human review of release-1", "captured_at": "2026-11-10T00:00:00Z",
            "reason": "Security contacts documented", "evidence": ["SECURITY.md at release-1"],
        }],
    }


def evaluate(data):
    return baseline.evaluate_conformance(data, "example/project", evaluated_at=AT)


class TestBaselineConformance(unittest.TestCase):
    def test_partial_record_is_useful_without_full_catalog_or_tools(self):
        result = evaluate(record())
        self.assertEqual(result["counts"], {
            "met": 1, "not_met": 0, "unknown": 23, "not_applicable": 0})
        self.assertEqual(result["outcome"], "incomplete")
        self.assertFalse(result["independently_verified"])
        self.assertNotIn("score", result)
        contact = next(row for row in result["requirements"]
                       if row["requirement_id"] == "OSPS-VM-02.01")
        self.assertEqual(contact["age_days"], 1)
        self.assertEqual(contact["evidence"], ["SECURITY.md at release-1"])

    def test_explicit_maturity_applicability_not_cumulative_guess(self):
        data = record()
        data["level"], data["observations"] = 2, []
        ids = {row["requirement_id"] for row in evaluate(data)["requirements"]}
        self.assertIn("OSPS-AC-04.01", ids)
        self.assertIn("OSPS-BR-06.01", ids)
        self.assertNotIn("OSPS-QA-07.01", ids)
        self.assertNotIn("OSPS-BR-07.01", ids)
        self.assertNotIn("OSPS-VM-02.01", ids)
        data["level"] = 3
        self.assertIn("OSPS-QA-07.01",
                      {row["requirement_id"] for row in evaluate(data)["requirements"]})

    def test_invalid_identity_catalog_level_or_requirement_is_not_ignored(self):
        for field, value in (("schema_version", True), ("catalog_version", "latest"),
                             ("target", "other/project"), ("level", True)):
            with self.subTest(field=field):
                data = record()
                data[field] = value
                with self.assertRaises(ValueError):
                    evaluate(data)
        for name in ("OSPS-BR-01.02", "OSPS-QA-07.01", "AC-01", "OSPS-X-01.01"):
            with self.subTest(requirement=name):
                data = record()
                data["observations"][0]["requirement_id"] = name
                with self.assertRaises(ValueError):
                    evaluate(data)
        with self.assertRaisesRegex(ValueError, "revision"):
            baseline.evaluate_conformance(record(), "example/project", evaluated_at=AT,
                                          expected_revision="different")

    def test_self_report_keeps_claim_but_does_not_establish_conformance(self):
        data = record()
        data["observations"][0]["evidence_type"] = "self_report"
        result = evaluate(data)
        self.assertEqual(result["counts"]["met"], 0)
        row = next(row for row in result["requirements"]
                   if row["requirement_id"] == "OSPS-VM-02.01")
        self.assertEqual(row["asserted_status"], "met")
        self.assertEqual(row["status"], "unknown")

    def test_evidence_reason_duplicates_and_future_dates_are_validated(self):
        for field, value in (("evidence", []), ("reason", ""),
                             ("captured_at", "2026-11-12T00:00:00Z"),
                             ("captured_at", "2026-11-10"),
                             ("evidence_type", "verified_by_scanner")):
            with self.subTest(field=field, value=value):
                data = record()
                data["observations"][0][field] = value
                with self.assertRaises(ValueError):
                    evaluate(data)
        data = record()
        data["observations"].append(deepcopy(data["observations"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            evaluate(data)

    def test_not_met_and_not_applicable_retain_rationale(self):
        data = record()
        data["observations"][0]["status"] = "not_met"
        self.assertEqual(evaluate(data)["outcome"], "gaps_reported")
        item = data["observations"][0]
        item.update(requirement_id="OSPS-DO-01.01", status="not_applicable",
                    reason="No releases have been made", evidence=[])
        result = evaluate(data)
        self.assertEqual(result["counts"]["not_applicable"], 1)
        self.assertEqual(result["outcome"], "incomplete")
        item["reason"] = ""
        with self.assertRaises(ValueError):
            evaluate(data)

    def test_complete_supplied_evidence_is_not_certification(self):
        data = record()
        item = data["observations"][0]
        data["observations"] = [
            {**item, "requirement_id": name}
            for name, levels in baseline.REQUIREMENTS.items() if 1 in levels
        ]
        result = evaluate(data)
        self.assertEqual(result["outcome"], "met_by_supplied_observations")
        self.assertFalse(result["independently_verified"])
        self.assertNotIn("grade", result)

    def test_cli_works_without_site_packages_and_empty_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            data = record()
            data["observations"] = []
            path.write_text(json.dumps(data), encoding="utf-8")
            run = subprocess.run(
                [sys.executable, "-S", str(ROOT / "scripts/baseline_conformance.py"),
                 "--target", "example/project", "--evidence", str(path), "--at", AT],
                cwd=temporary, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(run.stdout)["counts"]["unknown"], 24)
            path.write_bytes(b" " * (baseline.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "1 MB"):
                baseline.load_evidence(path)


if __name__ == "__main__":
    unittest.main()
