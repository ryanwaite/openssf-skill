"""Tests for the ensemble fusion engine (scripts/ensemble-eval.py).

These lock in the behavior described in ensemble/risk-model.md: mode weighting,
weight renormalization for unknown signals, escalation caps, and outcome mapping.
"""

import importlib.util
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "ensemble_eval", Path(__file__).resolve().parent.parent / "scripts" / "ensemble-eval.py"
)
ee = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ee)


def sig(name, subscore, status="ok", raw=None):
    return ee.signal(name, status, subscore, "high", name, raw=raw)


class TestFusion(unittest.TestCase):
    def test_consume_worked_example(self):
        # Mirrors the worked example in risk-model.md (supply_chain unknown).
        sigs = [
            sig("scorecard", 65),
            sig("known_vulns", 60, raw={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}),
            sig("maintenance", 100),
            sig("supply_chain", None, status="unknown"),
            sig("provenance", 40),
            sig("baseline", 60),
        ]
        result = ee.fuse(sigs, "consume")
        self.assertEqual(result["outcome"], "Adopt with mitigations")
        self.assertGreater(result["base_score"], 55)
        self.assertLess(result["base_score"], 80)
        self.assertIsNone(result["cap_applied"])

    def test_weights_renormalize_for_unknown(self):
        # Two ok signals only; active weight < 1 but base still 0-100.
        sigs = [sig("scorecard", 80), sig("maintenance", 100)]
        result = ee.fuse(sigs, "consume")
        self.assertLessEqual(result["final_score"], 100)
        self.assertGreaterEqual(result["final_score"], 0)
        self.assertLess(result["active_weight_covered"], 1.0)

    def test_live_secret_caps_to_F_critical(self):
        sigs = [sig("secrets", 0), sig("scorecard", 100)]
        result = ee.fuse(sigs, "produce")
        self.assertEqual(result["outcome"], "F")
        self.assertEqual(result["final_score"], 0)
        self.assertTrue(any(e["caps_at"] == "critical" for e in result["escalations"]))

    def test_critical_cve_caps_consume_to_avoid(self):
        sigs = [
            sig("known_vulns", 60, raw={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}),
            sig("maintenance", 100),
            sig("scorecard", 100),
        ]
        result = ee.fuse(sigs, "consume")
        self.assertEqual(result["outcome"], "Avoid")
        self.assertLessEqual(result["final_score"], 54)

    def test_archived_caps_high(self):
        sigs = [sig("maintenance", 0), sig("scorecard", 100), sig("known_vulns", 100)]
        result = ee.fuse(sigs, "consume")
        self.assertTrue(any("Archived" in e["rule"] for e in result["escalations"]))

    def test_insufficient_data(self):
        sigs = [sig("scorecard", None, status="unknown")]
        result = ee.fuse(sigs, "consume")
        self.assertEqual(result["outcome"], "INSUFFICIENT DATA")
        self.assertEqual(result["confidence"], "low")

    def test_strong_consume_adopts(self):
        sigs = [
            sig("scorecard", 95), sig("known_vulns", 100), sig("maintenance", 100),
            sig("supply_chain", 90), sig("provenance", 90), sig("baseline", 90),
        ]
        self.assertEqual(ee.fuse(sigs, "consume")["outcome"], "Adopt")

    def test_outcome_mapping_grades(self):
        self.assertEqual(ee._outcome(92, "produce", []), "A")
        self.assertEqual(ee._outcome(85, "produce", []), "B")
        self.assertEqual(ee._outcome(72, "produce", []), "C")
        self.assertEqual(ee._outcome(62, "produce", []), "D")
        self.assertEqual(ee._outcome(40, "produce", []), "F")


class TestNormalization(unittest.TestCase):
    def test_target_classification(self):
        self.assertTrue(ee.classify_target("https://github.com/owner/repo")["is_repo"])
        self.assertTrue(ee.classify_target(".")["is_local"])

    def test_known_vulns_deductions(self):
        # Pure unit check of the deduction table via probe is integration-heavy;
        # here we assert the constants match the risk model.
        self.assertEqual(ee.SEVERITY_DEDUCTION["CRITICAL"], 40)
        self.assertEqual(ee.SEVERITY_DEDUCTION["HIGH"], 20)


if __name__ == "__main__":
    unittest.main()
