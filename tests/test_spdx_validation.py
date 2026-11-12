"""Official-schema validation remains optional and does not imply SBOM truth."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import artifact_evidence
import spdx_validation as validation


def document():
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "synthetic release", "documentNamespace": "https://example.org/spdx/1",
        "dataLicense": "CC0-1.0",
        "creationInfo": {"created": "2026-11-12T00:00:00Z", "creators": ["Tool: test"]},
        "documentDescribes": ["SPDXRef-root"],
        "packages": [{"SPDXID": "SPDXRef-root", "name": "demo", "versionInfo": "1.0.0",
                      "downloadLocation": "NOASSERTION", "filesAnalyzed": False}],
    }


class SPDXValidationTests(unittest.TestCase):
    def test_missing_optional_validator_is_not_a_pass(self):
        with patch.object(validation.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 3)) as run:
            result = validation.validate_spdx(document())
        self.assertEqual(result["status"], "unknown")
        self.assertIn("jsonschema==4.25.1", result["reason"])
        self.assertIn("-I", run.call_args.args[0])

    def test_schema_tamper_timeout_and_invalid_input_are_explicit(self):
        with patch.object(Path, "read_bytes", return_value=b'{"type":"object"}'), \
                patch.object(validation.subprocess, "run") as run:
            self.assertEqual(validation.validate_spdx(document())["status"], "unknown")
            run.assert_not_called()
        with patch.object(validation.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired([], 15)):
            self.assertEqual(validation.validate_spdx(document())["status"], "unknown")
        self.assertEqual(validation.validate_spdx({"value": float("nan")})["status"], "error")

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "Optional jsonschema unavailable")
    def test_real_pinned_schema_accepts_structure_rejects_missing_field(self):
        valid = document()
        self.assertEqual(validation.validate_spdx(valid)["status"], "valid")
        invalid = document()
        invalid["packages"][0].pop("downloadLocation")
        self.assertEqual(validation.validate_spdx(invalid)["status"], "invalid")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.spdx.json"
            path.write_text(json.dumps(valid))
            result = artifact_evidence.ingest_spdx(
                path, "source_checkout", validate_schema=True)
            self.assertTrue(result["facts"]["quality"]["schema_validated"])
            self.assertEqual(result["facts"]["quality"]["completeness"], "unknown")
            path.write_text(json.dumps(invalid))
            result = artifact_evidence.ingest_spdx(
                path, "source_checkout", validate_schema=True)
            self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
