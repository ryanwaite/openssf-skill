"""Offline tests for optional, unscored Security Insights self-report ingestion."""

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "security_insights", Path(__file__).resolve().parent.parent / "scripts/security_insights.py")
si = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(si)
AT = "2026-11-12T12:00:00Z"
REPO = "github.com/example/demo"


def report(**changes):
    document = {
        "header": {
            "schema-version": "2.2.0", "last-updated": "2026-11-09",
            "last-reviewed": "2026-11-10",
            "url": "https://github.com/example/demo/raw/refs/heads/main/.github/security-insights.json",
        },
        "project": {
            "name": "Demo", "administrators": [{"name": "Maintainer", "primary": True}],
            "repositories": [{"name": "demo", "url": "https://github.com/example/demo",
                              "comment": "Source"}],
            "documentation": {"design": "https://example.org/design",
                              "support-policy": "https://example.org/support"},
            "vulnerability-reporting": {
                "reports-accepted": True, "bug-bounty-available": False,
                "policy": "https://example.org/SECURITY.md"},
        },
        "repository": {
            "url": "https://github.com/example/demo", "status": "active",
            "accepts-change-request": True, "accepts-automated-change-request": False,
            "core-team": [{"name": "Maintainer", "primary": True}],
            "license": {"url": "https://example.org/LICENSE", "expression": "MIT"},
            "documentation": {"security-policy": "https://example.org/SECURITY.md"},
            "security": {"assessments": {"self": {"comment": "Not yet assessed"}}},
        },
    }
    document.update(changes)
    return document


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent / (".security-insights-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.identity = {"kind": "local_directory", "path": str(self.root),
                         "requested": str(self.root), "repo": REPO,
                         "git_commit": "a" * 40, "git_dirty": False}

    def put(self, value=None, name="security-insights.json"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report() if value is None else value), encoding="utf-8")
        return path

    def inspect(self, value=None, name="security-insights.json"):
        self.put(value, name)
        with patch.object(si.shutil, "which", return_value=None):
            return si.discover_security_insights(self.identity, AT)

    def test_valid_release_claims_are_self_report_without_schema_or_score(self):
        result = self.inspect()
        self.assertEqual(result["status"], "partial")
        facts = result["facts"]
        self.assertEqual(facts["schema_version"], "2.2.0")
        self.assertEqual(facts["schema_validation"], "unknown")
        self.assertEqual(facts["scope_match"]["repository"], True)
        self.assertEqual(facts["scope_match"]["project"], True)
        self.assertEqual(facts["revision"], "a" * 40)
        self.assertTrue(facts["revision_bound"])
        self.assertEqual(len(facts["document_sha256"]), 64)
        fields = {claim["field"] for claim in facts["claims"]}
        self.assertEqual(fields, {"documentation.design", "documentation.support-policy",
                                  "vulnerability-reporting.reports-accepted",
                                  "vulnerability-reporting.policy", "status",
                                  "documentation.security-policy"})
        self.assertTrue(all(claim["evidence_type"] == "self_report" and
                            claim["verified"] is False for claim in facts["claims"]))
        self.assertNotIn("score", facts)

    def test_missing_and_ambiguous_are_not_no_controls(self):
        missing = si.discover_security_insights(self.identity, AT)
        self.assertEqual(missing["status"], "not_reported")
        self.assertEqual(missing["facts"], {})
        self.put()
        self.put(name=".github/security-insights.json")
        multiple = si.discover_security_insights(self.identity, AT)
        self.assertEqual(multiple["status"], "error")
        selected = si.discover_security_insights(
            self.identity, AT, file_path=self.root / ".github/security-insights.json")
        self.assertEqual(selected["status"], "partial")

    def test_invalid_versions_and_malformed_shape_withhold_claims(self):
        for version in ("2.0.0", "2.3.0", "2.2.0-dev", None):
            with self.subTest(version=version):
                document = report()
                document["header"]["schema-version"] = version
                result = self.inspect(document)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("claims", result["facts"])
        self.put({"header": {"schema-version": "2.2.0"}})
        result = si.read_security_insights(self.identity, self.root / "security-insights.json", AT)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("claims", result["facts"])
        for field, value in (("repositories", []),
                             ("vulnerability-reporting", ["not an object"])):
            with self.subTest(field=field):
                document = report()
                document["project"][field] = value
                result = self.inspect(document)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("claims", result["facts"])

    def test_duplicate_json_keys_and_nonfinite_values_rejected(self):
        path = self.put()
        for content in ('{"header":{},"header":{}}', '{"header":{"schema-version":NaN}}'):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                result = si.read_security_insights(self.identity, path, AT)
                self.assertEqual(result["status"], "error")
                self.assertNotIn("claims", result["facts"])

    def test_stale_future_and_mismatched_scope_withhold_claims(self):
        for header_change in ({"last-reviewed": "2023-01-01"},
                              {"last-updated": "2026-12-01"},
                              {"last-reviewed": "2026-11-01", "last-updated": "2026-11-10"}):
            with self.subTest(change=header_change):
                document = report()
                document["header"].update(header_change)
                result = self.inspect(document)
                self.assertEqual(result["status"], "partial")
                self.assertNotIn("claims", result["facts"])
        document = report()
        document["repository"]["url"] = "https://github.com/elsewhere/demo"
        result = self.inspect(document)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("claims", result["facts"])
        document = report()
        document["project"]["repositories"][0]["url"] = "https://github.com/elsewhere/demo"
        result = self.inspect(document)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("claims", result["facts"])
        document = report()
        document["header"]["url"] = "https://github.com/elsewhere/demo/raw/main/security-insights.yml"
        self.assertEqual(self.inspect(document)["status"], "error")

    def test_inheritance_not_followed_and_scope_is_separate(self):
        document = report()
        document["header"]["project-si-source"] = "https://example.org/shared.yml"
        del document["project"]
        result = self.inspect(document)
        self.assertEqual(result["facts"]["scope_match"]["project"], None)
        self.assertTrue(any("inheritance is not fetched" in gap for gap in result["gaps"]))
        self.assertFalse(any(claim["scope"] == "project" for claim in result["facts"]["claims"]))

    def test_urls_with_secrets_never_appear_in_results(self):
        document = report()
        document["project"]["documentation"]["design"] = "https://alice:secret@example.org/design?token=private"
        result = self.inspect(document)
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))
        self.assertFalse(any(claim["field"] == "documentation.design"
                             for claim in result["facts"]["claims"]))

    def test_repo_identity_explicit_file_does_not_bind_unverified_revision(self):
        path = self.put()
        identity = {"kind": "repo", "repo": REPO, "commit": "a" * 40}
        with patch.object(si.shutil, "which", return_value=None):
            result = si.read_security_insights(identity, path, AT)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["facts"]["revision_bound"])
        self.assertEqual(result["facts"]["revision"], "a" * 40)
        with self.assertRaises(ValueError):
            si.discover_security_insights(identity, AT)

    def test_symlink_size_and_explicit_outside_path_rejected(self):
        path = self.put()
        (self.root / "link.json").symlink_to(path)
        self.assertEqual(si.read_security_insights(
            self.identity, self.root / "link.json", AT)["status"], "error")
        self.assertEqual(si.read_security_insights(
            self.identity, self.root.parent / "unrelated.json", AT)["status"], "error")
        path.write_bytes(b" " * (si._MAX_BYTES + 1))
        self.assertEqual(si.read_security_insights(self.identity, path, AT)["status"], "error")

    def test_missing_yaml_parser_has_targeted_gap(self):
        self.put(name="security-insights.yml")
        with patch.dict(sys.modules, {"yaml": None}):
            result = si.discover_security_insights(self.identity, AT)
        self.assertEqual(result["status"], "partial")
        self.assertIn("PyYAML", " ".join(result["gaps"]))
        self.assertNotIn("claims", result["facts"])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "Optional PyYAML unavailable")
    def test_yaml_duplicate_keys_tags_aliases_and_unquoted_dates(self):
        path = self.root / "security-insights.yml"
        for content in ("header:\n  schema-version: 2.2.0\n  schema-version: 2.2.0\n",
                        "header: !!python/object/apply:os.system ['echo dangerous']\n",
                        "header: &h {schema-version: 2.2.0}\nproject: *h\n",
                        "header: [\n"):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                result = si.read_security_insights(self.identity, path, AT)
                self.assertEqual(result["status"], "error")
        data = report()
        data["header"]["last-reviewed"] = "2026-11-10"
        data["header"]["last-updated"] = "2026-11-09"
        import yaml
        path.write_text(yaml.safe_dump(data).replace("'2026-11-10'", "2026-11-10")
                        .replace("'2026-11-09'", "2026-11-09"), encoding="utf-8")
        with patch.object(si.shutil, "which", return_value=None):
            result = si.read_security_insights(self.identity, path, AT)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["last_reviewed"], "2026-11-10")

    def test_schema_cli_failed_or_missing_never_counts_as_valid(self):
        path = self.put()
        with patch.object(si.shutil, "which", return_value=None):
            missing = si.read_security_insights(self.identity, path, AT)
        self.assertEqual(missing["facts"]["schema_validation"], "unknown")
        with patch.object(si.subprocess, "run") as run:
            run.return_value.returncode = 1
            invalid = si.read_security_insights(self.identity, path, AT,
                                                cue_executable="/usr/bin/cue")
        self.assertEqual(invalid["status"], "error")
        self.assertEqual(invalid["facts"]["schema_validation"], "invalid")
        self.assertNotIn("claims", invalid["facts"])
        self.assertEqual(run.call_args.args[0][-1], str(path))
        arguments = run.call_args.kwargs
        self.assertEqual(arguments["cwd"], si._SCHEMA.parent)
        self.assertEqual(arguments["env"]["CUE_REGISTRY"], "none")
        self.assertEqual(arguments["env"]["HOME"], si.os.devnull)
        self.assertNotIn("HTTP_PROXY", arguments["env"])
        self.assertEqual(arguments["stdin"], si.subprocess.DEVNULL)
        self.assertEqual(arguments["stdout"], si.subprocess.DEVNULL)
        self.assertEqual(arguments["stderr"], si.subprocess.DEVNULL)
        self.assertNotIn("capture_output", arguments)

    @unittest.skipUnless(shutil.which("cue"), "CUE CLI unavailable")
    def test_real_cue_validates_release_and_rejects_bad_shape(self):
        tool = shutil.which("cue")
        path = self.put()
        valid = si.read_security_insights(self.identity, path, AT, cue_executable=tool)
        self.assertEqual(valid["status"], "partial")
        self.assertEqual(valid["facts"]["schema_validation"], "valid")
        if importlib.util.find_spec("yaml"):
            import yaml
            yaml_path = self.root / "security-insights.yml"
            yaml_path.write_text(yaml.safe_dump(report()), encoding="utf-8")
            yaml_result = si.read_security_insights(
                self.identity, yaml_path, AT, cue_executable=tool)
            self.assertEqual(yaml_result["facts"]["schema_validation"], "valid")
        malformed = report()
        malformed["repository"].pop("license")
        self.put(malformed)
        invalid = si.read_security_insights(self.identity, path, AT, cue_executable=tool)
        self.assertEqual(invalid["status"], "error")
        self.assertEqual(invalid["facts"]["schema_validation"], "invalid")
        self.assertNotIn("claims", invalid["facts"])

    def test_nonrelease_cue_schema_is_not_trusted(self):
        path = self.put()
        fake_schema = self.root / "schema.cue"
        fake_schema.write_text("#SecurityInsights: _", encoding="utf-8")
        with patch.object(si.subprocess, "run") as run:
            result = si.read_security_insights(
                self.identity, path, AT, schema_path=fake_schema, cue_executable="cue")
        self.assertEqual(result["facts"]["schema_validation"], "unknown")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
