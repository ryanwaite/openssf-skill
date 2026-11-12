"""Scanner, evidence, and fusion regression tests for the ensemble evaluator."""

import importlib.util
from contextlib import redirect_stdout
from datetime import datetime, timezone
import gzip
from io import BytesIO, StringIO
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import remote_acquisition as ra

_SPEC = importlib.util.spec_from_file_location(
    "ensemble_eval", Path(__file__).resolve().parent.parent / "scripts" / "ensemble-eval.py"
)
ee = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ee)

AT = "2026-11-09T12:00:00+00:00"
REMOTE_AT = datetime.now(timezone.utc).isoformat()


def sig(name, subscore, status="ok", raw=None, confidence="high", evidence_type="observation"):
    return ee.signal(name, status, subscore, confidence, name, raw=raw,
                     evidence_type=evidence_type)


def process(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def scorecard_result(commit="a" * 40, date=AT):
    return {
        "date": date, "repo": {"name": "github.com/example/repo", "commit": commit},
        "scorecard": {"version": "v5.6.0", "commit": "f" * 40}, "score": 9.2,
        "checks": [{"name": name, "score": 10, "reason": "observed", "details": None}
                   for name in sorted(ee._SCORECARD_CHECKS)],
    }


class TestFusion(unittest.TestCase):
    def test_consume_worked_example(self):
        signals = [
            sig("scorecard", 65), sig("known_vulns", 60), sig("maintenance", 100),
            sig("supply_chain", None, status="unknown"), sig("provenance", 40),
        ]
        result = ee.fuse(signals, "consume")
        self.assertEqual(result["base_score"], 69.3)
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
        self.assertEqual(result["active_weight_covered"], 0.87)
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

    def test_critical_fix_blocks_even_without_base_score(self):
        unknown = sig("known_vulns", None, status="unknown", raw={"findings": [
            {"severity": "CRITICAL", "fixed_versions": ["2.0"]}]})
        result = ee.fuse([unknown], "consume")
        self.assertEqual(result["outcome"], "Avoid")
        self.assertIsNone(result["base_score"])
        self.assertIsNone(result["final_score"])
        self.assertEqual(result["cap_applied"], "Unpatched CRITICAL vulnerability with fix")

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

    def test_scanner_all_packages_clean_shape_requires_valid_package_identity(self):
        data = {"results": [{"source": {"path": "requirements.txt", "type": "lockfile"},
                             "packages": [{"package": {"name": "requests",
                                                       "version": "2.32.0",
                                                       "ecosystem": "PyPI",
                                                       "purl": "pkg:pypi/requests@2.32.0"}}]}],
                "experimental_config": {"licenses": {"summary": False, "allowlist": None}}}
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))) as run:
            clean = ee.probe_known_vulns("requirements.txt", True)
        self.assertEqual(clean["status"], "ok")
        self.assertEqual(clean["subscore"], 100)
        self.assertEqual(clean["raw"]["triage"][0]["package"]["version"], "2.32.0")
        self.assertIn("--all-packages", run.call_args.args[0])
        self.assertIn("--all-vulns", run.call_args.args[0])
        data["results"][0]["packages"][0]["groups"] = [{"ids": ["CVE-123"]}]
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
            self.assertEqual(ee.probe_known_vulns("requirements.txt", True)["status"],
                             "error")
        data["results"][0]["packages"][0].pop("groups")
        del data["results"][0]["packages"][0]["package"]["version"]
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
            self.assertEqual(ee.probe_known_vulns("requirements.txt", True)["status"],
                             "error")
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, '{"results":[]}')):
            self.assertEqual(ee.probe_known_vulns("requirements.txt", True)["status"],
                             "unknown")

    def test_scorecard_missing_or_out_of_range_aggregate_not_observed(self):
        with patch.object(ee, "_have", return_value=True):
            for raw in ('{}', '{"score": -1}', '{"score": 11}',
                        '{"score": true}', '{"score": NaN}', '{"score": null}'):
                with self.subTest(raw=raw), \
                        patch.object(ee, "_run", return_value=process(0, raw)):
                    result = ee.probe_scorecard("https://github.com/example/repo", True)
                    self.assertEqual(result["status"], "error")
                    self.assertIsNone(result["subscore"])

    def test_scorecard_checks_revision_and_freshness(self):
        identity = ee.resolve_target("example/repo@" + "a" * 40)
        data = scorecard_result()
        failed = next(c for c in data["checks"] if c["name"] == "Dangerous-Workflow")
        failed.update(score=0, reason="dangerous checkout", details=["workflow.yml:12"])
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))) as run:
            result = ee.probe_scorecard(identity["requested"], True, identity, "produce", AT)
        self.assertEqual(result["status"], "ok")
        self.assertLess(result["subscore"], 100)
        self.assertEqual(result["raw"]["aggregate"], 9.2)
        self.assertEqual(result["raw"]["commit"], "a" * 40)
        self.assertEqual(failed["details"], ["workflow.yml:12"])
        self.assertIn("--commit=" + "a" * 40, run.call_args.args[0])
        report = ee._report(identity["requested"], "produce", [result], AT,
                            "repo", identity)
        self.assertIn("dangerous checkout", ee.to_markdown(report))
        self.assertIn("Dangerous-Workflow", report["actions"][0])
        self.assertIn("Scorecard Dangerous-Workflow", ee._risks([result])[0]["finding"])
        data["repo"]["commit"] = "b" * 40
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
            mismatched = ee.probe_scorecard(identity["requested"], True, identity, "produce", AT)
        self.assertEqual(mismatched["status"], "unknown")
        self.assertIn("different commit", mismatched["finding"])
        data["repo"]["commit"] = "a" * 40
        for field in ("date", "commit"):
            altered = json.loads(json.dumps(data))
            if field == "date":
                altered.pop("date")
            else:
                altered["repo"].pop("commit")
            with self.subTest(field=field), patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", return_value=process(0, json.dumps(altered))):
                result = ee.probe_scorecard(identity["requested"], True, identity, "produce", AT)
                self.assertEqual(result["status"], "unknown")
        data["date"] = "2026-01-01T00:00:00Z"
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
            stale = ee.probe_scorecard(identity["requested"], True, identity, "produce", AT)
        self.assertEqual(stale["status"], "unknown")
        self.assertIn("90 days", stale["finding"])

    def test_scorecard_unavailable_and_omitted_checks_do_not_score(self):
        identity = ee.resolve_target("example/repo")
        for mutate in (
                lambda d: d["checks"][0].update(score=-1, reason="permission denied"),
                lambda d: d["checks"].pop(),
        ):
            data = scorecard_result()
            mutate(data)
            with patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
                result = ee.probe_scorecard(identity["requested"], True, identity, "consume", AT)
            self.assertEqual(result["status"], "unknown")
            self.assertIsNone(result["subscore"])
            self.assertTrue(result["raw"]["checks"])
        data = scorecard_result()
        data["checks"][0]["score"] = True
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(0, json.dumps(data))):
            self.assertEqual(ee.probe_scorecard(identity["requested"], True,
                                                identity, "consume", AT)["status"], "error")

    def test_dirty_local_origin_cannot_substitute_remote_scorecard(self):
        identity = {"kind": "local_directory", "repo": "github.com/example/repo",
                    "git_commit": "a" * 40, "git_dirty": True}
        with patch.object(ee, "_have", return_value=True), patch.object(ee, "_run") as run:
            result = ee.probe_scorecard("./repo", False, identity, "produce", AT)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("dirty", result["finding"])
        run.assert_not_called()

    def test_cli_mock_scanner_files_and_pinned_repo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lockfile = root / "package-lock.json"
            lockfile.write_text('{"lockfileVersion":3}')
            osv = root / "osv-scanner"
            osv.write_text("#!/usr/bin/env python3\n"
                           "import json, os, sys\n"
                           "open(os.environ['COMMAND_LOG'], 'a').write(json.dumps(sys.argv[1:])+'\\n')\n"
                           "print(json.dumps({'results':[{'source':{'path':'package-lock.json'},"
                           "'packages':[{'package':{'name':'demo','version':'1',"
                           "'ecosystem':'npm'},'vulnerabilities':[]}]}]}))\n")
            osv.chmod(0o755)
            scorecard = root / "scorecard"
            scorecard.write_text("#!/usr/bin/env python3\n"
                                 "import os, sys\n"
                                 "open(os.environ['COMMAND_LOG'], 'a').write(repr(sys.argv[1:])+'\\n')\n"
                                 f"print({json.dumps(json.dumps(scorecard_result()))})\n")
            scorecard.chmod(0o755)
            gh = root / "gh"
            gh.write_text("#!/bin/sh\nexit 1\n")
            gh.chmod(0o755)
            command_log = root / "calls"
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       COMMAND_LOG=str(command_log))
            cli = [sys.executable, str(Path(ee.__file__)), "--mode", "consume",
                   "--at", AT]
            local = subprocess.run(cli + ["--target", str(lockfile)], env=env,
                                   check=True, capture_output=True, text=True)
            local_data = json.loads(local.stdout)
            self.assertEqual(local_data["target_kind"], "local_file")
            self.assertEqual(next(s for s in local_data["signals"]
                                  if s["name"] == "known_vulns")["subscore"], 100)
            self.assertIn("--lockfile=:" + str(lockfile), command_log.read_text())
            command_log.unlink()
            remote = subprocess.run(cli + ["--target", "example/repo@" + "a" * 40],
                                    env=env, check=True, capture_output=True, text=True)
            remote_data = json.loads(remote.stdout)
            self.assertEqual(next(s for s in remote_data["signals"]
                                  if s["name"] == "scorecard")["status"], "ok")
            self.assertEqual(next(s for s in remote_data["signals"]
                                  if s["name"] == "known_vulns")["status"], "unknown")
            self.assertIn("--commit=" + "a" * 40, command_log.read_text())
            self.assertNotIn("osv-scanner", command_log.read_text())

    def test_osv_file_uses_lockfile_or_sbom_flag_not_directory_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename, flag in (("package-lock.json", "--lockfile=:"),
                                   ("artifact.spdx.json", "-L")):
                path = Path(directory) / filename
                path.write_text("{}")
                identity = ee.resolve_target(str(path))
                with self.subTest(filename=filename), \
                        patch.object(ee, "_have", return_value=True), \
                        patch.object(ee, "_run", return_value=process(0, '{"results":[]}')) as run:
                    result = ee.probe_known_vulns(str(path), True, identity)
                self.assertEqual(result["status"], "unknown")
                cmd = run.call_args.args[0]
                self.assertIn("--no-call-analysis=go", cmd)
                self.assertNotIn("--recursive", cmd)
                if flag == "-L":
                    self.assertEqual(cmd[-2:], ["-L", str(path)])
                else:
                    self.assertEqual(cmd[-1], flag + str(path))
            for target in ("example/repo", "pkg:npm/name@1", "registry/app@sha256:" + "f" * 64):
                with patch.object(ee, "_have", return_value=True), \
                        patch.object(ee, "_run") as run:
                    result = ee.evaluate(target, "consume", evaluated_at=AT,
                                         ecosystem="npm" if target.startswith("pkg:") else None)
                    self.assertNotEqual(next(s for s in result["signals"] if
                                             s["name"] == "known_vulns")["status"], "ok")
                    self.assertFalse(any(c.args[0][0] == "osv-scanner"
                                         for c in run.call_args_list))

    def test_osv_directory_preserves_source_scan_without_go_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = ee.resolve_target(directory)
            with patch.object(ee, "_have", return_value=True), \
                    patch.object(ee, "_run", return_value=process(0, '{"results":[]}')) as run:
                ee.probe_known_vulns(directory, True, identity)
            self.assertEqual(run.call_args.args[0][-2:], ["--recursive", directory])
            self.assertIn("--no-call-analysis=go", run.call_args.args[0])

    def test_osv_alias_group_dedup_fix_severity_and_identity(self):
        advisory = {
            "id": "GHSA-123", "aliases": ["CVE-123"],
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "demo"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "2.0"}]}]}],
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
            "vulnerabilities": [{"id": "CVE-123",
                                  "severity": [{"type": "CVSS_V3", "score": vector}]}],
        }]}]}
        def absent_cvss(cmd, timeout=180):
            if cmd[0] == sys.executable:
                self.assertEqual(cmd[1], "-I")
                return process(3)
            return process(1, json.dumps(data))

        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", side_effect=absent_cvss):
            result = ee.probe_known_vulns(".", True)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["subscore"])
        self.assertEqual(result["raw"]["findings"][0]["severity"], None)
        self.assertEqual(result["raw"]["findings"][0]["severity_status"], "parser_unavailable")
        self.assertIn("optional", result["finding"])

    @unittest.skipUnless(importlib.util.find_spec("cvss"), "Install optional cvss==3.6")
    def test_cvss3_vector_98_critical_and_conflicting_lower_bucket(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        severity, base, status = ee._severity({
            "severity": [{"type": "CVSS_V3", "score": vector}],
            "database_specific": {"severity": "MEDIUM"},
        })
        self.assertEqual((severity, base, status), ("CRITICAL", 9.8, "known"))
        data = {"results": [{"source": {"path": "a.lock"}, "packages": [{
            "package": {"name": "demo", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "CVE-123", "severity": [
                {"type": "CVSS_V3", "score": vector}],
                "affected": [{"package": {"ecosystem": "npm", "name": "demo"},
                              "ranges": [{"type": "SEMVER", "events": [{"fixed": "2"}]}]}]}],
        }]}]}
        original_run = ee._run

        def scanner(cmd, timeout=180):
            return (original_run(cmd, timeout) if cmd[0] == sys.executable
                    else process(1, json.dumps(data)))

        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", side_effect=scanner):
            result = ee.probe_known_vulns(".", True)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["subscore"], 20)
        self.assertEqual(result["raw"]["findings"][0]["cvss_base_score"], 9.8)
        self.assertEqual(result["raw"]["findings"][0]["severity"], "CRITICAL")

    @unittest.skipUnless(importlib.util.find_spec("cvss"), "Install optional cvss==3.6")
    def test_cvss4_vector_and_malformed_conflicting_evidence(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"
        self.assertEqual(ee._severity({"severity": [{"type": "CVSS_V4", "score": vector}]}),
                         ("CRITICAL", 9.9, "known"))
        zero = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        self.assertEqual(ee._severity({"severity": [{"type": "CVSS_V3", "score": zero}]}),
                         ("NONE", 0.0, "known"))
        severity, base, status = ee._severity({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            "database_specific": {"severity": "LOW"},
        })
        self.assertEqual((severity, base, status), (None, None, "malformed_vector"))

    def test_missing_and_unsupported_vector_remain_unknown(self):
        self.assertEqual(ee._severity({}), (None, None, "missing"))
        severity, base, status = ee._severity({"severity": [
            {"type": "CVSS_V3", "score": "CVSS:9.9/AV:N"}]})
        self.assertEqual((severity, base, status), (None, None, "unsupported_vector"))

    def test_partial_severity_keeps_supported_critical_fix_cap(self):
        data = {"results": [{"source": {"path": "a.lock"}, "packages": [{
            "package": {"name": "demo", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "CVE-123",
                "severity": [{"type": "CVSS_V3", "score": "9.8"},
                             {"type": "CVSS_V3", "score": "CVSS:9.9/AV:N"}],
                "affected": [{"package": {"ecosystem": "npm", "name": "demo"},
                              "ranges": [{"type": "SEMVER", "events": [{"fixed": "2"}]}]}],
            }],
        }]}]}
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", return_value=process(1, json.dumps(data))):
            result = ee.probe_known_vulns(".", True)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["subscore"])
        self.assertEqual(result["raw"]["findings"][0]["severity"], "CRITICAL")
        verdict = ee.fuse([result], "consume")
        self.assertEqual(verdict["outcome"], "Avoid")
        self.assertEqual(verdict["cap_applied"], "Unpatched CRITICAL vulnerability with fix")

    def test_package_target_not_passed_as_lockfile(self):
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run") as run:
            result = ee.probe_known_vulns("requests@2.31.0", False)
        self.assertEqual(result["status"], "unknown")
        run.assert_not_called()

    def test_explicit_package_query_pagination_triage_and_cli_replay(self):
        fixed = {"id": "MAL-123", "aliases": ["GHSA-xyz"],
                 "database_specific": {"severity": "CRITICAL"},
                 "affected": [{"package": {"ecosystem": "npm", "name": "@scope/name"},
                               "ranges": [{"type": "SEMVER", "events": [
                                   {"introduced": "0"}, {"fixed": "2.0"}]}]}]}
        withdrawn = {"id": "CVE-123", "withdrawn": AT,
                     "affected": [{"package": {"ecosystem": "npm", "name": "@scope/name"},
                                   "versions": ["1.0"]}]}
        responses = [json.dumps({"vulns": [fixed], "next_page_token": "next"}).encode(),
                     json.dumps({"vulns": [withdrawn]}).encode()]
        calls = []

        def fake_read(url, *, payload=None, limit=ra.MAX_RESPONSE):
            self.assertEqual(url, "https://api.osv.dev/v1/query")
            calls.append(json.loads(payload))
            return responses.pop(0)

        with patch.object(ra, "_read", side_effect=fake_read), \
                patch.object(ee, "_have", return_value=False), \
                patch.object(sys, "argv", ["ensemble-eval.py", "--target",
                                            "@scope/name@1.0", "--ecosystem", "npm",
                                            "--mode", "consume", "--at", REMOTE_AT,
                                            "--acquire-remote"]), \
                redirect_stdout(StringIO()) as output:
            ee.main()
        report = json.loads(output.getvalue())
        self.assertEqual(calls[0], {"package": {"ecosystem": "npm",
                                                "name": "@scope/name"}, "version": "1.0"})
        self.assertEqual(calls[1]["page_token"], "next")
        known = next(s for s in report["signals"] if s["name"] == "known_vulns")
        self.assertEqual(known["raw"]["findings"][0]["fixed_versions"], ["2.0"])
        self.assertEqual(known["raw"]["findings"][0]["paths"], ["pkg:npm/%40scope/name@1.0"])
        self.assertEqual(known["raw"]["triage"][0]["findings"][0]["version_status"], "withdrawn")
        self.assertTrue(any(record["malicious"]["report"] for finding in
                            known["raw"]["triage"][0]["findings"]
                            for record in finding["records"]))
        self.assertEqual(report["remote_acquisition"]["pages"], 2)
        self.assertIn("advisory lookup only", report["remote_acquisition"]["scope"])
        self.assertEqual(report["target_identity"]["identifier"], "npm:@scope/name@1.0")
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            self.assertEqual(ee.replay(snapshot)["remote_acquisition"],
                             report["remote_acquisition"])

    def test_pypi_empty_query_and_query_errors_do_not_fabricate_coverage(self):
        identity = ee.resolve_target("requests@2.31.0", "PyPI")
        with patch.object(ra, "_read", return_value=b'{"vulns":[]}'):
            report = ee.evaluate(identity["requested"], "consume", ecosystem="PyPI",
                                 evaluated_at=REMOTE_AT, acquire_remote=True)
        known = next(s for s in report["signals"] if s["name"] == "known_vulns")
        self.assertEqual(known["status"], "ok")
        self.assertEqual(known["raw"]["triage"][0]["package"]["ecosystem"], "PyPI")
        self.assertIn("malicious-code absence", known["finding"])
        self.assertEqual(report["remote_acquisition"]["advisories"], 0)
        self.assertEqual(report["remote_acquisition"]["freshness"], "current")
        self.assertEqual(known["captured_at"], report["remote_acquisition"]["fetched_at"])
        with patch.object(ra, "_read", return_value=b'{"vulns":[]}'):
            historical = ee.evaluate(identity["requested"], "consume", ecosystem="PyPI",
                                     evaluated_at=AT, acquire_remote=True)
        self.assertEqual(historical["remote_acquisition"]["freshness"], "future")
        self.assertEqual(next(s for s in historical["signals"] if
                              s["name"] == "known_vulns")["status"], "unknown")
        for response in (b'{"vulns":{}}',
                         b'{"vulns":[],"next_page_token":"x"}'):
            with self.subTest(response=response), \
                    patch.object(ra, "_read", side_effect=[response] * ra.MAX_PAGES):
                result = ee.evaluate(identity["requested"], "consume", ecosystem="PyPI",
                                     evaluated_at=REMOTE_AT, acquire_remote=True)
            known = next(s for s in result["signals"] if s["name"] == "known_vulns")
            self.assertEqual(known["status"], "error")
            self.assertIsNone(known["subscore"])

    def test_image_digest_preflight_and_explicit_invocation(self):
        identity = ee.resolve_target("ghcr.io/example/app@sha256:" + "f" * 64)
        with patch.object(ee, "_have", return_value=False), \
                patch.object(ee, "_run_remote") as run:
            missing = ee.evaluate(identity["requested"], "consume",
                                  evaluated_at=REMOTE_AT, acquire_remote=True)
        self.assertEqual(next(s for s in missing["signals"] if
                              s["name"] == "known_vulns")["status"], "unknown")
        run.assert_not_called()
        data = {"results": [{"source": {"path": "os:var/lib/dpkg/status"},
                             "packages": [{"package": {"ecosystem": "Debian:12",
                                                       "name": "example", "version": "1"},
                                           "vulnerabilities": []}]}]}

        def preflight(cmd, timeout=180):
            return process(0, "image scan supported") if cmd[:3] == [
                "osv-scanner", "scan", "image"] else process(0, "running")

        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run", side_effect=preflight), \
                patch.object(ee, "_run_remote",
                             return_value=process(0, json.dumps(data))) as run:
            report = ee.evaluate(identity["requested"], "consume", evaluated_at=REMOTE_AT,
                                 acquire_remote=True)
        self.assertEqual(next(s for s in report["signals"] if
                              s["name"] == "known_vulns")["status"], "ok")
        self.assertEqual(run.call_args.args[0][-1], identity["identifier"])
        self.assertIn("--no-call-analysis=go", run.call_args.args[0])
        self.assertIn("--no-resolve", run.call_args.args[0])
        with patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run_remote") as run:
            unsupported = ee.evaluate("registry.example/app@sha256:" + "e" * 64,
                                      "consume", evaluated_at=REMOTE_AT, acquire_remote=True)
        self.assertEqual(next(s for s in unsupported["signals"] if
                              s["name"] == "known_vulns")["status"], "error")
        run.assert_not_called()

    def test_remote_repo_commit_archive_scoped_paths_and_cleanup(self):
        commit = "a" * 40
        tar = BytesIO()
        with tarfile.open(fileobj=tar, mode="w:gz") as archive:
            contents = b'{"lockfileVersion":3}'
            directory = tarfile.TarInfo("repo-" + commit + "/nested/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            item = tarfile.TarInfo("repo-" + commit + "/nested/package-lock.json")
            item.size = len(contents)
            archive.addfile(item, BytesIO(contents))
        seen = []

        def scan(cmd, **kwargs):
            source = Path(cmd[-1])
            seen.append(source)
            self.assertTrue((source / "nested/package-lock.json").is_file())
            self.assertIn("--no-resolve", cmd)
            self.assertIn("--no-ignore", cmd)
            self.assertTrue(any(arg.startswith("--config=") for arg in cmd))
            result = {"results": [{"source": {"path": str(source / "nested/package-lock.json")},
                                   "packages": [{"package": {"ecosystem": "npm",
                                                             "name": "demo", "version": "1"},
                                                 "vulnerabilities": [{"id": "GHSA-123",
                                                                     "database_specific": {
                                                                         "severity": "HIGH"}}]}]}]}
            return process(1, json.dumps(result))

        def fetch(url, *, payload=None, limit=ra.MAX_RESPONSE):
            self.assertEqual(url, f"https://codeload.github.com/example/repo/tar.gz/{commit}")
            self.assertLessEqual(len(tar.getvalue()), limit)
            return tar.getvalue()

        with patch.object(ra, "_json", return_value={"sha": commit}), \
                patch.object(ra, "_read", side_effect=fetch), \
                patch.object(ee, "_have", return_value=True), \
                patch.object(ee, "_run_remote", side_effect=scan), \
                patch.object(ee, "_run", return_value=process(1)):
            report = ee.evaluate("example/repo@main", "consume", evaluated_at=REMOTE_AT,
                                 acquire_remote=True)
        self.assertFalse(seen[0].exists())
        self.assertEqual(report["target_identity"]["identifier"],
                         f"github.com/example/repo@{commit}")
        known = next(s for s in report["signals"] if s["name"] == "known_vulns")
        self.assertEqual(known["raw"]["findings"][0]["paths"],
                         ["nested/package-lock.json"])
        self.assertEqual(known["status"], "ok")
        self.assertEqual(known["raw"]["triage"][0]["package"]["name"], "demo")
        self.assertNotIn(str(seen[0]), json.dumps(report))
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            self.assertEqual(ee.replay(snapshot)["target_identity"], report["target_identity"])

    def test_remote_repo_archive_traversal_and_commit_mismatch_are_errors(self):
        commit = "a" * 40
        for entry_name, kind in (("repo-" + commit + "/../escape", tarfile.REGTYPE),
                                 ("repo-" + commit + "/link", tarfile.SYMTYPE)):
            with self.subTest(entry_name=entry_name):
                archive_bytes = BytesIO()
                with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                    item = tarfile.TarInfo(entry_name)
                    item.type = kind
                    item.size = 0
                    archive.addfile(item)
                with patch.object(ra, "_json", return_value={"sha": commit}), \
                        patch.object(ra, "_read", return_value=archive_bytes.getvalue()), \
                        patch.object(ee, "_have", return_value=False):
                    report = ee.evaluate("example/repo@main", "consume",
                                         evaluated_at=REMOTE_AT, acquire_remote=True)
                self.assertEqual(report["remote_acquisition"]["status"], "error")
                self.assertNotIn("commit", report["remote_acquisition"])
                self.assertEqual(next(s for s in report["signals"] if
                                      s["name"] == "scorecard")["status"], "unknown")
        with patch.object(ra, "_json", return_value={"sha": "b" * 40}), \
                patch.object(ra, "_read") as read:
            report = ee.evaluate("example/repo@" + commit, "consume", evaluated_at=REMOTE_AT,
                                 acquire_remote=True)
        self.assertEqual(report["remote_acquisition"]["status"], "error")
        read.assert_not_called()

    def test_remote_acquisition_opt_in_and_fixed_https_hosts(self):
        with patch.object(ra, "_read") as read, \
                patch.object(ra, "_json") as gh, \
                patch.object(ee, "_have", return_value=False):
            report = ee.evaluate("requests@2.31.0", "consume", ecosystem="PyPI",
                                 evaluated_at=AT)
            self.assertNotIn("remote_acquisition", report)
            self.assertEqual(next(s for s in report["signals"] if
                                  s["name"] == "known_vulns")["status"], "unknown")
            read.assert_not_called()
            gh.assert_not_called()
        for endpoint in ("http://api.osv.dev/v1/query",
                         "https://127.0.0.1/v1/query",
                         "https://user:token@api.github.com/repos/example/repo",
                         "https://api.osv.dev:8443/v1/query"):
            with self.subTest(endpoint=endpoint), \
                    self.assertRaises(ra.RemoteAcquisitionError):
                ra._read(endpoint)
        with self.assertRaises(ra.RemoteAcquisitionError):
            ra._NoRedirect().redirect_request(None, None, 302, "redirect", {},
                                               "http://127.0.0.1")

    def test_remote_scanner_process_is_time_and_output_bounded(self):
        complete = ee._run_remote([sys.executable, "-c", "print('json')"], timeout=2)
        self.assertEqual((complete.returncode, complete.stdout.strip()), (0, "json"))
        timeout = ee._run_remote([sys.executable, "-c", "import time; time.sleep(2)"],
                                 timeout=0.1)
        self.assertIsNone(timeout)
        oversized = ee._run_remote([sys.executable, "-c",
                                    "import sys; sys.stdout.write('x' * 9000000)"],
                                   timeout=2)
        self.assertNotEqual(oversized.returncode, 0)

    def test_archive_duplicate_and_size_limits_clean_up(self):
        commit = "a" * 40
        for entries in (
                [("repo-" + commit + "/file", b"x"),
                 ("repo-" + commit + "/file", b"y")],
                [("repo-" + commit + "/file", b"x" * (ra.MAX_FILE + 1))],
        ):
            with self.subTest(size=len(entries[-1][1])):
                archive_bytes = BytesIO()
                with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                    for name, content in entries:
                        item = tarfile.TarInfo(name)
                        item.size = len(content)
                        archive.addfile(item, BytesIO(content))
                seen = []
                original_extract = ra._extract

                def observe(raw, path):
                    seen.append(path)
                    return original_extract(raw, path)

                identity = ee.resolve_target("example/repo@" + commit)
                with patch.object(ra, "_json", return_value={"sha": commit}), \
                        patch.object(ra, "_read", return_value=archive_bytes.getvalue()), \
                        patch.object(ra, "_extract", side_effect=observe):
                    with self.assertRaises(ra.RemoteAcquisitionError):
                        with ra.acquire_repository(identity):
                            self.fail("Invalid archive was accepted")
                self.assertFalse(seen[0].exists())
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ra, "MAX_TAR_BYTES", 1024):
            with self.assertRaisesRegex(ra.RemoteAcquisitionError,
                                        "decompression size limit"):
                ra._extract(gzip.compress(b"\0" * 2048), Path(directory))

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
                    "name": "threat_coverage", "evidence_type": "manual_observation",
                    "facts": {"coverage": "partial"},
                    "source": "reviewed threat model", "captured_at": AT,
                    "tool": {"name": "manual", "version": "1"},
                }],
            }))
            with patch.object(ee, "_have", return_value=False):
                report = ee.evaluate(target, "produce", evidence, evaluated_at=AT)
            self.assertEqual(next(s for s in report["signals"] if s["name"] == "threat_coverage")
                             ["subscore"], 50)
            self.assertEqual(report["verdict"]["outcome"], "INCOMPLETE")
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(report))
            with patch.object(ee, "_run") as run:
                self.assertEqual(ee.replay(snapshot), report)
                run.assert_not_called()
            Path(target).rmdir()
            self.assertEqual(ee.replay(snapshot), report)
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

    def test_codeowners_proxy_reconciles_manual_review_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "target")
            Path(target).mkdir()
            (Path(target) / "CODEOWNERS").write_text("* @maintainer\n")
            evidence = Path(directory) / "evidence.json"
            evidence.write_text(json.dumps({
                "schema_version": 1, "target": target, "mode": "produce",
                "observations": [{
                    "name": "code_review", "evidence_type": "manual_observation",
                    "facts": {"required_reviews": True, "protected_default_branch": True},
                    "source": "branch settings reviewed", "captured_at": AT,
                    "tool": {"name": "manual", "version": "1"},
                }],
            }))
            with patch.object(ee, "_have", return_value=False):
                report = ee.evaluate(target, "produce", evidence, evaluated_at=AT)
            code_review = next(s for s in report["signals"] if s["name"] == "code_review")
            self.assertEqual(code_review["subscore"], 100)
            self.assertEqual(code_review["confidence"], "low")
            self.assertIn("CODEOWNERS", code_review["evidence_note"])
            self.assertIn("Evidence reconciliation", ee.to_markdown(report))
            submitted = json.loads(evidence.read_text())
            submitted["observations"][0]["evidence_type"] = "self_report"
            evidence.write_text(json.dumps(submitted))
            with patch.object(ee, "_have", return_value=False):
                self_report = ee.evaluate(target, "produce", evidence, evaluated_at=AT)
            code_review = next(s for s in self_report["signals"]
                               if s["name"] == "code_review")
            self.assertEqual(code_review["subscore"], 50)
            self.assertEqual(code_review["related_evidence"][0]["evidence_type"],
                             "self_report")

    def test_self_report_does_not_count_as_verified(self):
        item = {"name": "provenance", "facts": {"slsa_level": 3},
                "evidence_type": "self_report", "source": "project homepage",
                "captured_at": AT, "tool": {"name": "manual", "version": "1"}}
        result = ee._manual_signal(item)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["subscore"])

    def test_policy_v1_snapshot_cannot_silently_change_its_scoring(self):
        legacy = {
            "schema_version": 1, "policy_version": "1", "target": "example/repo",
            "target_kind": "repo", "target_identity": {
                "requested": "example/repo", "resolved": False},
            "mode": "consume", "evaluated_at": AT,
            "signals": [sig("scorecard", 92, raw={"aggregate": 9.2})],
            "actions": ["Review source"],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(legacy))
            with self.assertRaisesRegex(ValueError, "original policy version"):
                ee.replay(snapshot)


if __name__ == "__main__":
    unittest.main()
