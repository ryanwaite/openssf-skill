#!/usr/bin/env python3
"""
OpenSSF Ensemble Evaluator

Runs the OpenSSF tool *ensemble* against a target, normalizes each tool's output
into a 0-100 sub-score, fuses them with mode-specific weights, applies escalation
rules, and emits one decision-ready verdict.

This script is the executable counterpart to ``ensemble/risk-model.md`` — the
weights, normalization, and escalation logic here mirror that document exactly.

Design goals:
- **Graceful degradation.** Any tool that is not installed or cannot run yields
  an ``unknown`` signal (weight 0, surfaced in the report) rather than a crash.
- **No shell injection.** Every external command is invoked with an argument
  list; ``shell=True`` is never used.
- **Reproducible.** Same inputs -> same verdict.

Usage:
    python3 ensemble-eval.py --target <path|repo-url|pkg@ver> --mode consume|produce
    python3 ensemble-eval.py --target . --mode produce --format md

Output: fused JSON (default) or a Markdown report (``--format md``).
"""

import argparse
from datetime import datetime, timezone
import json
import math
import os
import re
import shlex
import shutil
import signal as signal_module
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from target_identity import resolve_target
from remote_acquisition import acquire_repository, query_package, RemoteAcquisitionError
from baseline_conformance import evaluate_conformance, load_evidence as load_baseline
from supplemental_evidence import (
    artifact_evidence, governance_inputs, read_document, reviewed_threat_input, vex_context,
)
from vulnerability_evidence import triage_osv_package
from project_governance import governance_evidence, maintenance_evidence

# --- Risk model constants (mirror ensemble/risk-model.md) --------------------

MODE_WEIGHTS: Dict[str, Dict[str, float]] = {
    "consume": {
        "known_vulns": 0.28 / 0.92,
        "maintenance": 0.22 / 0.92,
        "supply_chain": 0.16 / 0.92,
        "scorecard": 0.14 / 0.92,
        "provenance": 0.12 / 0.92,
    },
    "produce": {
        "secrets": 0.20 / 0.90,
        "provenance": 0.16 / 0.90,
        "code_review": 0.16 / 0.90,
        "scorecard": 0.14 / 0.90,
        "known_vulns": 0.12 / 0.90,
        "threat_coverage": 0.12 / 0.90,
    },
}

SEVERITY_DEDUCTION = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2,
                      "NONE": 0}
SCHEMA_VERSION = 1
POLICY_VERSION = "2"
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


# --- Signal helper -----------------------------------------------------------

def signal(name: str, status: str, subscore: Optional[float],
           confidence: str, finding: str, raw: Any = None,
           evidence_type: str = "observation", source: str = "",
           captured_at: Optional[str] = None,
           tool: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Build a normalized signal record."""
    return {
        "name": name,
        "status": status,           # ok | unknown | error
        "subscore": subscore,       # 0-100 or None
        "confidence": confidence,   # high | medium | low
        "finding": finding,
        "raw": raw,
        "evidence_type": evidence_type,
        "source": source or name,
        "captured_at": captured_at,
        "tool": tool,
    }


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _tool_version(tool: str) -> str:
    proc = _run([tool, "--version"], timeout=10)
    if proc and proc.returncode == 0:
        match = re.search(r"\bv?\d+\.\d+(?:\.\d+)?\b", proc.stdout[:256])
        if match:
            return match.group()
    return "unrecorded"


def _run(cmd: List[str], timeout: int = 180) -> Optional[subprocess.CompletedProcess]:
    """Run a command safely (no shell). Return None on failure/timeout."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _run_remote(cmd: List[str], *, timeout: int = 120) -> Optional[subprocess.CompletedProcess]:
    """Bound scanner output and time; never preserve scanner diagnostics or credentials."""
    try:
        import resource
    except ImportError:
        return None  # Base/local advice remains available without POSIX process limits.
    limit = 8 * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="openssf-scan-") as home:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "LANG": "C"}
        env.update({key: os.environ[key] for key in (
            "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy",
            "SSL_CERT_FILE", "SSL_CERT_DIR") if key in os.environ})
        try:
            with tempfile.TemporaryFile() as output:
                proc = subprocess.Popen(
                    cmd, stdout=output, stderr=subprocess.DEVNULL,
                    env=env, start_new_session=True,
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE,
                                                         (limit, limit)))
                try:
                    code = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal_module.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                    return None
                if output.tell() > limit:
                    return None
                output.seek(0)
                return subprocess.CompletedProcess(
                    cmd, code, output.read(limit).decode("utf-8", errors="replace"), "")
        except OSError:
            return None


# --- Probes ------------------------------------------------------------------
# Each probe returns a signal dict. When the underlying tool is unavailable the
# probe returns an `unknown` signal so the gap is surfaced, never hidden.

_SCORECARD_OVERLAP = {
    "consume": {"Vulnerabilities", "Maintained", "Signed-Releases", "Pinned-Dependencies"},
    "produce": {"Vulnerabilities", "Code-Review", "Branch-Protection", "Signed-Releases"},
}
_SCORECARD_CHECKS = {
    "Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices",
    "Code-Review", "Contributors", "Dangerous-Workflow", "Dependency-Update-Tool",
    "Fuzzing", "License", "Maintained", "Packaging", "Pinned-Dependencies",
    "SAST", "Security-Policy", "Signed-Releases", "Token-Permissions",
    "Vulnerabilities",
}


def probe_scorecard(target: str, is_repo: bool, identity: Optional[Dict[str, Any]] = None,
                    mode: str = "consume", evaluated_at: Optional[str] = None) -> Dict[str, Any]:
    repo = (identity or {}).get("repo") if identity else None
    if not repo and is_repo:
        repo = resolve_target(target).get("repo")
    if identity and identity["kind"] == "local_directory" and identity.get("git_dirty") is not False:
        return signal("scorecard", "unknown", None, "low",
                      "Local working tree is dirty or its status is unavailable; remote Scorecard "
                      "cannot represent its contents.")
    if not repo or not _have("scorecard"):
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard not run (needs `scorecard` CLI and a supported GitHub origin).")
    ref = ((identity or {}).get("git_commit") or (identity or {}).get("commit")
           or (identity or {}).get("ref"))
    cmd = ["scorecard", f"--repo={repo}", "--format=json"]
    if ref:
        cmd.append(f"--commit={ref}")
    proc = _run(cmd)
    if not proc or proc.returncode != 0 or not proc.stdout.strip():
        return signal("scorecard", "error", None, "low",
                      "Scorecard execution failed.")
    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, dict) or type(data.get("score")) not in (int, float):
            raise ValueError("Invalid aggregate")
        agg = data["score"]
        if not math.isfinite(agg) or not 0 <= agg <= 10 or \
                not isinstance(data.get("repo"), dict) or \
                data["repo"].get("name") != repo or \
                not isinstance(data.get("scorecard"), dict) or \
                not isinstance(data["scorecard"].get("version"), str) or \
                not data["scorecard"]["version"] or \
                not isinstance(data.get("checks"), list) or not data["checks"]:
            raise ValueError("Invalid Scorecard metadata or checks")
        checks = []
        names = set()
        for check in data["checks"]:
            if not isinstance(check, dict) or \
                    not isinstance(check.get("name"), str) or not check["name"] or \
                    check["name"] in names or type(check.get("score")) not in (int, float) or \
                    not math.isfinite(check["score"]) or \
                    (check["score"] != -1 and not 0 <= check["score"] <= 10) or \
                    not isinstance(check.get("reason"), str) or \
                    check.get("details") is not None and (
                        not isinstance(check["details"], list) or
                        not all(isinstance(item, str) for item in check["details"])):
                raise ValueError("Invalid Scorecard check")
            names.add(check["name"])
            checks.append({"name": check["name"], "score": check["score"],
                           "reason": check["reason"], "details": check.get("details"),
                           "overlaps": check["name"] in _SCORECARD_OVERLAP[mode]})
        commit = data["repo"].get("commit")
        captured = data.get("date")
        if commit is not None and (not isinstance(commit, str) or
                                   not re.fullmatch(r"[a-fA-F0-9]{40}", commit)):
            raise ValueError("Invalid Scorecard commit")
        if captured is not None:
            _utc(captured)
    except (json.JSONDecodeError, ValueError, TypeError, KeyError):
        return signal("scorecard", "error", None, "low",
                      "Could not parse Scorecard output.")
    omitted = sorted(_SCORECARD_CHECKS - names)
    raw = {"aggregate": agg, "repo": repo, "commit": commit, "date": captured,
           "version": data["scorecard"]["version"], "checks": checks,
           "excluded_overlap": sorted(_SCORECARD_OVERLAP[mode]),
           "omitted_checks": omitted,
           "permission_scope": "Branch-Protection admin-only settings and repository "
           "ruleset access may require additional permissions; not independently verified"}
    if not commit or not captured:
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard result lacks commit or capture date; revision/freshness unknown.",
                      raw=raw, source="Scorecard")
    expected = (identity or {}).get("git_commit") or (identity or {}).get("commit")
    if expected and commit.lower() != expected.lower():
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard returned a different commit than the requested target revision.",
                      raw=raw, source="Scorecard", captured_at=captured)
    if evaluated_at and (_utc(evaluated_at) - _utc(captured)).total_seconds() > 90 * 86400:
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard observation is over 90 days old; refresh before scoring.",
                      raw=raw, source="Scorecard", captured_at=captured)
    if evaluated_at and _utc(captured) > _utc(evaluated_at):
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard capture date is after evaluation time.",
                      raw=raw, source="Scorecard", captured_at=captured)
    available = [c["score"] for c in checks if not c["overlaps"] and c["score"] != -1]
    missing = [c["name"] for c in checks if c["score"] == -1]
    if not available or missing or omitted:
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard has unavailable checks (score -1) or omitted checks: "
                      + ", ".join(missing + omitted or ["no non-overlapping checks scored"]) + ".",
                      raw=raw, source="Scorecard", captured_at=captured)
    return signal("scorecard", "ok", round(10 * sum(available) / len(available), 1),
                  "medium", f"Scorecard aggregate {agg}/10; scored {len(available)} "
                  "non-overlapping checks, with per-check reasons preserved.",
                  raw=raw, source="Scorecard", captured_at=captured,
                  tool={"name": "scorecard", "version": data["scorecard"]["version"]})


def _cvss_vector_score(vector: str, kind: str) -> tuple:
    """Return a vetted parser's base score or a non-scoring reason."""
    versions = {"CVSS_V2": (("AV:",), "CVSS2"),
                "CVSS_V3": (("CVSS:3.0/", "CVSS:3.1/"), "CVSS3"),
                "CVSS_V4": (("CVSS:4.0/",), "CVSS4")}
    if kind not in versions:
        return None, "unsupported_vector"
    prefixes, parser_name = versions[kind]
    if len(vector) > 512 or not vector.startswith(prefixes):
        return None, "unsupported_vector"
    code = (
        "import sys\n"
        "from importlib.metadata import PackageNotFoundError, version\n"
        "try:\n"
        "    if version('cvss') != '3.6':\n"
        "        raise PackageNotFoundError\n"
        "    from cvss import CVSS2, CVSS3, CVSS4\n"
        "    from cvss.exceptions import CVSSError\n"
        "except (ImportError, PackageNotFoundError):\n"
        "    sys.exit(3)\n"
        "try:\n"
        "    print(globals()[sys.argv[1]](sys.argv[2]).scores()[0])\n"
        "except CVSSError:\n"
        "    sys.exit(4)\n"
    )
    proc = _run([sys.executable, "-I", "-c", code, parser_name, vector], timeout=10)
    if proc is None or proc.returncode == 3:
        return None, "parser_unavailable"
    if proc.returncode == 4:
        return None, "malformed_vector"
    if proc.returncode != 0:
        return None, "parser_error"
    try:
        score = float(proc.stdout.strip()) if len(proc.stdout) <= 32 else float("nan")
    except ValueError:
        return None, "invalid_computed_score"
    if not isinstance(score, (int, float)) or not math.isfinite(score) \
            or not 0 <= score <= 10:
        return None, "invalid_computed_score"
    return float(score), "computed"


def _severity(vuln: Dict[str, Any]) -> tuple:
    """Use published buckets/numeric CVSS or a vetted optional vector parser."""
    buckets = []
    base_scores = []
    unresolved = []
    severities = vuln.get("severity", [])
    if not isinstance(severities, list):
        raise ValueError("Invalid severity list")
    for item in severities:
        if not isinstance(item, dict):
            raise ValueError("Invalid severity entry")
        value = item.get("score")
        kind = item.get("type")
        if kind not in ("CVSS_V2", "CVSS_V3", "CVSS_V4"):
            unresolved.append("unsupported_type")
            continue
        if isinstance(value, str) and value.replace(".", "", 1).isdigit():
            number, status = float(value), "reported"
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            number, status = float(value), "reported"
        elif isinstance(value, str):
            number, status = _cvss_vector_score(value, kind)
        else:
            number, status = None, "missing_score"
        if number is None or not math.isfinite(number) or not 0 <= number <= 10:
            unresolved.append(status if number is None else "invalid_score")
            continue
        base_scores.append(number)
        buckets.append("NONE" if number == 0 else
                       "CRITICAL" if kind != "CVSS_V2" and number >= 9
                       else "HIGH" if number >= 7 else "MEDIUM" if number >= 4
                       else "LOW")
    for field in ("database_specific", "ecosystem_specific"):
        detail = vuln.get(field) or {}
        if isinstance(detail, dict):
            bucket = detail.get("severity")
            if isinstance(bucket, str) and bucket.upper() in SEVERITY_DEDUCTION:
                buckets.append(bucket.upper())
    if unresolved:
        # Preserve an independently supported blocking CRITICAL fact while
        # keeping the overall severity status unresolved and unscored.
        return ("CRITICAL" if "CRITICAL" in buckets else None,
                max(base_scores, default=None), sorted(unresolved)[0])
    return (max(buckets, key=lambda bucket: SEVERITY_DEDUCTION[bucket])
            if buckets else None,
            max(base_scores, default=None), "known" if buckets else "missing")


def _affected_ranges(vuln: Dict[str, Any], package: Dict[str, Any]) -> List[Dict[str, Any]]:
    ranges_out = []
    affected_list = vuln.get("affected", [])
    if not isinstance(affected_list, list):
        raise ValueError("Invalid affected list")
    for affected in affected_list:
        if not isinstance(affected, dict):
            raise ValueError("Invalid affected entry")
        identity = affected.get("package")
        if not isinstance(identity, dict):
            raise ValueError("Missing affected package identity")
        if any(identity.get(key) != package[key] for key in ("ecosystem", "name")):
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            raise ValueError("Invalid ranges")
        for item in ranges:
            if not isinstance(item, dict):
                continue
            if not isinstance(item.get("type", "unknown"), str):
                raise ValueError("Invalid range type")
            events = item.get("events", [])
            if not isinstance(events, list):
                raise ValueError("Invalid events")
            normalized = []
            for event in events:
                if not isinstance(event, dict):
                    raise ValueError("Invalid range event")
                for key in ("introduced", "last_affected", "fixed"):
                    if key in event:
                        if not isinstance(event[key], str):
                            raise ValueError("Invalid affected version")
                        normalized.append({key: event[key]})
            ranges_out.append({"type": item.get("type", "unknown"), "events": normalized})
    return ranges_out


def _osv_findings(data: Dict[str, Any], context: Optional[Dict[str, Any]] = None,
                  triage: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Collapse overlapping aliases/groups per package version across sources."""
    records: Dict[tuple, List[Dict[str, Any]]] = {}
    for result in data["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
            raise ValueError("Invalid result")
        source = result.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise ValueError("Missing source")
        for entry in result["packages"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict) \
                    or not isinstance(entry.get("vulnerabilities"), list):
                raise ValueError("Invalid package")
            pkg = entry["package"]
            if not all(isinstance(pkg.get(k), str) and pkg[k]
                       for k in ("name", "version", "ecosystem")):
                raise ValueError("Missing package identity")
            package_triage = triage_osv_package(pkg, entry["vulnerabilities"], **(context or {}))
            scoped_records = {record["id"]: record for finding in package_triage["findings"]
                              for record in finding["records"]}
            if triage is not None:
                triage.append(package_triage)
            groups = entry.get("groups", [])
            if not isinstance(groups, list):
                raise ValueError("Invalid groups")
            group_ids = []
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("ids"), list):
                    raise ValueError("Invalid group")
                group_ids.append(set(group["ids"]))
            key = (pkg["ecosystem"], pkg["name"], pkg["version"])
            bucket = records.setdefault(key, [])
            for vuln in entry["vulnerabilities"]:
                if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) \
                        or not vuln["id"] or not isinstance(vuln.get("aliases", []), list):
                    raise ValueError("Missing advisory identity")
                ids = {vuln["id"], *vuln.get("aliases", [])}
                if not all(isinstance(i, str) and i for i in ids):
                    raise ValueError("Invalid alias")
                for group in group_ids:
                    if ids & group:
                        ids.update(group)
                if vuln.get("withdrawn"):
                    continue
                severity, base_score, severity_status = _severity(vuln)
                affected = _affected_ranges({"affected": scoped_records[vuln["id"]]["affected"]}, pkg)
                fixes = [event["fixed"] for item in affected for event in item["events"]
                         if "fixed" in event]
                matching = [r for r in bucket if ids & set(r["aliases"])]
                for old in matching:
                    ids.update(old["aliases"])
                    fixes.extend(old["fixed_versions"])
                    affected.extend(old["affected_ranges"])
                    severity = max((x for x in (severity, old["severity"]) if x),
                                   key=lambda x: SEVERITY_DEDUCTION[x], default=None)
                    base_score = max((x for x in (base_score, old["cvss_base_score"])
                                      if x is not None), default=None)
                    if severity_status == "known":
                        severity_status = old["severity_status"]
                    bucket.remove(old)
                paths = {source["path"]}
                for old in matching:
                    paths.update(old["paths"])
                bucket.append({"id": sorted(ids)[0], "aliases": sorted(ids),
                               "ecosystem": key[0], "package": key[1],
                               "version": key[2], "severity": severity,
                               "cvss_base_score": base_score,
                               "severity_status": severity_status,
                               "fixed_versions": sorted(set(fixes)),
                               "fix_status": "available" if fixes else "unknown",
                               "affected_ranges": [json.loads(item) for item in sorted(
                                   {json.dumps(item, sort_keys=True) for item in affected})],
                               "paths": sorted(paths)})
    return sorted((r for bucket in records.values() for r in bucket),
                  key=lambda r: (r["ecosystem"], r["package"], r["version"], r["id"]))


def _osv_signal(data: Dict[str, Any], status_code: int,
                context: Optional[Dict[str, Any]] = None, *,
                source: str = "OSV-Scanner",
                root: Optional[Path] = None,
                all_packages: bool = False) -> Dict[str, Any]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    try:
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("Missing results")
        for result in data["results"]:
            if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
                raise ValueError("Missing packages")
            for entry in result["packages"]:
                if isinstance(entry, dict) and "vulnerabilities" not in entry and \
                        all_packages and not entry.get("groups") and \
                        isinstance(entry.get("package"), dict) and all(
                            isinstance(entry["package"].get(key), str) and entry["package"][key]
                            for key in ("ecosystem", "name", "version")):
                    entry["vulnerabilities"] = []
        if root:
            for result in data["results"]:
                path = result.get("source", {}).get("path")
                if not isinstance(path, str) or not path:
                    raise ValueError("Missing source path")
                candidate = Path(path)
                if candidate.is_absolute():
                    try:
                        candidate = candidate.relative_to(root)
                    except ValueError as exc:
                        raise ValueError("Scanner source outside acquired archive") from exc
                if any(part in ("..", ".") for part in candidate.parts) or \
                        not candidate.parts or not (root / candidate).is_file():
                    raise ValueError("Scanner source outside acquired archive")
                result["source"]["path"] = candidate.as_posix()
        triage = []
        findings = _osv_findings(data, context, triage)
        if not any(result["packages"] for result in data["results"]):
            return signal("known_vulns", "unknown", None, "low",
                          f"{source} reported no scanned package sources; coverage unknown.",
                          source=source)
        reported = any(entry["vulnerabilities"] for result in data["results"]
                       for entry in result["packages"])
        if (status_code == 0 and reported) or (status_code == 1 and not reported):
            raise ValueError("Exit/output mismatch")
        for finding in findings:
            if finding["severity"] and finding["severity_status"] == "known":
                counts[finding["severity"]] += 1
    except (TypeError, ValueError, KeyError):
        return signal("known_vulns", "error", None, "low",
                      f"{source} output or scope invalid; no clean result inferred.", source=source)
    score = 100
    for sev, n in counts.items():
        score -= sum(SEVERITY_DEDUCTION[sev] *
                     (2 if finding["fixed_versions"] else 1)
                     for finding in findings if finding["severity"] == sev)
    score = max(0, score)
    unknown = sum(f["severity_status"] != "known" for f in findings)
    return signal("known_vulns", "ok" if not unknown else "unknown",
                  score if not unknown else None, "high" if not unknown else "low",
                  f"{len(findings)} advisory group(s) ({counts['CRITICAL']}C/"
                  f"{counts['HIGH']}H/{counts['MEDIUM']}M/{counts['LOW']}L/"
                  f"{counts['NONE']}N/"
                  f"{unknown} unknown severity); "
                  + ("verify unknown severities before scoring; optional "
                     "`cvss==3.6` calculates supported vectors, while malformed "
                     "or missing data needs manual review." if unknown else
                     f"Severity and fix data from {source}."),
                  raw={"counts": counts, "findings": findings, "triage": triage},
                  source=source, tool={"name": "osv-scanner" if source == "OSV-Scanner"
                                       else "OSV API", "version": "unrecorded"
                                       if source == "OSV-Scanner" else "v1"})


def probe_known_vulns(target: str, is_local: bool,
                      identity: Optional[Dict[str, Any]] = None,
                      context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not is_local:
        return signal("known_vulns", "unknown", None, "low",
                      "OSV source scan needs a local directory or lockfile/SPDX file. "
                      "Repository URLs, package coordinates and OCI digests are not acquired or scanned.")
    if identity and identity["kind"] == "local_file" and identity["file_type"] == "file":
        return signal("known_vulns", "unknown", None, "low",
                      "OSV supports recognized lockfiles and SPDX files; this file format is unsupported.")
    if not _have("osv-scanner"):
        return signal("known_vulns", "unknown", None, "low",
                      "OSV-Scanner not installed.")
    cmd = ["osv-scanner", "scan", "source", "--format=json", "--all-packages",
           "--all-vulns", "--no-call-analysis=go"]
    if identity and identity["kind"] == "local_file":
        if identity["file_type"] == "spdx":
            cmd.extend(["-L", identity["path"]])
        else:
            cmd.append(f"--lockfile=:{identity['path']}")
    else:
        cmd.extend(["--recursive", target])
    proc = _run(cmd)
    if proc is None or proc.returncode not in (0, 1) or not proc.stdout.strip():
        return signal("known_vulns", "error", None, "low",
                      "OSV-Scanner failed or produced no JSON; no clean result inferred.")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return signal("known_vulns", "error", None, "low",
                      "OSV-Scanner exit status or JSON structure invalid; no clean result inferred.")
    return _osv_signal(data, proc.returncode, context, all_packages=True)


def _remote_known_vulns(identity: Dict[str, Any], context: Dict[str, Any],
                        source: Optional[Path] = None) -> Dict[str, Any]:
    kind = identity["kind"]
    if kind == "package":
        advisories, metadata = query_package(identity)
        package = {key: identity[key] for key in ("ecosystem", "name", "version", "purl")}
        data = {"results": [{"source": {"path": identity["purl"]},
                             "packages": [{"package": package,
                                           "vulnerabilities": advisories}]}]}
        result = _osv_signal(data, 1 if advisories else 0, context, source="OSV API")
        result["acquisition"] = metadata
        result["confidence"] = "medium" if result["status"] == "ok" else "low"
        result["finding"] += (" Exact-version advisories only; package contents, malicious-code "
                              "absence and dependency closure are not verified.")
        return result
    if os.name != "posix":
        return signal("known_vulns", "unknown", None, "low",
                      "Bounded remote source/image scanner execution currently requires a POSIX host; "
                      "local advice and exact-package API queries remain available.")
    if not _have("osv-scanner"):
        return signal("known_vulns", "unknown", None, "low",
                      "Install OSV-Scanner v2 for explicit remote source/image scanning.")
    if kind == "repo":
        with tempfile.TemporaryDirectory(prefix="openssf-osv-config-") as config_dir:
            config = Path(config_dir) / "empty.toml"
            config.write_text("", encoding="utf-8")
            cmd = ["osv-scanner", "scan", "source", "--format=json",
                   "--all-packages", "--all-vulns", "--no-call-analysis=go",
                   "--no-resolve", "--no-ignore",
                   f"--config={config}", "--recursive", str(source)]
            proc = _run_remote(cmd)
    elif kind == "image":
        image = identity["image"]
        registry = image.split("/", 1)[0].lower()
        if registry not in ("ghcr.io", "docker.io") or "/" not in image:
            return signal("known_vulns", "error", None, "low",
                          "Image registry unsupported; specify ghcr.io or docker.io explicitly "
                          "with an exact sha256 digest.")
        if not _have("docker"):
            return signal("known_vulns", "unknown", None, "low",
                          "Image scanning requires an installed, running Docker daemon; "
                          "start it explicitly or provide a local artifact.")
        available = _run(["docker", "info", "--format={{.ServerVersion}}"], timeout=10)
        capability = _run(["osv-scanner", "scan", "image", "--help"], timeout=10)
        if not available or available.returncode != 0 or not capability or \
                capability.returncode != 0 or "image" not in capability.stdout.lower():
            return signal("known_vulns", "unknown", None, "low",
                          "Docker daemon or OSV-Scanner image subcommand unavailable; "
                          "do not auto-start Docker.")
        cmd = ["osv-scanner", "scan", "image", "--format=json",
               "--all-packages", "--all-vulns", "--no-call-analysis=go",
               "--no-resolve", identity["identifier"]]
        proc = _run_remote(cmd)
    else:
        raise ValueError("Unsupported remote acquisition target")
    if proc is None or proc.returncode not in (0, 1) or not proc.stdout.strip():
        return signal("known_vulns", "error", None, "low",
                      "Explicit remote OSV scan failed, timed out or exceeded output limit; "
                      "no clean result inferred.")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return signal("known_vulns", "error", None, "low",
                      "Explicit remote OSV scan returned invalid JSON.")
    result = _osv_signal(data, proc.returncode, context,
                         root=source if kind == "repo" else None, all_packages=True)
    if kind == "image":
        result["acquisition"] = {
            "kind": "oci_digest_scan", "registry": registry,
            "digest": identity["digest"], "reference": identity["identifier"],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "scope": "OSV-Scanner image package inventory at requested digest; "
                     "manifest identity not independently attested",
        }
    return result


def probe_secrets(target: str, is_local: bool) -> Dict[str, Any]:
    if not is_local:
        return signal("secrets", "unknown", None, "low",
                      "Secrets scan needs a local checkout.")
    if not _have("gitleaks"):
        return signal("secrets", "unknown", None, "low",
                      "Gitleaks not installed.")
    scopes = ["dir"]
    if (Path(target) / ".git").exists():
        scopes.insert(0, "git")
    counts = {}
    with tempfile.TemporaryDirectory(prefix="openssf-gitleaks-") as temp:
        for scope in scopes:
            report_path = Path(temp) / f"{scope}.json"
            proc = _run(["gitleaks", scope, "--redact=100", "--report-format", "json",
                         "--report-path", str(report_path), "--no-banner", target])
            if proc is None or proc.returncode not in (0, 1) or \
                    "partial scan" in proc.stderr.lower() or \
                    "failed to scan" in proc.stderr.lower():
                return signal("secrets", "error", None, "low",
                              f"Gitleaks {scope} scan failed; no clean result inferred.")
            try:
                findings = json.loads(report_path.read_text(encoding="utf-8"))
                if findings is None and proc.returncode == 0:
                    findings = []  # Gitleaks serializes a nil clean slice as JSON null.
                if not isinstance(findings, list) or not all(isinstance(x, dict) for x in findings):
                    raise ValueError("Invalid report")
                if (proc.returncode == 0 and findings) or (proc.returncode == 1 and not findings):
                    raise ValueError("Exit/report mismatch")
            except (OSError, ValueError, json.JSONDecodeError):
                return signal("secrets", "error", None, "low",
                              f"Gitleaks {scope} report missing, malformed, or inconsistent.")
            counts[scope] = len(findings)
    count = sum(counts.values())
    return signal("secrets", "ok", 50 if count else 100, "medium",
                  f"{count} potential secret finding(s) across {', '.join(scopes)}; "
                  + ("verify and rotate if live." if count else "no findings in scanned scopes."),
                  raw={"potential_count": count, "scopes": counts, "verified_live": False},
                  source="Gitleaks", tool={"name": "gitleaks", "version": "unrecorded"})


def probe_maintenance(target: str, is_local: bool,
                      evaluated_at: Optional[str] = None) -> Dict[str, Any]:
    """Use git history (local) or gh API (repo) to gauge activity."""
    if is_local and (Path(target) / ".git").exists():
        proc = _run(["git", "-C", target, "log", "-1", "--format=%ct"])
        if proc and proc.returncode == 0 and proc.stdout.strip().isdigit():
            at = _utc(evaluated_at) if evaluated_at else datetime.now(timezone.utc)
            committed = datetime.fromtimestamp(int(proc.stdout.strip()), timezone.utc)
            if committed > at:
                return signal("maintenance", "unknown", None, "low",
                              "Latest commit is after the evaluation time; recency is not established.")
            age_days = (at - committed).total_seconds() / 86400
            if age_days <= 90:
                return signal("maintenance", "ok", 100, "medium",
                              f"Last commit {int(age_days)}d ago.")
            if age_days <= 365:
                return signal("maintenance", "ok", 75, "medium",
                              f"Last commit {int(age_days)}d ago (slowing).")
            return signal("maintenance", "ok", 50, "medium",
                          f"Last commit {int(age_days)}d ago (stale).")
    if (not is_local) and _have("gh"):
        repo = target.replace("https://github.com/", "").rstrip("/")
        proc = _run(["gh", "api", f"repos/{repo}", "--jq",
                     "{archived:.archived, pushed:.pushed_at}"])
        if proc and proc.returncode == 0 and proc.stdout.strip():
            try:
                meta = json.loads(proc.stdout)
                if not isinstance(meta, dict) or type(meta.get("archived")) is not bool:
                    raise ValueError("Invalid metadata")
                if meta.get("archived"):
                    return signal("maintenance", "ok", 0, "high",
                                  "Repository is ARCHIVED.", raw=meta)
                pushed = _utc(meta["pushed"])
                at = _utc(evaluated_at) if evaluated_at else datetime.now(timezone.utc)
                if pushed > at:
                    raise ValueError("Push timestamp is after the evaluation time")
                age = (at - pushed).days
                score = 100 if age <= 90 else 75 if age <= 365 else 50
                return signal("maintenance", "ok", score, "low",
                              f"Last push {age}d ago (release cadence and bus factor unverified).",
                              raw=meta, source="GitHub API")
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                pass
    return signal("maintenance", "unknown", None, "low",
                  "Could not determine maintenance signals.")


def _placeholder(name: str, hint: str) -> Dict[str, Any]:
    """Probes whose tooling integration is environment-specific.

    These return `unknown` by default so the agent knows to run them manually
    or import a structured observation with --evidence; they remain un-run
    rather than fabricating a score.
    """
    return signal(name, "unknown", None, "low", hint)


def probe_supply_chain(target: str) -> Dict[str, Any]:
    return _placeholder("supply_chain",
                        "Generate an SPDX SBOM (syft/spdx-sbom-generator) and assess "
                        "transitive risk; import counts with --evidence.")


def probe_provenance(target: str) -> Dict[str, Any]:
    return _placeholder("provenance",
                        "Check SLSA level and verify signatures with "
                        "`cosign verify`; import the observed level with --evidence.")


def probe_threat_coverage(target: str) -> Dict[str, Any]:
    return _placeholder("threat_coverage",
                        "Review STRIDE threat model coverage; import observation with --evidence.")


def probe_code_review(target: str, is_local: bool) -> Dict[str, Any]:
    if is_local:
        co = Path(target)
        has_codeowners = any((co / p).exists() for p in
                             ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"))
        if has_codeowners:
            return signal("code_review", "unknown", None, "low",
                          "CODEOWNERS present; required reviews and effective protection remain unknown.",
                          raw={"codeowners_present": True}, source="local files")
    return _placeholder("code_review",
                        "Confirm required reviews + protected default branch.")


# --- Fusion ------------------------------------------------------------------

def fuse(signals: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    weights = MODE_WEIGHTS[mode]
    names = [s["name"] for s in signals]
    if len(set(names)) != len(names) or any(name not in weights for name in names):
        raise ValueError("Signals must have unique, mode-applicable names")
    for s in signals:
        score = s["subscore"]
        if s["status"] not in ("ok", "unknown", "error") or \
                (s["status"] == "ok") != (score is not None):
            raise ValueError("Invalid signal status/score")
        if score is not None and (isinstance(score, bool) or
                                  not isinstance(score, (int, float)) or
                                  not math.isfinite(score) or not 0 <= score <= 100):
            raise ValueError("Signal subscore outside 0-100")
    usable = [s for s in signals
              if s["status"] == "ok"]
    active_weight = sum(weights[s["name"]] for s in usable)

    if active_weight == 0:
        base = None
    else:
        base = sum(s["subscore"] * (weights[s["name"]] / active_weight)
                   for s in usable)
        base = round(base, 1)

    escalations = _escalations(signals)
    capped = base
    cap_label = None
    # Apply the most severe cap.
    caps = {"critical": 0, "high": 54, "medium": 69}
    for esc in escalations:
        level = esc["caps_at"]
        if level == "critical":
            capped, cap_label = 0, esc["rule"]
            break
        ceiling = caps[level]
        if capped is None and (level == "high" or cap_label is None):
            cap_label = esc["rule"]
        if capped is not None and capped > ceiling:
            capped, cap_label = ceiling, esc["rule"]

    provisional = _outcome(capped, mode, escalations)
    complete = len(signals) == len(weights) and all(s["status"] == "ok" for s in signals)
    # Missing evidence must not turn a renormalized average into a positive verdict.
    blocking = bool(escalations) and (
        (mode == "consume" and provisional == "Avoid") or
        (mode == "produce" and provisional == "F"))
    outcome = provisional if complete or blocking else "INCOMPLETE"
    confidence = _confidence(signals, complete)

    return {
        "mode": mode,
        "base_score": base,
        "final_score": capped,
        "escalations": escalations,
        "cap_applied": cap_label,
        "outcome": outcome,
        "provisional_outcome": provisional if not complete else None,
        "complete": complete,
        "confidence": confidence,
        "risk_tier": min((e["caps_at"] for e in escalations),
                         key=lambda level: {"critical": 0, "high": 1, "medium": 2}[level],
                         default="not assigned"),
        "active_weight_covered": round(active_weight, 2),
        "effective_weights": {
            s["name"]: round(weights[s["name"]] / active_weight, 6)
            for s in usable
        } if active_weight else {},
    }


def _escalations(signals: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    out = []
    by = {s["name"]: s for s in signals}
    sec = by.get("secrets")
    if sec and sec["status"] == "ok" and sec.get("evidence_type") == "verified_finding" \
            and isinstance(sec.get("raw"), dict) and sec["raw"].get("verified_live") is True:
        out.append({"rule": "Verified live secret exposed", "caps_at": "critical"})
    kv = by.get("known_vulns")
    if kv and isinstance(kv.get("raw"), dict) and any(
            finding.get("severity") == "CRITICAL" and finding.get("fixed_versions")
            for finding in kv["raw"].get("findings", [])):
        out.append({"rule": "Unpatched CRITICAL vulnerability with fix", "caps_at": "high"})
    mnt = by.get("maintenance")
    if mnt and mnt["status"] == "ok" and isinstance(mnt.get("raw"), dict) \
            and mnt["raw"].get("critical_dependency") is True \
            and (mnt["raw"].get("archived") is True or mnt["raw"].get("eol") is True
                 or mnt["raw"].get("unmaintained_over_year") is True):
        out.append({"rule": "Archived / EOL critical dependency", "caps_at": "high"})
    prov = by.get("provenance")
    if prov and prov["status"] == "ok" and prov.get("evidence_type") == "verified_finding" \
            and isinstance(prov.get("raw"), dict) \
            and prov["raw"].get("distributing_binaries") is True \
            and prov["raw"].get("releases_signed") is False \
            and prov["raw"].get("slsa_level") in (0, 1):
        out.append({"rule": "Unsigned low-provenance binaries", "caps_at": "medium"})
    return out


def _outcome(score: Optional[float], mode: str,
             escalations: List[Dict[str, str]]) -> str:
    if any(e["caps_at"] in ("critical", "high") for e in escalations):
        return "Avoid" if mode == "consume" else "F"
    if score is None:
        return "INSUFFICIENT DATA"
    if mode == "consume":
        if any(e["caps_at"] == "critical" for e in escalations) or score < 55:
            return "Avoid"
        if score < 80:
            return "Adopt with mitigations"
        return "Adopt"
    # produce
    if any(e["caps_at"] == "critical" for e in escalations) or score < 60:
        return "F"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    return "D"


def _confidence(signals: List[Dict[str, Any]], complete: bool) -> str:
    if not complete or any(s["confidence"] == "low" for s in signals):
        return "low"
    if any(s["confidence"] == "medium" for s in signals):
        return "medium"
    return "high"


# --- Orchestration -----------------------------------------------------------

def _github_request(path: str) -> Dict[str, Any]:
    """Read bounded GitHub JSON with existing gh credentials, without changing settings."""
    if not _have("gh"):
        raise OSError("GitHub CLI is not installed")
    proc = _run(["gh", "api", "--hostname", "github.com", "--method", "GET",
                 "--include", path], timeout=30)
    if proc is None or len(proc.stdout.encode("utf-8")) > 1_000_000:
        raise OSError("GitHub response unavailable or too large")
    header, separator, body = proc.stdout.replace("\r\n", "\n").partition("\n\n")
    match = re.match(r"HTTP/[\d.]+\s+(\d{3})\b", header)
    if not separator or not match:
        raise OSError("GitHub response headers unavailable")
    status = int(match.group(1))
    data = None
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise OSError("GitHub returned invalid JSON") from exc
    links = [line.partition(":")[2] for line in header.splitlines()
             if line.lower().startswith("link:")]
    return {"status": status, "data": data,
            "next": any('rel="next"' in link for link in links)}


def _fetch_project_evidence(identity: Dict[str, Any],
                             branch: Optional[str] = None) -> Dict[str, Any]:
    """Fetch exact-branch controls and limited activity facts only after explicit opt-in."""
    repo = identity.get("repo")
    if not isinstance(repo, str) or not re.fullmatch(
            r"github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("--fetch-governance requires a supported GitHub repository or local origin")
    base = "/repos/" + repo.removeprefix("github.com/")
    cache = {}
    deadline = time.monotonic() + 90

    def request(path):
        if not (path == base or path.startswith(base + "/")) or \
                ".." in path or "://" in path:
            raise ValueError("Governance request is outside the selected repository")
        if path not in cache:
            if len(cache) >= 40 or time.monotonic() >= deadline:
                raise OSError("GitHub governance request budget exceeded")
            cache[path] = _github_request(path)
        return cache[path]

    try:
        governance = governance_evidence(identity, None, request=request, branch=branch)
        at = governance["facts"]["evaluated_at"]
        metadata = cache.get(base, {})
        data = metadata.get("data") if metadata.get("status") == 200 else None
        evidence = {
            "schema_version": 1, "target": repo,
            "revision": identity.get("git_commit") or identity.get("commit") or identity.get("ref"),
            "captured_at": at,
        }
        if isinstance(data, dict) and type(data.get("archived")) is bool:
            evidence["repository"] = {
                "archived": data["archived"], "pushed_at": data.get("pushed_at"),
            }
        ref = identity.get("git_commit") or identity.get("commit") or \
            identity.get("ref") or governance["facts"].get("branch")
        if ref:
            latest = request(f"{base}/commits/{quote(ref, safe='')}")
            commit = latest.get("data")
            if latest["status"] == 200 and isinstance(commit, dict):
                detail = commit.get("commit")
                committer = detail.get("committer") if isinstance(detail, dict) else None
                author = commit.get("author")
                if isinstance(committer, dict) and committer.get("date"):
                    evidence["latest_commit"] = {
                        "committed_at": committer["date"],
                        "author_type": author.get("type", "unknown") if isinstance(author, dict)
                        else "unknown",
                    }
        release = request(f"{base}/releases/latest")
        if release["status"] == 200 and isinstance(release.get("data"), dict):
            evidence["latest_release"] = {
                key: release["data"].get(key)
                for key in ("tag_name", "draft", "prerelease", "published_at")
            }
        at = datetime.now(timezone.utc).isoformat()
        evidence["captured_at"] = at
        maintenance = maintenance_evidence(identity, at, evidence)
        maintenance["provenance"]["evidence_type"] = "injected_read_only_request"
        return {"governance": governance, "maintenance": maintenance}
    except OSError:
        return {"governance": {
            "status": "unknown", "facts": {}, "provenance": {
                "evidence_type": "injected_read_only_request", "authenticated_by_module": False},
            "gaps": ["GitHub read-only lookup unavailable; check gh access or supply an offline snapshot."],
            "limitations": ["Unavailable API access or exhausted request budgets do not prove "
                            "that controls are absent."],
        }}


def _apply_project_evidence(signals: List[Dict[str, Any]],
                            observations: Dict[str, Any]) -> None:
    """Map only established predicates; preserve richer context without inventing assurance."""
    for current in signals:
        key = {"code_review": "governance", "maintenance": "maintenance",
               "threat_coverage": "threat_model"}.get(current["name"])
        if key not in observations:
            continue
        observation = observations[key]
        facts = observation["facts"]
        current.setdefault("contextual_evidence", {})[key] = observation
        if key == "governance":
            protected, reviews = facts.get("protected_branch"), facts.get("required_reviews")
            primary = facts.get("branch") == facts.get("default_branch") and facts.get("branch")
            if observation["status"] == "ok" and primary and \
                    type(protected) is bool and type(reviews) is bool:
                imported = observation.get("provenance", {}).get("evidence_type") == "caller_supplied_snapshot"
                current.update(
                    status="ok", subscore=50 * (protected + reviews),
                    confidence="low" if imported else "medium",
                    evidence_type="manual_observation" if imported else "observation",
                    finding="Effective primary-branch protection and required review predicates assessed; "
                            "individual review execution is not proven.",
                    raw=facts, captured_at=facts.get("captured_at"),
                    source="Imported GitHub settings" if imported else "GitHub settings API",
                    tool={"name": "manual" if imported else "gh", "version": "unrecorded"},
                )
            else:
                current.update(status="unknown", subscore=None, confidence="low",
                               finding="Effective primary-branch review controls remain partial or unknown; "
                                       "inspect bypass, permission, and branch-scope gaps.",
                               raw=facts)
        elif key == "maintenance":
            support = facts.get("support", {})
            if facts.get("archived") is True or (support.get("status") == "eol" and
                                                 support.get("evidence_type") == "manual_observation"):
                current.update(status="ok", subscore=0, confidence="low",
                               finding="Archive or reviewed end-of-support evidence reported; "
                                       "confirm the applicable scope and mitigations.",
                               raw=facts, captured_at=facts.get("captured_at"))
            # Release age, bots and contributor counts are not a maintainer/bus-factor score.
        elif key == "threat_model":
            current.update(status="unknown", subscore=None, confidence="low",
                           finding="Reviewed threat-model areas are recorded; whole-project coverage "
                                   "is not established by a partial area review.", raw=facts)


def _utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Expected an ISO-8601 timestamp with timezone")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ValueError("Expected an ISO-8601 timestamp with timezone") from exc
    if date.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return date.astimezone(timezone.utc)


def _nonnegative(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Evidence counts must be non-negative integers")
    return value


def _manual_signal(item: Dict[str, Any]) -> Dict[str, Any]:
    name = item["name"]
    if name == "baseline":
        raise ValueError("Baseline is separate from policy v2; use --baseline-evidence "
                         "with requirement-level conformance observations")
    facts = item["facts"]
    if not isinstance(facts, dict) or item["evidence_type"] not in (
            "manual_observation", "self_report"):
        raise ValueError("Invalid manual evidence type or facts")
    fields = {
        "supply_chain": {"direct_high_critical", "transitive_high_critical",
                         "pinned_lockfile"},
        "provenance": {"slsa_level"},
        "threat_coverage": {"coverage"},
        "code_review": {"required_reviews", "protected_default_branch"},
    }
    if name not in fields or set(facts) != fields[name]:
        raise ValueError("Unsupported or extra manual evidence facts")
    tool = item["tool"]
    if not isinstance(tool, dict) or not all(
            isinstance(tool.get(k), str) and tool[k] for k in ("name", "version")):
        raise ValueError("Evidence needs tool name and version (use 'manual' for manual review)")
    _utc(item["captured_at"])
    if not isinstance(item["source"], str) or not item["source"].strip():
        raise ValueError("Evidence needs a source description")
    if name == "supply_chain":
        direct = _nonnegative(facts["direct_high_critical"])
        transitive = _nonnegative(facts["transitive_high_critical"])
        if type(facts["pinned_lockfile"]) is not bool:
            raise ValueError("pinned_lockfile must be boolean")
        score = min(100, max(0, 100 - 5 * direct - 2 * transitive)
                    + (10 if facts["pinned_lockfile"] else 0))
        finding = f"{direct} direct and {transitive} transitive high/critical dependencies."
    elif name == "provenance":
        level = facts["slsa_level"]
        if type(level) is not int or level not in (0, 1, 2, 3):
            raise ValueError("slsa_level must be 0..3")
        score = {0: 10, 1: 40, 2: 70, 3: 100}[level]
        finding = f"Reported SLSA level {level}; artifact verification not performed by evaluator."
    elif name == "threat_coverage":
        coverage = facts["coverage"]
        if coverage not in ("current", "partial", "none"):
            raise ValueError("Threat coverage must be current, partial, or none")
        score = {"current": 100, "partial": 50, "none": 0}[coverage]
        finding = f"Threat model coverage: {coverage} (manual observation)."
    elif name == "code_review":
        if type(facts["required_reviews"]) is not bool or \
                type(facts["protected_default_branch"]) is not bool:
            raise ValueError("Code review facts must be booleans")
        score = 50 * (facts["required_reviews"] + facts["protected_default_branch"])
        finding = "Required reviews and protected branch assessed manually."
    if item["evidence_type"] == "self_report":
        return signal(name, "unknown", None, "low",
                      f"Self-reported {finding} Requires independent confirmation.",
                      raw=facts, evidence_type="self_report", source=item["source"],
                      captured_at=item["captured_at"], tool=tool)
    return signal(name, "ok", score, "low", finding, raw=facts,
                  evidence_type="manual_observation", source=item["source"],
                  captured_at=item["captured_at"], tool=tool)


def _import_evidence(path: Path, target: str, mode: str) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION \
            or data.get("target") != target or data.get("mode") != mode \
            or not isinstance(data.get("observations"), list):
        raise ValueError("Evidence schema, target, or mode mismatch")
    result = {}
    for item in data["observations"]:
        if not isinstance(item, dict):
            raise ValueError("Evidence observations must be objects")
        s = _manual_signal(item)
        if s["name"] in result or s["name"] not in MODE_WEIGHTS[mode]:
            raise ValueError("Duplicate or inapplicable evidence signal")
        result[s["name"]] = s
    return result


def _actions(signals: List[Dict[str, Any]], target: str,
             target_kind: str) -> List[str]:
    actions = []
    for s in signals:
        if s["name"] == "secrets" and s["status"] == "ok" \
                and s["raw"].get("potential_count"):
            actions.append("Review Gitleaks findings locally; rotate any verified live credentials and investigate exposure.")
        if s["name"] == "known_vulns" and isinstance(s.get("raw"), dict):
            for f in s["raw"].get("findings", []):
                if f["fixed_versions"]:
                    actions.append(f"Upgrade {f['package']}@{f['version']} past "
                                   f"{', '.join(f['fixed_versions'])} for {f['id']}.")
                else:
                    actions.append(f"Investigate {f['id']} in {f['package']}@{f['version']}; "
                                   "confirm severity and available fixes.")
    scorecard = next((s for s in signals if s["name"] == "scorecard"), None)
    if scorecard and scorecard["status"] == "ok" and isinstance(scorecard.get("raw"), dict):
        for check in scorecard["raw"].get("checks", []):
            if check["score"] == 0 and not check["overlaps"]:
                actions.append(f"Investigate Scorecard {check['name']}: {check['reason']}")
    if not actions:
        if target_kind in ("local", "local_directory"):
            inventory = Path(__file__).resolve().with_name("assess-project.py")
            actions.append("Inventory local dependencies and existing security artifacts "
                           f"with `python3 {shlex.quote(str(inventory))} "
                           f"{shlex.quote(target)}`; review "
                           "the highest-impact finding before installing optional scanners.")
        else:
            actions.append("Identify the exact upstream artifact and dependency version; "
                           "review available advisories before choosing optional scanners.")
    return actions[:10]


def _report(target: str, mode: str, signals: List[Dict[str, Any]],
            evaluated_at: str, target_kind: str,
            target_identity: Dict[str, Any]) -> Dict[str, Any]:
    at = _utc(evaluated_at)
    for s in signals:
        captured = s.get("captured_at")
        s["age_days"] = round((at - _utc(captured)).total_seconds() / 86400, 1) \
                        if captured else None
    verdict = fuse(signals, mode)
    return {
        "schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
        "target": target,
        "target_kind": target_kind,
        "target_identity": target_identity,
        "mode": mode, "evaluated_at": evaluated_at,
        "signals": signals, "verdict": verdict,
        "gaps": [{"signal": s["name"], "reason": s["finding"]}
                 for s in signals if s["status"] != "ok"],
        "actions": _actions(signals, target, target_kind),
    }


def evaluate(target: str, mode: str, evidence: Optional[Path] = None,
             evaluated_at: Optional[str] = None,
             ecosystem: Optional[str] = None, *,
             baseline_evidence: Optional[Path] = None,
             artifact_input: Optional[Path] = None,
             vex_input: Optional[Path] = None,
             allow_network_trust: bool = False,
             acquire_remote: bool = False,
             governance_input: Optional[Path] = None,
             threat_input: Optional[Path] = None,
             fetch_governance: bool = False,
             governance_branch: Optional[str] = None) -> Dict[str, Any]:
    if fetch_governance and (governance_input or evaluated_at):
        raise ValueError("Live governance cannot be combined with an offline settings input or --at; "
                         "capture live settings now, then replay the snapshot")
    if governance_branch and not fetch_governance:
        raise ValueError("--governance-branch requires --fetch-governance")
    evaluated_at = evaluated_at or datetime.now(timezone.utc).isoformat()
    _utc(evaluated_at)
    identity = resolve_target(target, ecosystem)
    is_repo = identity["kind"] == "repo"
    is_local = identity["kind"] in ("local_directory", "local_file")
    is_dir = identity["kind"] == "local_directory"
    scan_path = identity.get("path", target)
    context = vex_context(vex_input, target) if vex_input else {}
    context["as_of"] = evaluated_at
    project = governance_inputs(governance_input, target, identity, evaluated_at) \
        if governance_input else {}
    if fetch_governance:
        project = _fetch_project_evidence(identity, governance_branch)
        evaluated_at = datetime.now(timezone.utc).isoformat()
        context["as_of"] = evaluated_at
    if threat_input:
        project["threat_model"] = reviewed_threat_input(
            threat_input, target, identity, evaluated_at)

    acquisition = None
    acquired_signal = None
    if acquire_remote:
        if identity["kind"] not in ("repo", "package", "image"):
            raise ValueError("--acquire-remote requires a GitHub repository, exact package, or OCI digest")
        try:
            if identity["kind"] == "repo":
                with acquire_repository(identity) as (source, acquisition):
                    identity.update(commit=acquisition["commit"],
                                    identifier=f"{identity['repo']}@{acquisition['commit']}",
                                    resolved=True, immutable=True, verified=False)
                    acquired_signal = _remote_known_vulns(identity, context, source)
            else:
                acquired_signal = _remote_known_vulns(identity, context)
                acquisition = acquired_signal.get("acquisition")
        except RemoteAcquisitionError as exc:
            acquisition = {"kind": identity["kind"], "requested": target,
                           "status": "error", "reason": str(exc),
                           "scope": "remote acquisition incomplete; no scan inferred"}
            acquired_signal = signal("known_vulns", "error", None, "low",
                                     f"Remote acquisition failed: {exc}")
        if acquisition:
            acquisition["requested"] = target
            acquisition["status"] = acquired_signal["status"]
            acquired_signal["acquisition"] = acquisition
        elif acquired_signal:
            acquisition = {"kind": identity["kind"], "requested": target,
                           "status": acquired_signal["status"],
                           "scope": "remote acquisition unavailable; no scan inferred"}
            acquired_signal["acquisition"] = acquisition
        if acquisition.get("fetched_at"):
            captured = acquisition["fetched_at"]
            age_seconds = (_utc(evaluated_at) - _utc(captured)).total_seconds()
            acquisition["age_days"] = round(age_seconds / 86400, 1)
            acquisition["freshness"] = ("future" if age_seconds < -300 else
                                        "stale" if age_seconds > 90 * 86400
                                        else "current")
            acquired_signal["captured_at"] = captured
            if acquired_signal["status"] == "ok" and acquisition["freshness"] != "current":
                acquired_signal.update(status="unknown", subscore=None, confidence="low",
                                       finding=acquired_signal["finding"] + " Remote evidence is "
                                       + acquisition["freshness"] + " relative to --at; "
                                       "rerun with a current evaluation time.")
                acquisition["status"] = "unknown"

    signals = [
        (signal("scorecard", "unknown", None, "low",
                "Could not resolve the requested GitHub ref to a verified commit; "
                "Scorecard default HEAD is not a substitute.")
         if acquire_remote and is_repo and not identity.get("verified") and not
         (acquisition and acquisition.get("commit"))
         else probe_scorecard(target, is_repo, identity, mode, evaluated_at)),
        acquired_signal if acquired_signal else
        probe_known_vulns(scan_path, is_local, identity, context),
        probe_provenance(target),
    ]
    if mode == "consume":
        if is_dir or is_repo:
            maintenance_target = identity["path"] if is_dir else \
                identity["repo"].removeprefix("github.com/")
            maintenance = (signal("maintenance", "unknown", None, "low",
                                  "Acquired commit archive has no git history; "
                                  "review public repository maintenance separately.")
                           if acquire_remote and is_repo else
                           probe_maintenance(maintenance_target, is_dir, evaluated_at))
        else:
            maintenance = signal("maintenance", "unknown", None, "low",
                                 "Repository maintenance needs a local checkout or GitHub repo; "
                                 "package and image coordinates have no verified source repository.")
        signals[2:2] = [maintenance, probe_supply_chain(target)]
    if mode == "produce":
        signals += [
            probe_secrets(scan_path, is_dir),
            probe_code_review(scan_path, is_dir),
            probe_threat_coverage(target),
        ]

    if evidence:
        imported = _import_evidence(evidence, target, mode)
        merged = []
        for s in signals:
            observation = imported.get(s["name"])
            if not observation:
                merged.append(s)
            elif s["name"] == "code_review" and observation["status"] == "ok" and \
                    isinstance(s.get("raw"), dict) and s["raw"].get("codeowners_present"):
                observation["finding"] += (" Local CODEOWNERS presence also observed; "
                                           "this replaces only the CODEOWNERS proxy.")
                observation["evidence_note"] = "Manual observation reconciled with local CODEOWNERS."
                observation["related_evidence"] = [{
                    "evidence_type": s["evidence_type"], "source": s["source"],
                    "finding": s["finding"], "captured_at": s["captured_at"],
                }]
                merged.append(observation)
            elif s["name"] == "code_review" and observation["status"] == "unknown" and \
                    isinstance(s.get("raw"), dict) and s["raw"].get("codeowners_present"):
                s["evidence_note"] = ("Self-report received but not scored; "
                                      "local CODEOWNERS indicator remains unverified.")
                s["related_evidence"] = [observation]
                merged.append(s)
            elif s["status"] != "ok":
                merged.append(observation)
            else:
                raise ValueError("Manual evidence conflicts with an already measured signal")
        signals = merged
    _apply_project_evidence(signals, project)
    for s in signals:
        if s["status"] == "ok" and not s["captured_at"]:
            s["captured_at"] = evaluated_at
        if s["status"] == "ok" and not s["tool"]:
            tool_name = {"maintenance": "git" if is_dir else "gh",
                         "scorecard": "scorecard", "code_review": "local files"}.get(s["name"])
            if tool_name:
                s["tool"] = {"name": tool_name, "version":
                             _tool_version(tool_name) if tool_name not in ("local files",)
                             else "not applicable"}
        elif s["status"] == "ok" and s["tool"]["version"] == "unrecorded":
            s["tool"]["version"] = _tool_version(s["tool"]["name"])
    supplemental = artifact_evidence(
        artifact_input, target, identity, allow_network_trust=allow_network_trust
    ) if artifact_input else {}
    for s in signals:
        controls = (("signature", "provenance") if s["name"] == "provenance"
                    else ("sbom",) if s["name"] == "supply_chain" else ())
        observed = {key: supplemental[key] for key in controls if key in supplemental}
        if not observed:
            continue
        s["related_evidence"] = observed
        if any(result["status"] == "error" for result in observed.values()):
            s.update(status="error", subscore=None, confidence="low",
                     finding="Supplied artifact evidence failed verification; review its reported gaps.")
        elif s["status"] != "ok":
            s["finding"] = ("Artifact observations are available separately; verification "
                            "does not establish a SLSA level or complete transitive vulnerability coverage.")
    report = _report(target, mode, signals, evaluated_at, identity["kind"], identity)
    if acquisition:
        report["remote_acquisition"] = acquisition
    if project:
        report["project_evidence"] = project
        governance = project.get("governance", {})
        facts = governance.get("facts", {})
        if facts.get("required_reviews") is False:
            report["actions"].append("Review the primary branch's pull-request approval requirements.")
        if facts.get("bypass_actors"):
            report["actions"].append("Review the scope of reported review-bypass actors before relying on enforcement.")
        for area in project.get("threat_model", {}).get("facts", {}).get("reviewed_areas", []):
            if area["coverage"] != "current" or area["limitations"]:
                report["actions"].append(
                    f"Review uncovered assets and trust boundaries in the declared {area['scope']} scope.")
    if supplemental:
        report["artifact_evidence"] = supplemental
        failures = [key for key, result in supplemental.items() if result["status"] == "error"]
        report["actions"] = [
            f"Investigate the {key} evidence mismatch before relying on this artifact."
            for key in failures
        ] + report["actions"]
    if baseline_evidence:
        expected = identity.get("git_commit") if identity.get("git_dirty") is False else \
            identity.get("commit") if identity["kind"] == "repo" else \
            identity.get("identifier") if identity["kind"] == "local_file" else None
        report["baseline_conformance"] = evaluate_conformance(
            load_baseline(baseline_evidence), target, evaluated_at=evaluated_at,
            expected_revision=expected,
        )
    if vex_input:
        report["vex_input"] = {
            "documents_supplied": len(context["vex_documents"]),
            "authors_authenticated": False,
            "limitation": "Imported statements are context only; no automatic finding suppression.",
        }
    return report


def replay(snapshot: Path, evaluated_at: Optional[str] = None) -> Dict[str, Any]:
    data = read_document(snapshot, MAX_SNAPSHOT_BYTES)
    if isinstance(data, dict) and data.get("policy_version") != POLICY_VERSION:
        raise ValueError("Snapshot policy differs from policy v2 (Baseline is now unweighted). "
                         "Retain the original report or replay with its original policy version; "
                         "run a new evaluation for policy v2.")
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION \
            or data.get("policy_version") != POLICY_VERSION \
            or data.get("mode") not in MODE_WEIGHTS or not isinstance(data.get("target"), str) \
            or not isinstance(data.get("signals"), list):
        raise ValueError("Snapshot schema or policy version invalid")
    at = evaluated_at or data.get("evaluated_at")
    _utc(at)
    if not all(isinstance(s, dict) for s in data["signals"]):
        raise ValueError("Invalid snapshot signal")
    if data.get("target_kind") not in (
            "local", "local_directory", "local_file", "repo", "package", "image") or \
            not isinstance(data.get("target_identity"), dict):
        raise ValueError("Snapshot target identity missing")
    report = _report(data["target"], data["mode"], data["signals"], at,
                     data["target_kind"], data["target_identity"])
    # Actions belong to the captured run, including its installed skill path.
    if not isinstance(data.get("actions"), list) or not all(
            isinstance(action, str) for action in data["actions"]):
        raise ValueError("Snapshot actions missing")
    report["actions"] = data["actions"]
    for name in ("artifact_evidence", "baseline_conformance", "vex_input",
                 "remote_acquisition", "project_evidence"):
        if name in data:
            if not isinstance(data[name], dict):
                raise ValueError("Invalid supplemental snapshot evidence")
            report[name] = data[name]
    return report


def _md(value: Any) -> str:
    text = str(value).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()<>!#|])", r"\\\1", text)


def _risks(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    risks = []
    for s in signals:
        if s["name"] == "scorecard" and s["status"] == "ok" and \
                isinstance(s.get("raw"), dict):
            for check in s["raw"].get("checks", []):
                if check["score"] == 0 and not check["overlaps"]:
                    risks.append({"finding": f"Scorecard {check['name']}: {check['reason']}",
                                  "priority": 24 if check["name"] == "Dangerous-Workflow" else 3,
                                  "source": "Scorecard",
                                  "basis": "Failed check at the recorded revision; "
                                           "verify context before remediation"})
        if s["name"] == "known_vulns" and isinstance(s.get("raw"), dict):
            for f in s["raw"].get("findings", []):
                severity = f["severity"]
                if severity and severity != "NONE":
                    # Exposure is not resolved yet: conservative direct/production
                    # assumption, explicitly disclosed in the report.
                    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[severity] \
                           * (2 if f["fixed_versions"] else 1) * 3
                    risks.append({"finding": f"{f['id']}: {f['package']}@{f['version']}",
                                  "priority": rank, "source": "OSV-Scanner",
                                  "basis": f"{severity}; fix "
                                           + ("available" if f["fixed_versions"] else "not established")
                                           + "; exposure assumed direct pending verification"})
        if s["name"] == "secrets" and s["status"] == "ok" \
                and s["raw"].get("potential_count"):
            risks.append({"finding": f"{s['raw']['potential_count']} potential secret(s)",
                          "priority": None, "source": "Gitleaks",
                          "basis": "Liveness unverified; triage promptly, not a confirmed live secret"})
    return sorted(risks, key=lambda x: (x["priority"] is None, -(x["priority"] or 0),
                                       x["finding"]))[:5]


def to_markdown(report: Dict[str, Any]) -> str:
    v = report["verdict"]
    lines = [
        f"# OpenSSF Ensemble Evaluation — {_md(report['target'])}",
        "",
        f"- **Mode:** {report['mode']}",
        f"- **Target kind:** {report['target_kind']}",
        f"- **Identity:** requested `{_md(report['target'])}`; "
        + ("resolved" if report["target_identity"]["resolved"] else
           "not pinned to an immutable artifact"),
        f"- **Resolved scope:** `{_md(report['target_identity'].get('identifier', 'not recorded'))}`; "
        f"immutable: {_md(report['target_identity'].get('immutable', 'unknown'))}; "
        f"verified locally: {_md(report['target_identity'].get('verified', 'unknown'))}",
        f"- **Evaluated:** {_md(report['evaluated_at'])} · "
        f"**Policy:** custom heuristic v{_md(report['policy_version'])} · "
        f"**Schema:** v{report['schema_version']}",
        f"- **Evidence coverage:** {sum(s['status'] == 'ok' for s in report['signals'])}"
        f"/{len(report['signals'])} probes; weighted {v['active_weight_covered']:.0%}",
        "",
        "## Verdict",
        "",
        f"> **{v['outcome']}** · base "
        f"{v['base_score'] if v['base_score'] is not None else 'n/a'} → final "
        f"{v['final_score'] if v['final_score'] is not None else 'n/a'} "
        f"· confidence {v['confidence']} · risk tier {v['risk_tier']}",
        "",
    ]
    if v["outcome"] == "INCOMPLETE" and v["base_score"] is None:
        lines += ["No scored weighted evidence yet; the actions below can start now.", ""]
    elif v["outcome"] == "INCOMPLETE":
        lines += [f"The computed {v['provisional_outcome']} is **provisional**, not an "
                  "adoption recommendation or grade; resolve evidence gaps for assurance. "
                  "The actions below can start now.", ""]
    if v["cap_applied"]:
        lines.append(f"_Escalation cap applied: {_md(v['cap_applied'])}_\n")
        if v["base_score"] is None:
            lines.append("The adverse cap determines the outcome without a numeric base score.\n")
    lines += ["## Evidence", "",
              "| Signal | Status | Sub-score | Original → effective weight | "
              "Contribution | Confidence | Source / time / age | Finding |",
              "|--------|--------|-----------|-----------------------------|"
              "--------------|------------|---------------|---------|"]
    for s in report["signals"]:
        ss = "—" if s["subscore"] is None else s["subscore"]
        original = MODE_WEIGHTS[report["mode"]][s["name"]]
        effective = v["effective_weights"].get(s["name"], 0)
        contribution = round(ss * effective, 2) if isinstance(ss, (float, int)) else "—"
        lines.append(f"| {_md(s['name'])} | {_md(s['status'])} | {ss} | "
                     f"{original:.2f} → {effective:.3f} | {contribution} | "
                     f"{_md(s['confidence'])} | {_md(s.get('source', s['name']))} "
                     f"({_md(s.get('evidence_type', 'observation'))}, "
                     f"{_md(s.get('captured_at') or 'time unrecorded')}, "
                     f"{_md(str(s['age_days']) + 'd' if s.get('age_days') is not None else 'age unknown')}, "
                     f"{_md((s.get('tool') or {}).get('version', 'tool version unrecorded'))}) | "
                     f"{_md(s['finding'])} |")
    lines += ["", f"**Math:** Σ(sub-score × effective weight) = "
              f"{v['base_score'] if v['base_score'] is not None else 'n/a'}; "
              f"cap → {v['final_score'] if v['final_score'] is not None else 'n/a'}. "
              f"Escalations: {', '.join(e['rule'] for e in v['escalations']) or 'none'}.",
              "", "## Top risks (ranked)", ""]
    notes = [f"- **{_md(s['name'])}:** {_md(s['evidence_note'])}"
             for s in report["signals"] if s.get("evidence_note")]
    if notes:
        lines += ["", "**Evidence reconciliation:**", *notes, ""]
    scorecard = next((s for s in report["signals"] if s["name"] == "scorecard"), None)
    if scorecard and isinstance(scorecard.get("raw"), dict) and \
            isinstance(scorecard["raw"].get("checks"), list):
        raw = scorecard["raw"]
        lines += ["", "**Scorecard checks:** aggregate "
                  f"{_md(raw['aggregate'])}/10; revision {_md(raw.get('commit') or 'unrecorded')}; "
                  f"captured {_md(raw.get('date') or 'unrecorded')}; "
                  f"version {_md(raw.get('version') or 'unrecorded')}. "
                  "Overlapping checks are preserved but not scored again. "
                  f"{_md(raw.get('permission_scope', ''))}", ""]
        for check in raw["checks"]:
            lines.append(f"- **{_md(check['name'])} ({_md(check['score'])}/10"
                         f"{', overlap' if check['overlaps'] else ''}):** "
                         f"{_md(check['reason'])}"
                         + (f"; {_md('; '.join(check['details']))}" if check["details"] else ""))
    risks = _risks(report["signals"])
    lines.extend(f"{i}. **{_md(r['finding'])}** — {_md(r['source'])}; "
                 f"priority {_md(r['priority'] if r['priority'] is not None else 'unranked')}. "
                 f"{_md(r['basis'])}."
                 for i, r in enumerate(risks, 1))
    if not risks:
        lines.append("No ranked findings in the available evidence; this is not a clean bill of health.")
    known = next((s for s in report["signals"] if s["name"] == "known_vulns"), None)
    if known and isinstance(known.get("raw"), dict) and known["raw"].get("triage"):
        lines += ["", "## Vulnerability context (not automatic exclusions)", ""]
        for package in known["raw"]["triage"]:
            for finding in package["findings"]:
                lines.append(f"- **{_md(finding['id'])}:** {_md(finding['version_status'])} "
                             f"for {_md(package['package']['name'])}@{_md(package['package']['version'])}.")
                for record in finding["records"]:
                    if record["malicious"]["report"]:
                        lines.append(f"  Malicious-package report: {_md(record['malicious']['recommendation'])}; "
                                     "report identity alone is not proof of compromise.")
                for context in finding["vex"]:
                    lines.append(f"  VEX: {_md(context['status'])}; {_md(context['assessment'])}; "
                                 f"scope {_md(context['scope'])}; freshness {_md(context['freshness'])}; "
                                 f"authenticated author: {_md(context['authenticated'])}.")
    if report.get("artifact_evidence"):
        lines += ["", "## Artifact evidence (separate observations)", ""]
        for name, result in report["artifact_evidence"].items():
            lines.append(f"- **{_md(name)}:** {_md(result['status'])}. "
                         + " ".join(_md(gap) for gap in result["gaps"]))
        lines.append("Successful signature or provenance verification does not by itself certify a SLSA level. "
                     "SBOM checksum declarations do not establish inventory completeness.")
    if report.get("project_evidence"):
        lines += ["", "## Project governance and reviewed scope", ""]
        for name, result in report["project_evidence"].items():
            lines.append(f"- **{_md(name)}:** {_md(result['status'])}; "
                         + " ".join(_md(gap) for gap in result["gaps"]))
            facts = result["facts"]
            if name == "governance":
                lines.append(
                    f"  Branch {_md(facts.get('branch') or 'unknown')}; "
                    f"protected {_md(facts.get('protected_branch'))}; "
                    f"required reviews {_md(facts.get('required_reviews'))}; "
                    f"captured {_md(facts.get('captured_at') or 'not recorded')}.")
            elif name == "maintenance":
                release = facts.get("latest_stable_release")
                if release:
                    lines.append(f"  Observed stable release {_md(release['tag'])}: "
                                 f"{_md(release['age_days'])} days before evaluation.")
                if facts.get("support"):
                    lines.append(f"  Declared support: {_md(facts['support']['status'])}; "
                                 f"scope {_md(facts['support']['scope'])}.")
            elif name == "threat_model":
                for area in facts.get("reviewed_areas", []):
                    lines.append(f"  Reviewed scope {_md(area['scope'])}: "
                                 f"{_md(area['coverage'])}; {_md(area['reviewed_at'])}; "
                                 f"source {_md(area['source'])}.")
        lines.append("Imported settings/support are observations, not authenticated API results. "
                     "One reviewed threat-model area does not establish whole-project coverage.")
    if report.get("remote_acquisition"):
        acquisition = report["remote_acquisition"]
        lines += ["", "## Explicit remote acquisition", "",
                  f"Status {_md(acquisition['status'])}; kind {_md(acquisition['kind'])}; "
                  f"scope {_md(acquisition['scope'])}. "
                  f"Resolved commit {_md(acquisition.get('commit') or 'not verified')}; "
                  f"fetched {_md(acquisition.get('fetched_at') or 'not available')}; "
                  f"freshness {_md(acquisition.get('freshness') or 'unknown')} "
                  f"(age {_md(acquisition.get('age_days') if acquisition.get('age_days') is not None else 'unknown')}d). "
                  f"{_md(acquisition.get('reason') or acquisition.get('binding') or '')}"]
    if report.get("baseline_conformance"):
        baseline = report["baseline_conformance"]
        lines += ["", "## OSPS Baseline conformance (not weighted)", "",
                  f"Catalog {_md(baseline['catalog_version'])}; level {_md(baseline['level'])}; "
                  f"scope {_md(baseline['scope'])}; revision {_md(baseline['revision'])}.",
                  f"**{_md(baseline['outcome'])}**: "
                  + ", ".join(f"{_md(name)}={count}" for name, count in baseline["counts"].items()),
                  "Supplied observations are not independently verified or a certification."]
        lines.extend(f"- **{_md(row['requirement_id'])}:** {_md(row['status'])}; {_md(row['reason'])}"
                     for row in baseline["requirements"] if row["evidence_type"] != "not_observed")
    lines += ["", "## Required actions", ""]
    lines.extend(f"- [ ] {_md(action)}" for action in report["actions"])
    if not report["actions"]:
        lines.append("No immediate action established by the available evidence.")
    lines += ["", "## What we could not determine", ""]
    lines.extend(f"- **{_md(gap['signal'])}** — {_md(gap['reason'])}"
                 for gap in report["gaps"])
    if not report["gaps"]:
        lines.append("No missing weighted probes; target identity and tool coverage may still be limited.")
    else:
        lines += ["", "These gaps limit assurance, not immediate progress. Run or import "
                  "only the evidence relevant to your next decision; scanners are optional."]
    lines += ["", "## Provenance of this report", "",
              "Signals name their source, observation type, and capture time above. "
              "Any evidence reconciliation is recorded per signal as `evidence_note`. "
              "Manual observations and self-reports are not independent verification. "
              "Scanner diagnostics and secret contents are never included. "
              "This is a custom risk heuristic, not OpenSSF certification."]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="OpenSSF ensemble evaluator")
    selection = ap.add_mutually_exclusive_group(required=True)
    selection.add_argument("--target",
                    help="local ./path, GitHub owner/repo[@ref], exact package@version, or OCI digest")
    selection.add_argument("--replay", type=Path, help="re-evaluate a JSON snapshot without scanners")
    ap.add_argument("--mode", choices=["consume", "produce"])
    ap.add_argument("--ecosystem", choices=sorted({"npm", "PyPI", "Go", "crates.io",
                                                    "Maven", "NuGet", "RubyGems"}),
                    help="required for package@version targets without a purl")
    ap.add_argument("--format", choices=["json", "md"], default="json")
    ap.add_argument("--evidence", type=Path, help="import versioned, target-bound manual observations")
    ap.add_argument("--baseline-evidence", type=Path,
                    help="optional requirement-level Baseline conformance (not scored)")
    ap.add_argument("--artifact-evidence", type=Path,
                    help="optional local signature/provenance/SPDX evidence configuration")
    ap.add_argument("--vex-evidence", type=Path,
                    help="optional OpenVEX context; no automatic suppression or authentication")
    ap.add_argument("--allow-network-trust", action="store_true",
                    help="explicitly allow artifact verifiers' public trust lookup")
    ap.add_argument("--acquire-remote", action="store_true",
                    help="explicitly query OSV for exact package versions, acquire public "
                         "GitHub commit archives, or scan OCI digests via installed OSV-Scanner")
    ap.add_argument("--governance-evidence", type=Path,
                    help="optional target-bound offline governance/maintenance observations")
    ap.add_argument("--threat-evidence", type=Path,
                    help="optional target-bound reviewed threat-model areas")
    ap.add_argument("--fetch-governance", action="store_true",
                    help="explicit read-only GitHub branch/ruleset and activity lookup via gh")
    ap.add_argument("--governance-branch",
                    help="literal branch for --fetch-governance (defaults to requested/default branch)")
    ap.add_argument("--snapshot-out", type=Path, help="write sanitized replayable JSON")
    ap.add_argument("--at", help="ISO-8601 evaluation time (UTC offset required)")
    args = ap.parse_args()
    if bool(args.target) != bool(args.mode) or args.replay and (
            args.evidence or args.ecosystem or args.baseline_evidence or
            args.artifact_evidence or args.vex_evidence or args.allow_network_trust or
            args.acquire_remote or args.governance_evidence or args.threat_evidence or
            args.fetch_governance or args.governance_branch):
        ap.error("--target requires --mode; new evidence/options cannot be used with --replay")
    if args.allow_network_trust and not args.artifact_evidence:
        ap.error("--allow-network-trust requires --artifact-evidence")
    try:
        report = (replay(args.replay, args.at) if args.replay else
                  evaluate(args.target, args.mode, args.evidence, args.at, args.ecosystem,
                           baseline_evidence=args.baseline_evidence,
                           artifact_input=args.artifact_evidence, vex_input=args.vex_evidence,
                           allow_network_trust=args.allow_network_trust,
                           acquire_remote=args.acquire_remote,
                           governance_input=args.governance_evidence,
                           threat_input=args.threat_evidence,
                           fetch_governance=args.fetch_governance,
                           governance_branch=args.governance_branch))
        if args.snapshot_out:
            snapshot = (json.dumps(report, indent=2) + "\n").encode("utf-8")
            if len(snapshot) > MAX_SNAPSHOT_BYTES:
                raise ValueError("Snapshot exceeds the 32 MiB replay limit; reduce the evidence scope")
            args.snapshot_out.write_bytes(snapshot)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        ap.error(str(exc) if isinstance(exc, ValueError) else
                 f"Evidence validation or output failed ({type(exc).__name__}); "
                 "check schema, target, mode, and writable paths")
    if args.format == "md":
        print(to_markdown(report))
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
