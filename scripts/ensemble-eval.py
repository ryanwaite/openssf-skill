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
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Risk model constants (mirror ensemble/risk-model.md) --------------------

MODE_WEIGHTS: Dict[str, Dict[str, float]] = {
    "consume": {
        "known_vulns": 0.28,
        "maintenance": 0.22,
        "supply_chain": 0.16,
        "scorecard": 0.14,
        "provenance": 0.12,
        "baseline": 0.08,
    },
    "produce": {
        "secrets": 0.20,
        "provenance": 0.16,
        "code_review": 0.16,
        "scorecard": 0.14,
        "known_vulns": 0.12,
        "threat_coverage": 0.12,
        "baseline": 0.10,
    },
}

SEVERITY_DEDUCTION = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}


# --- Signal helper -----------------------------------------------------------

def signal(name: str, status: str, subscore: Optional[float],
           confidence: str, finding: str, raw: Any = None) -> Dict[str, Any]:
    """Build a normalized signal record."""
    return {
        "name": name,
        "status": status,           # ok | unknown | error
        "subscore": subscore,       # 0-100 or None
        "confidence": confidence,   # high | medium | low
        "finding": finding,
        "raw": raw,
    }


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: List[str], timeout: int = 180) -> Optional[subprocess.CompletedProcess]:
    """Run a command safely (no shell). Return None on failure/timeout."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


# --- Probes ------------------------------------------------------------------
# Each probe returns a signal dict. When the underlying tool is unavailable the
# probe returns an `unknown` signal so the gap is surfaced, never hidden.

def probe_scorecard(target: str, is_repo: bool) -> Dict[str, Any]:
    if not is_repo or not _have("scorecard"):
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard not run (needs `scorecard` CLI + repo URL).")
    repo = target.replace("https://", "").rstrip("/")
    proc = _run(["scorecard", f"--repo={repo}", "--format=json"])
    if not proc or proc.returncode != 0 or not proc.stdout.strip():
        return signal("scorecard", "unknown", None, "low",
                      "Scorecard execution failed.")
    try:
        data = json.loads(proc.stdout)
        agg = float(data.get("score", 0))
    except (json.JSONDecodeError, ValueError, TypeError):
        return signal("scorecard", "error", None, "low",
                      "Could not parse Scorecard output.")
    return signal("scorecard", "ok", round(agg * 10, 1), "high",
                  f"Scorecard aggregate {agg}/10.", raw={"aggregate": agg})


def probe_known_vulns(target: str, is_local: bool) -> Dict[str, Any]:
    if not _have("osv-scanner"):
        return signal("known_vulns", "unknown", None, "low",
                      "OSV-Scanner not installed.")
    arg = ["osv-scanner", "--format=json"]
    arg += (["--recursive", target] if is_local else ["--lockfile", target])
    proc = _run(arg)
    if not proc or not proc.stdout.strip():
        return signal("known_vulns", "unknown", None, "low",
                      "OSV-Scanner produced no output.")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    try:
        data = json.loads(proc.stdout)
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    sev = _osv_severity(vuln)
                    counts[sev] = counts.get(sev, 0) + 1
    except (json.JSONDecodeError, TypeError):
        return signal("known_vulns", "error", None, "low",
                      "Could not parse OSV-Scanner output.")
    score = 100
    for sev, n in counts.items():
        score -= SEVERITY_DEDUCTION[sev] * n
    score = max(0, score)
    total = sum(counts.values())
    return signal("known_vulns", "ok", score, "high",
                  f"{total} known vulns ({counts['CRITICAL']}C/{counts['HIGH']}H/"
                  f"{counts['MEDIUM']}M/{counts['LOW']}L).", raw=counts)


def _osv_severity(vuln: Dict[str, Any]) -> str:
    """Best-effort CVSS/severity bucket from an OSV vuln record."""
    for sev in vuln.get("severity", []):
        score = str(sev.get("score", ""))
        # CVSS vector or numeric — coarse bucket
        if "CRITICAL" in score.upper():
            return "CRITICAL"
    db = (vuln.get("database_specific") or {}).get("severity", "")
    db = str(db).upper()
    if db in SEVERITY_DEDUCTION:
        return db
    return "MEDIUM"


def probe_secrets(target: str, is_local: bool) -> Dict[str, Any]:
    if not is_local:
        return signal("secrets", "unknown", None, "low",
                      "Secrets scan needs a local checkout.")
    if not _have("gitleaks"):
        return signal("secrets", "unknown", None, "low",
                      "Gitleaks not installed.")
    proc = _run(["gitleaks", "detect", "--source", target,
                 "--report-format", "json", "--report-path", "/dev/stdout",
                 "--no-banner"])
    if proc is None:
        return signal("secrets", "unknown", None, "low", "Gitleaks failed to run.")
    # gitleaks exits non-zero when leaks are found
    findings = []
    if proc.stdout.strip():
        try:
            findings = json.loads(proc.stdout)
        except json.JSONDecodeError:
            findings = []
    if findings:
        return signal("secrets", "ok", 0, "high",
                      f"{len(findings)} potential secret(s) detected — verify "
                      f"liveness immediately.", raw={"count": len(findings)})
    return signal("secrets", "ok", 100, "high", "No secrets detected by Gitleaks.")


def probe_maintenance(target: str, is_local: bool) -> Dict[str, Any]:
    """Use git history (local) or gh API (repo) to gauge activity."""
    if is_local and (Path(target) / ".git").exists():
        proc = _run(["git", "-C", target, "log", "-1", "--format=%ct"])
        if proc and proc.stdout.strip().isdigit():
            import time
            age_days = (time.time() - int(proc.stdout.strip())) / 86400
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
        if proc and proc.stdout.strip():
            try:
                meta = json.loads(proc.stdout)
                if meta.get("archived"):
                    return signal("maintenance", "ok", 0, "high",
                                  "Repository is ARCHIVED.", raw=meta)
                return signal("maintenance", "ok", 90, "medium",
                              f"Last push {meta.get('pushed')}.", raw=meta)
            except json.JSONDecodeError:
                pass
    return signal("maintenance", "unknown", None, "low",
                  "Could not determine maintenance signals.")


def _placeholder(name: str, hint: str) -> Dict[str, Any]:
    """Probes whose tooling integration is environment-specific.

    These return `unknown` by default so the agent knows to run them manually
    and feed results back; they are intentionally honest about being un-run
    rather than fabricating a score.
    """
    return signal(name, "unknown", None, "low", hint)


def probe_supply_chain(target: str) -> Dict[str, Any]:
    return _placeholder("supply_chain",
                        "Generate an SPDX SBOM (syft/spdx-sbom-generator) and assess "
                        "transitive risk; feed the count back in.")


def probe_provenance(target: str) -> Dict[str, Any]:
    return _placeholder("provenance",
                        "Check SLSA level and verify signatures with "
                        "`cosign verify`; record the level.")


def probe_baseline(target: str) -> Dict[str, Any]:
    return _placeholder("baseline",
                        "Score OSPS Baseline L1 controls met / total.")


def probe_threat_coverage(target: str) -> Dict[str, Any]:
    return _placeholder("threat_coverage",
                        "Confirm a current STRIDE threat model exists.")


def probe_code_review(target: str, is_local: bool) -> Dict[str, Any]:
    if is_local:
        co = Path(target)
        has_codeowners = any((co / p).exists() for p in
                             ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"))
        if has_codeowners:
            return signal("code_review", "ok", 50, "low",
                          "CODEOWNERS present; branch-protection status unknown.")
    return _placeholder("code_review",
                        "Confirm required reviews + protected default branch.")


# --- Fusion ------------------------------------------------------------------

def fuse(signals: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    weights = MODE_WEIGHTS[mode]
    usable = [s for s in signals
              if s["status"] == "ok" and s["name"] in weights
              and s["subscore"] is not None]
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
        if capped is not None and capped > ceiling:
            capped, cap_label = ceiling, esc["rule"]

    outcome = _outcome(capped, mode, escalations)
    confidence = _confidence(active_weight, base)

    return {
        "mode": mode,
        "base_score": base,
        "final_score": capped,
        "escalations": escalations,
        "cap_applied": cap_label,
        "outcome": outcome,
        "confidence": confidence,
        "active_weight_covered": round(active_weight, 2),
    }


def _escalations(signals: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    out = []
    by = {s["name"]: s for s in signals}
    sec = by.get("secrets")
    if sec and sec["status"] == "ok" and sec["subscore"] == 0:
        out.append({"rule": "Potential live secret exposed", "caps_at": "critical"})
    kv = by.get("known_vulns")
    if kv and kv["status"] == "ok" and isinstance(kv.get("raw"), dict) \
            and kv["raw"].get("CRITICAL", 0) > 0:
        out.append({"rule": "Unpatched CRITICAL vulnerability", "caps_at": "high"})
    mnt = by.get("maintenance")
    if mnt and mnt["status"] == "ok" and mnt["subscore"] == 0:
        out.append({"rule": "Archived / EOL project", "caps_at": "high"})
    return out


def _outcome(score: Optional[float], mode: str,
             escalations: List[Dict[str, str]]) -> str:
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


def _confidence(active_weight: float, base: Optional[float]) -> str:
    """Confidence keys off how much of the mode's weight the run actually covered.

    Missing data never inflates confidence: a partial run cannot report 'high'.
    """
    if base is None or active_weight < 0.5:
        return "low"
    if active_weight < 0.8:
        return "medium"
    return "high"


# --- Orchestration -----------------------------------------------------------

def classify_target(target: str) -> Dict[str, bool]:
    is_repo = target.startswith("http") or target.count("/") == 1 and "@" not in target
    is_local = Path(target).exists()
    return {"is_repo": bool(is_repo and not is_local), "is_local": is_local}


def evaluate(target: str, mode: str) -> Dict[str, Any]:
    kind = classify_target(target)
    is_repo, is_local = kind["is_repo"], kind["is_local"]

    signals = [
        probe_scorecard(target, is_repo),
        probe_known_vulns(target, is_local),
        probe_maintenance(target, is_local),
        probe_supply_chain(target),
        probe_provenance(target),
        probe_baseline(target),
    ]
    if mode == "produce":
        signals += [
            probe_secrets(target, is_local),
            probe_code_review(target, is_local),
            probe_threat_coverage(target),
        ]

    fusion = fuse(signals, mode)
    return {
        "target": target,
        "target_kind": "local" if is_local else ("repo" if is_repo else "package"),
        "mode": mode,
        "signals": signals,
        "verdict": fusion,
    }


def to_markdown(report: Dict[str, Any]) -> str:
    v = report["verdict"]
    lines = [
        f"# OpenSSF Ensemble Evaluation — {report['target']}",
        "",
        f"- **Mode:** {report['mode']}",
        f"- **Target kind:** {report['target_kind']}",
        "",
        "## Verdict",
        "",
        f"> **{v['outcome']}** · base {v['base_score']} → final {v['final_score']} "
        f"· confidence {v['confidence']}",
        "",
    ]
    if v["cap_applied"]:
        lines.append(f"_Escalation cap applied: {v['cap_applied']}_\n")
    lines += ["## Evidence", "",
              "| Signal | Status | Sub-score | Confidence | Finding |",
              "|--------|--------|-----------|------------|---------|"]
    for s in report["signals"]:
        ss = "—" if s["subscore"] is None else s["subscore"]
        lines.append(f"| {s['name']} | {s['status']} | {ss} | "
                     f"{s['confidence']} | {s['finding']} |")
    unknown = [s for s in report["signals"] if s["status"] != "ok"]
    if unknown:
        lines += ["", "## Could not determine", ""]
        lines += [f"- **{s['name']}** — {s['finding']}" for s in unknown]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="OpenSSF ensemble evaluator")
    ap.add_argument("--target", required=True,
                    help="local path, repo URL (owner/repo), or package@version")
    ap.add_argument("--mode", choices=["consume", "produce"], required=True)
    ap.add_argument("--format", choices=["json", "md"], default="json")
    args = ap.parse_args()

    report = evaluate(args.target, args.mode)
    if args.format == "md":
        print(to_markdown(report))
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
