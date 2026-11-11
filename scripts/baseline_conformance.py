#!/usr/bin/env python3
"""Validate optional, versioned OSPS evidence without assigning a risk score."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


CATALOG_VERSION = "2026.08.28"
CATALOG_COMMIT = "a26a7963f6fd098c1e82829322ec9e1196a4f294"
CATALOG_SOURCE = (
    "https://github.com/ossf/security-baseline/tree/"
    f"{CATALOG_COMMIT}/baseline"
)

# Explicit applicability, not inferred cumulative levels: BR-07.01 and
# VM-02.01 apply only to maturity-1 in this release. BR-01.02 is retired.
REQUIREMENTS = {
    "OSPS-AC-01.01": (1, 2, 3), "OSPS-AC-02.01": (1, 2, 3),
    "OSPS-AC-03.01": (1, 2, 3), "OSPS-AC-03.02": (1, 2, 3),
    "OSPS-AC-04.01": (2, 3), "OSPS-AC-04.02": (3,),
    "OSPS-BR-01.01": (1, 2, 3), "OSPS-BR-01.03": (1, 2, 3),
    "OSPS-BR-01.04": (3,), "OSPS-BR-02.01": (2, 3),
    "OSPS-BR-02.02": (3,), "OSPS-BR-03.01": (1, 2, 3),
    "OSPS-BR-03.02": (1, 2, 3), "OSPS-BR-04.01": (2, 3),
    "OSPS-BR-05.01": (2, 3), "OSPS-BR-06.01": (2, 3),
    "OSPS-BR-07.01": (1,), "OSPS-BR-07.02": (3,),
    "OSPS-DO-01.01": (1, 2, 3), "OSPS-DO-02.01": (1, 2, 3),
    "OSPS-DO-03.01": (3,), "OSPS-DO-03.02": (3,),
    "OSPS-DO-04.01": (3,), "OSPS-DO-05.01": (3,),
    "OSPS-DO-06.01": (2, 3), "OSPS-DO-07.01": (2, 3),
    "OSPS-GV-01.01": (2, 3), "OSPS-GV-01.02": (2, 3),
    "OSPS-GV-02.01": (1, 2, 3), "OSPS-GV-03.01": (1, 2, 3),
    "OSPS-GV-03.02": (2, 3), "OSPS-GV-04.01": (3,),
    "OSPS-LE-01.01": (2, 3), "OSPS-LE-02.01": (1, 2, 3),
    "OSPS-LE-02.02": (1, 2, 3), "OSPS-LE-03.01": (1, 2, 3),
    "OSPS-LE-03.02": (1, 2, 3),
    "OSPS-QA-01.01": (1, 2, 3), "OSPS-QA-01.02": (1, 2, 3),
    "OSPS-QA-02.01": (1, 2, 3), "OSPS-QA-02.02": (3,),
    "OSPS-QA-03.01": (2, 3), "OSPS-QA-04.01": (1, 2, 3),
    "OSPS-QA-04.02": (3,), "OSPS-QA-05.01": (1, 2, 3),
    "OSPS-QA-05.02": (1, 2, 3), "OSPS-QA-06.01": (2, 3),
    "OSPS-QA-06.02": (3,), "OSPS-QA-06.03": (3,),
    "OSPS-QA-07.01": (3,),
    "OSPS-SA-01.01": (2, 3), "OSPS-SA-02.01": (2, 3),
    "OSPS-SA-03.01": (2, 3), "OSPS-SA-03.02": (3,),
    "OSPS-VM-01.01": (2, 3), "OSPS-VM-02.01": (1,),
    "OSPS-VM-03.01": (2, 3), "OSPS-VM-04.01": (2, 3),
    "OSPS-VM-04.02": (3,), "OSPS-VM-05.01": (3,),
    "OSPS-VM-05.02": (3,), "OSPS-VM-05.03": (3,),
    "OSPS-VM-06.01": (3,), "OSPS-VM-06.02": (3,),
}
STATUSES = ("met", "not_met", "unknown", "not_applicable")
MAX_BYTES = 1_000_000


def _text(value: Any, field: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{field} must be a nonempty string of at most {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    value = _text(value, field, 64)
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if result.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return result.astimezone(timezone.utc)


def _fields(value: Any, expected: set[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{context} must contain exactly: {', '.join(sorted(expected))}")


def evaluate_conformance(
    evidence: Any, target: str, *, evaluated_at: str,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    """Assess supplied observations; never independently attest their truth."""
    _fields(evidence, {
        "schema_version", "catalog_version", "target", "revision", "scope",
        "level", "observations",
    }, "Baseline evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1:
        raise ValueError("Unsupported Baseline evidence schema_version (expected 1)")
    if evidence["catalog_version"] != CATALOG_VERSION:
        raise ValueError(f"Unsupported catalog_version (expected {CATALOG_VERSION})")
    if _text(evidence["target"], "target") != target:
        raise ValueError("Baseline evidence target does not match the requested target")
    revision = _text(evidence["revision"], "revision")
    if expected_revision is not None and revision != expected_revision:
        raise ValueError("Baseline evidence revision does not match the resolved target")
    scope = _text(evidence["scope"], "scope")
    level = evidence["level"]
    if type(level) is not int or level not in (1, 2, 3):
        raise ValueError("Baseline level must be 1, 2, or 3")
    at = _timestamp(evaluated_at, "evaluated_at")
    observations = evidence["observations"]
    if not isinstance(observations, list) or len(observations) > len(REQUIREMENTS):
        raise ValueError("Baseline observations must be a bounded list")
    selected = {name for name, levels in REQUIREMENTS.items() if level in levels}
    supplied = {}
    for item in observations:
        _fields(item, {
            "requirement_id", "status", "evidence_type", "source",
            "captured_at", "reason", "evidence",
        }, "Baseline observation")
        name = _text(item["requirement_id"], "requirement_id", 64)
        if name == "OSPS-BR-01.02":
            raise ValueError("OSPS-BR-01.02 is retired in this catalog")
        if name not in selected:
            raise ValueError("Unknown requirement_id or requirement outside the selected level")
        if name in supplied:
            raise ValueError("Duplicate Baseline requirement_id")
        status = item["status"]
        if status not in STATUSES:
            raise ValueError("Invalid Baseline observation status")
        kind = item["evidence_type"]
        if kind not in ("manual_observation", "self_report"):
            raise ValueError("Baseline evidence_type must be manual_observation or self_report")
        captured = _timestamp(item["captured_at"], "captured_at")
        if captured > at:
            raise ValueError("Baseline observation is dated after evaluated_at")
        source = _text(item["source"], "source")
        reason = _text(item["reason"], "reason")
        references = item["evidence"]
        if not isinstance(references, list) or len(references) > 16:
            raise ValueError("Observation evidence must be a list of at most 16 references")
        for reference in references:
            _text(reference, "evidence reference")
        if status in ("met", "not_met") and not references:
            raise ValueError("Met/not_met observations require evidence references")
        supplied[name] = {
            "requirement_id": name,
            "status": status if kind == "manual_observation" else "unknown",
            "asserted_status": status,
            "evidence_type": kind, "source": source, "reason": reason,
            "captured_at": captured.isoformat(),
            "age_days": round((at - captured).total_seconds() / 86400, 2),
            "evidence": references[:],
        }
    rows = []
    for name in sorted(selected):
        row = supplied.get(name, {
            "requirement_id": name, "status": "unknown",
            "asserted_status": None, "evidence_type": "not_observed",
            "source": None, "reason": "No observation supplied; inspect this control when relevant.",
            "captured_at": None, "age_days": None, "evidence": [],
        })
        category = name.split("-")[1]
        row["catalog_source"] = (
            f"{CATALOG_SOURCE.replace('/tree/', '/blob/')}/OSPS-{category}.yaml"
        )
        rows.append(row)
    counts = dict.fromkeys(STATUSES, 0)
    counts.update(Counter(row["status"] for row in rows))
    if counts["not_met"]:
        outcome = "gaps_reported"
    elif counts["unknown"]:
        outcome = "incomplete"
    elif counts["met"]:
        outcome = "met_by_supplied_observations"
    else:
        outcome = "no_applicable_requirements_reported"
    return {
        "schema_version": 1, "catalog_version": CATALOG_VERSION,
        "catalog_commit": CATALOG_COMMIT, "catalog_source": CATALOG_SOURCE,
        "target": target, "revision": revision, "scope": scope, "level": level,
        "evaluated_at": at.isoformat(), "requirements": rows, "counts": counts,
        "outcome": outcome, "independently_verified": False,
        "limitations": [
            "Observations and applicability justifications require human review.",
            "Evidence references are not fetched or independently verified.",
            "Capture age is reported; no automatic freshness policy is assumed.",
            "This is a point-in-time conformance record, not a score, badge, or certification.",
            "Missing evidence does not block immediate remediation or targeted advice.",
        ],
    }


def load_evidence(path: Path) -> Any:
    """Read bounded JSON without fetching any referenced resources."""
    with path.open("rb") as stream:
        content = stream.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("Baseline evidence exceeds the 1 MB input limit")
    try:
        return json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Baseline evidence must be valid UTF-8 JSON") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--revision", help="Expected resolved revision, when known")
    parser.add_argument("--at", default=None, help="ISO-8601 evaluation time with timezone")
    args = parser.parse_args()
    try:
        report = evaluate_conformance(
            load_evidence(args.evidence), args.target,
            evaluated_at=args.at or datetime.now(timezone.utc).isoformat(),
            expected_revision=args.revision,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else
                     "Could not read Baseline evidence; check the local file and permissions")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
