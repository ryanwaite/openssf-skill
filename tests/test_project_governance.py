"""Synthetic, offline regression cases for scoped governance evidence."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "project_governance", Path(__file__).resolve().parent.parent / "scripts/project_governance.py")
pg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pg)
AT = "2026-11-12T00:00:00Z"
SHA = "a" * 40
IDENTITY = {"kind": "repo", "repo": "github.com/example/demo", "ref": "main",
            "verified": True}


def response(data, status=200, **extra):
    return {"status": status, "data": data, **extra}


def snapshot(*, protection=None, rules=None, listed=None, details=None):
    return {
        "schema_version": 1, "target": IDENTITY["repo"], "revision": "main",
        "branch": "main", "captured_at": AT,
        "repository_metadata": response({"full_name": "example/demo", "default_branch": "main"}),
        "branch_info": response({"name": "main", "protected": True, "commit": {"sha": SHA}}),
        "branch_protection": response(
            protection if protection is not None else {
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "require_last_push_approval": True,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                    "bypass_pull_request_allowances": {"apps": [{"slug": "automation"}]},
                }}),
        "effective_rules": [response(rules if rules is not None else [], next=False)],
        "rulesets": [response(listed if listed is not None else [], next=False)],
        "ruleset_details": details if details is not None else {},
    }


def rule(rid=42, count=2):
    return {"type": "pull_request", "ruleset_id": rid,
            "ruleset_source_type": "Organization", "ruleset_source": "example",
            "parameters": {"required_approving_review_count": count,
                           "require_last_push_approval": True,
                           "require_code_owner_review": True,
                           "dismiss_stale_reviews_on_push": True}}


def maintenance(**changes):
    evidence = {"schema_version": 1, "target": IDENTITY["repo"], "revision": "main",
                "captured_at": AT, "repository": {"archived": False,
                                                 "pushed_at": "2023-01-01T00:00:00Z"},
                "latest_commit": {"committed_at": "2023-01-01T00:00:00Z",
                                  "author_type": "Bot"},
                "latest_release": {"tag_name": "v1", "draft": False, "prerelease": False,
                                   "published_at": "2022-01-01T00:00:00Z"},
                "support": {"status": "supported", "scope": "v1", "source": "support-policy",
                            "declared_at": "2025-01-01T00:00:00Z",
                            "evidence_type": "manual_observation"},
                "maintainers": []}
    evidence.update(changes)
    return evidence


def threat(**changes):
    evidence = {"schema_version": 1, "target": IDENTITY["repo"], "revision": "main",
                "captured_at": AT, "areas": [{
                    "scope": "authentication", "source": "review meeting",
                    "reference": "review-123", "reviewed_at": "2026-11-11T00:00:00Z",
                    "reviewer": "reviewer", "evidence_type": "manual_observation",
                    "coverage": "current", "assets": ["sessions"],
                    "trust_boundaries": ["untrusted login to application"],
                    "limitations": [],
                }]}
    evidence.update(changes)
    return evidence


class GovernanceTests(unittest.TestCase):
    def test_legacy_reviewer_and_bypass_are_separate_facts(self):
        result = pg.governance_evidence(IDENTITY, AT, snapshot=snapshot())
        self.assertTrue(result["facts"]["protected_branch"])
        self.assertTrue(result["facts"]["required_reviews"])
        self.assertTrue(result["facts"]["review_policies"][0]["last_push_approval"])
        self.assertTrue(result["facts"]["codeowners_enforcement"])
        self.assertEqual(result["facts"]["bypass_actors"][0]["id"], "automation")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["provenance"]["evidence_type"], "caller_supplied_snapshot")
        self.assertFalse(result["provenance"]["authenticated_by_module"])
        self.assertEqual(result["facts"]["predicates"]["required_reviews"]["sources"],
                         ["branch_protection.required_pull_request_reviews"])

    def test_complete_snapshot_exposes_predicate_sources_not_attestation(self):
        evidence = snapshot()
        evidence["branch_protection"]["data"]["required_pull_request_reviews"].pop(
            "bypass_pull_request_allowances")
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertEqual(result["status"], "ok")
        self.assertIn("branch_info.protected",
                      result["facts"]["predicates"]["protected_branch"]["sources"])
        self.assertFalse(result["provenance"]["authenticated_by_module"])

    def test_missing_admin_enforcement_stays_partial(self):
        evidence = snapshot()
        evidence["branch_protection"]["data"].pop("enforce_admins")
        evidence["branch_protection"]["data"]["required_pull_request_reviews"].pop(
            "bypass_pull_request_allowances")
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any("administrative bypass unknown" in gap for gap in result["gaps"]))

    def test_effective_org_rules_not_disabled_or_evaluate_inventory(self):
        evidence = snapshot(
            protection={"enabled": False}, rules=[rule()],
            listed=[{"id": 42, "enforcement": "active", "source_type": "Organization"},
                    {"id": 43, "enforcement": "evaluate", "source_type": "Repository"},
                    {"id": 44, "enforcement": "disabled", "source_type": "Organization"}],
            details={"42": response({"id": 42, "enforcement": "active",
                                     "bypass_actors": [{"actor_type": "RepositoryRole",
                                                        "actor_id": 5, "bypass_mode": "pull_request"}]})})
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertTrue(result["facts"]["required_reviews"])
        self.assertEqual(result["facts"]["review_policies"][0]["approvals"], 2)
        self.assertEqual(result["facts"]["bypass_actors"][0]["mode"], "pull_request")
        self.assertEqual([r["effective_for_branch"] for r in result["facts"]["ruleset_inventory"]],
                         [True, False, False])

    def test_explicit_disabled_protection_and_no_effective_rules(self):
        evidence = snapshot(protection={"enabled": False})
        evidence["branch_info"]["data"]["protected"] = False
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertIs(result["facts"]["protected_branch"], False)
        self.assertIs(result["facts"]["required_reviews"], False)
        self.assertEqual(result["facts"]["branch_protection_status"], "disabled")

    def test_partial_permission_and_pagination_never_claim_absence(self):
        evidence = snapshot(protection={"enabled": False})
        evidence["branch_info"]["data"]["protected"] = False
        evidence["branch_protection"] = response(None, 403)
        evidence["effective_rules"] = [response([], 403)]
        evidence["rulesets"] = [response([], 404)]
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertIsNone(result["facts"]["protected_branch"])
        self.assertIsNone(result["facts"]["required_reviews"])
        self.assertEqual(result["status"], "partial")
        evidence["effective_rules"] = [response([rule()], next=True)]
        evidence["ruleset_details"] = {"42": response(None, 403)}
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertTrue(result["facts"]["required_reviews"])
        self.assertTrue(any("pagination" in gap for gap in result["gaps"]))
        self.assertTrue(any("bypass actors unknown" in gap for gap in result["gaps"]))

    def test_metadata_403_preserves_named_branch_facts_without_default_claim(self):
        evidence = snapshot()
        evidence["repository_metadata"] = response(None, 403)
        result = pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertEqual(result["facts"]["branch"], "main")
        self.assertIsNone(result["facts"]["default_branch"])
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any("Repository metadata unavailable" in gap for gap in result["gaps"]))

    def test_inaccessible_repository_without_ref_returns_unknown_without_branch_requests(self):
        calls = []

        def denied(path):
            calls.append(path)
            return response(None, 403)

        identity = {**IDENTITY, "ref": None, "verified": False}
        result = pg.governance_evidence(identity, "2099-01-01T00:00:00Z",
                                        request=denied)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(calls, ["/repos/example/demo"])
        self.assertIsNone(result["facts"]["protected_branch"])
        self.assertIsNone(result["facts"]["required_reviews"])

    def test_live_request_only_opt_in_and_safe_paths(self):
        calls = []
        fixture = snapshot()

        def request(path):
            calls.append(path)
            if path == "/repos/example/demo":
                return fixture["repository_metadata"]
            if path.endswith("/branches/main"):
                return fixture["branch_info"]
            if path.endswith("/branches/main/protection"):
                return fixture["branch_protection"]
            if "/rules/branches/" in path:
                return fixture["effective_rules"][0]
            return fixture["rulesets"][0]

        with self.assertRaisesRegex(ValueError, "exactly one"):
            pg.governance_evidence(IDENTITY, AT)
        # A live fetch cannot be backdated into a past snapshot.
        with self.assertRaisesRegex(ValueError, "captured_at is after evaluated_at"):
            pg.governance_evidence(IDENTITY, AT, request=request)
        self.assertTrue(calls)
        self.assertTrue(all(path.startswith("/repos/example/demo") for path in calls))
        with self.assertRaisesRegex(ValueError, "branch"):
            pg.governance_evidence(IDENTITY, AT, snapshot=snapshot(), branch="../../admin")

    def test_live_fetch_reads_effective_rules_and_each_ruleset_detail(self):
        paths = []
        fixture = snapshot(rules=[rule()], listed=[
            {"id": 42, "enforcement": "active", "source_type": "Organization"}],
            details={"42": response({"id": 42, "enforcement": "active",
                                     "bypass_actors": []})})

        def request(path):
            paths.append(path)
            if path == "/repos/example/demo":
                return fixture["repository_metadata"]
            if path.endswith("/branches/main"):
                return fixture["branch_info"]
            if path.endswith("/branches/main/protection"):
                return fixture["branch_protection"]
            if path.endswith("/rulesets/42"):
                return fixture["ruleset_details"]["42"]
            if "/rules/branches/" in path:
                return fixture["effective_rules"][0]
            return fixture["rulesets"][0]

        result = pg.governance_evidence({**IDENTITY, "verified": False},
                                        "2099-01-01T00:00:00Z", request=request)
        self.assertTrue(result["facts"]["required_reviews"])
        self.assertIn("/repos/example/demo/rulesets/42", paths)
        self.assertIn("/repos/example/demo/rules/branches/main?per_page=100&page=1", paths)

    def test_named_branch_encoded_and_pagination_bounded(self):
        identity = {**IDENTITY, "ref": "release/1.0"}
        evidence = snapshot(rules=[rule()])
        evidence["revision"] = "release/1.0"
        evidence["branch"] = "release/1.0"
        evidence["branch_info"]["data"]["name"] = "release/1.0"
        evidence["ruleset_details"] = {
            "42": response({"id": 42, "enforcement": "active", "bypass_actors": []})}
        evidence["effective_rules"] = [response([rule()], next=True) for _ in range(4)]
        result = pg.governance_evidence(identity, AT, snapshot=evidence)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any("pagination" in gap for gap in result["gaps"]))
        calls = []

        def request(path):
            calls.append(path)
            if path == "/repos/example/demo":
                return evidence["repository_metadata"]
            if path.endswith("/rulesets/42"):
                return evidence["ruleset_details"]["42"]
            if "/rules/branches/" in path:
                return response([rule()], next=False)
            if "/rulesets?" in path:
                return response([], next=False)
            if path.endswith("/protection"):
                return evidence["branch_protection"]
            return evidence["branch_info"]

        pg.governance_evidence(identity, "2099-01-01T00:00:00Z", request=request)
        self.assertTrue(any("/branches/release%2F1.0" in path for path in calls))

    def test_snapshot_binding_and_missing_permission_cannot_be_faked(self):
        evidence = snapshot()
        evidence["repository_metadata"]["data"]["full_name"] = "other/repo"
        with self.assertRaisesRegex(ValueError, "metadata"):
            pg.governance_evidence(IDENTITY, AT, snapshot=evidence)
        self.assertEqual(pg.governance_evidence({**IDENTITY, "verified": False}, AT,
                                                snapshot=snapshot())["facts"]["branch"], "main")
        with self.assertRaisesRegex(ValueError, "safe"):
            pg.governance_evidence({**IDENTITY, "repo": "github.com/../demo"}, AT,
                                   snapshot=snapshot())
        with self.assertRaisesRegex(ValueError, "after evaluated_at"):
            pg.governance_evidence(IDENTITY, AT,
                                   snapshot={**snapshot(), "captured_at": "2026-11-13T00:00:00Z"})


class MaintenanceTests(unittest.TestCase):
    def test_stable_low_churn_is_not_abandoned_and_bots_are_not_maintainers(self):
        result = pg.maintenance_evidence(IDENTITY, AT, maintenance())
        self.assertEqual(result["facts"]["support"]["status"], "supported")
        self.assertGreater(result["facts"]["last_push_age_days"], 1000)
        self.assertEqual(result["facts"]["maintainers"], [])
        self.assertNotIn("score", result)
        self.assertTrue(any("human maintainer" in gap for gap in result["gaps"]))
        self.assertEqual(result, pg.maintenance_evidence(IDENTITY, AT, maintenance()))

    def test_archive_eol_and_prerelease_stay_distinct(self):
        evidence = maintenance(
            repository={"archived": True, "pushed_at": "2025-01-01T00:00:00Z"},
            latest_release={"tag_name": "v2rc", "draft": False, "prerelease": True,
                            "published_at": "2026-01-01T00:00:00Z"},
            support={"status": "eol", "scope": "v1", "source": "support-policy",
                     "declared_at": "2025-01-01T00:00:00Z", "eol_at": "2026-01-01T00:00:00Z",
                     "evidence_type": "self_report"})
        result = pg.maintenance_evidence(IDENTITY, AT, evidence)
        self.assertTrue(result["facts"]["archived"])
        self.assertNotIn("latest_stable_release", result["facts"])
        self.assertEqual(result["facts"]["support"]["status"], "eol")
        with self.assertRaisesRegex(ValueError, "after evaluated_at"):
            pg.maintenance_evidence(IDENTITY, AT, maintenance(
                latest_commit={"committed_at": "2027-01-01T00:00:00Z",
                               "author_type": "User"}))

    def test_human_review_requires_named_dated_source(self):
        evidence = maintenance(maintainers=[{"identity": "Alice", "source": "PR review",
                                             "evidence_type": "manual_observation",
                                             "last_human_review_at": "2026-11-01T00:00:00Z"}])
        self.assertEqual(pg.maintenance_evidence(IDENTITY, AT, evidence)["facts"][
            "maintainers"][0]["last_human_review_age_days"], 11)
        self.assertEqual(pg.maintenance_evidence(IDENTITY, AT, evidence)["status"], "ok")
        evidence["maintainers"][0].pop("source")
        with self.assertRaisesRegex(ValueError, "source"):
            pg.maintenance_evidence(IDENTITY, AT, evidence)


class ThreatTests(unittest.TestCase):
    def test_reviewed_area_does_not_claim_whole_project_coverage(self):
        result = pg.threat_evidence(IDENTITY, AT, threat())
        self.assertEqual(result["facts"]["reviewed_areas"][0]["coverage"], "current")
        self.assertIsNone(result["facts"]["project_wide_coverage"])
        self.assertTrue(result["gaps"])

    def test_self_report_partial_future_mismatch_and_missing_boundaries(self):
        partial = threat()
        partial["areas"][0].update(coverage="partial", evidence_type="self_report",
                                    limitations=["payment flow not reviewed"])
        result = pg.threat_evidence(IDENTITY, AT, partial)
        self.assertTrue(any("self-reported" in gap for gap in result["gaps"]))
        self.assertTrue(any("partial coverage" in gap for gap in result["gaps"]))
        with self.assertRaisesRegex(ValueError, "revision"):
            pg.threat_evidence(IDENTITY, AT, threat(revision="other"))
        with self.assertRaisesRegex(ValueError, "after evaluated_at"):
            pg.threat_evidence(IDENTITY, AT, threat(
                areas=[{**threat()["areas"][0], "reviewed_at": "2027-01-01T00:00:00Z"}]))
        with self.assertRaisesRegex(ValueError, "trust boundaries"):
            pg.threat_evidence(IDENTITY, AT, threat(
                areas=[{**threat()["areas"][0], "trust_boundaries": []}]))

    def test_explicit_local_target_without_remote_or_immutable_commit(self):
        local = {"kind": "local_directory", "requested": "./project",
                 "path": "/tmp/project", "resolved": True,
                 "verified": False, "git_dirty": True}
        evidence = threat(target="./project", revision="reviewed-working-copy")
        result = pg.threat_evidence(local, AT, evidence)
        self.assertFalse(result["facts"]["revision_verified"])
        self.assertIn("not independently bound", result["limitations"][-1])


if __name__ == "__main__":
    unittest.main()
