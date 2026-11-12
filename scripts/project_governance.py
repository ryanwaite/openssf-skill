"""Bounded, unscored repository governance, maintenance, and threat evidence.

The caller supplies a resolved target identity. Network acquisition is possible
only by explicitly injecting a read-only request(path) callable; it must return
{"status": int, "data": JSON value, "next": bool} for paginated responses.
Paths are relative GitHub REST paths, never arbitrary URLs.
"""

from datetime import datetime, timezone
import json
import re
from urllib.parse import quote


_REPO = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\Z")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]+\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_MAX_BYTES = 1_000_000
_MAX_PAGES = 4


def _text(value, label, limit=512):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or \
            any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{label} must be nonempty bounded text")
    return value


def _time(value, label, at=None):
    try:
        timestamp = datetime.fromisoformat(_text(value, label, 64).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    timestamp = timestamp.astimezone(timezone.utc)
    if at is not None and timestamp > at:
        raise ValueError(f"{label} is after evaluated_at")
    return timestamp


def _age(timestamp, at):
    return round((at - timestamp).total_seconds() / 86400, 2)


def _bound(value):
    try:
        size = len(json.dumps(value, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Evidence must be JSON serializable") from exc
    if size > _MAX_BYTES:
        raise ValueError("Evidence exceeds 1 MB")


def _identity(identity):
    if not isinstance(identity, dict) or identity.get("kind") not in ("repo", "local_directory"):
        raise ValueError("A resolved repository target identity is required")
    repo = identity.get("repo")
    match = _REPO.fullmatch(repo) if isinstance(repo, str) else None
    if not match or any(part in (".", "..") or part.startswith("-")
                        for part in match.groups()):
        raise ValueError("A safe github.com/owner/repo identity is required")
    return repo


def _revision(identity):
    return identity.get("git_commit") or identity.get("commit") or identity.get("ref")


def _bound_evidence(identity, evidence, at):
    repo = _identity(identity)
    _bound(evidence)
    if not isinstance(evidence, dict) or type(evidence.get("schema_version")) is not int or \
            evidence["schema_version"] != 1 or \
            evidence.get("target") != repo or \
            evidence.get("revision") != _revision(identity):
        raise ValueError("Evidence target or revision does not match resolved identity")
    _time(evidence.get("captured_at"), "captured_at", at)
    return repo


def _threat_target(identity, evidence, at):
    _bound(evidence)
    if not isinstance(identity, dict) or not isinstance(evidence, dict):
        raise ValueError("Threat evidence needs a target identity and object")
    if identity.get("kind") in ("local_directory", "local_file"):
        if identity.get("resolved") is not True or not isinstance(identity.get("path"), str):
            raise ValueError("An explicitly resolved local target is required")
        target = _text(identity.get("requested"), "local requested target")
        known_revision = (identity.get("git_commit") or identity.get("sha256")
                          if identity.get("verified") is True else None)
        bound_revision = known_revision
    else:
        target = _identity(identity)
        bound_revision = _revision(identity)
        known_revision = (bound_revision if identity.get("verified") is True and
                          isinstance(bound_revision, str) and _SHA.fullmatch(bound_revision)
                          else None)
    revision = _text(evidence.get("revision"), "declared revision")
    if type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 1 or \
            evidence.get("target") != target or \
            bound_revision is not None and revision != bound_revision:
        raise ValueError("Threat evidence target or revision does not match requested target")
    _time(evidence.get("captured_at"), "captured_at", at)
    return target, known_revision == revision


def _branch(value):
    if not isinstance(value, str) or not _BRANCH.fullmatch(value) or \
            value.startswith(("-", "/")) or ".." in value or "//" in value or \
            value.endswith(("/", ".lock")) or len(value) > 255:
        raise ValueError("Invalid literal branch name")
    return value


def _response(value):
    if not isinstance(value, dict) or type(value.get("status")) is not int or \
            not 100 <= value["status"] <= 599 or \
            (value["status"] == 200 and "data" not in value):
        raise ValueError("Expected read-only HTTP response with status and data")
    _bound(value)
    return value


def _pages(request, path):
    pages = []
    for number in range(1, _MAX_PAGES + 1):
        response = _response(request(f"{path}{'&' if '?' in path else '?'}per_page=100&page={number}"))
        pages.append(response)
        if response.get("next") is False or response["status"] != 200:
            break
        if response.get("next") is not True:
            break
    return pages


def _read_governance(identity, branch, request):
    repo = _identity(identity).removeprefix("github.com/")
    base = f"/repos/{repo}"
    metadata = _response(request(base))
    if metadata["status"] == 200 and (
            not isinstance(metadata.get("data"), dict) or
            not isinstance(metadata["data"].get("full_name"), str) or
            metadata["data"]["full_name"].lower() != repo.lower()):
        raise ValueError("Repository metadata must match resolved identity")
    default = (_branch(metadata["data"].get("default_branch"))
               if metadata["status"] == 200 and isinstance(metadata.get("data"), dict)
               else None)
    selected = identity.get("ref")
    if branch is None and (not selected or _SHA.fullmatch(selected)) and default is None:
        return {"schema_version": 1, "target": _identity(identity),
                "revision": _revision(identity), "branch": None,
                "repository_metadata": metadata}
    name = _branch(branch or (selected if selected and not _SHA.fullmatch(selected) else default))
    encoded = quote(name, safe="")
    return {
        "schema_version": 1, "target": _identity(identity),
        "revision": _revision(identity), "branch": name,
        "repository_metadata": metadata,
        "branch_info": _response(request(f"{base}/branches/{encoded}")),
        "branch_protection": _response(request(f"{base}/branches/{encoded}/protection")),
        "effective_rules": _pages(request, f"{base}/rules/branches/{encoded}"),
        "rulesets": _pages(request, f"{base}/rulesets?includes_parents=true"),
        "ruleset_details": {},
    }


def _collect_pages(value, label, gaps):
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_PAGES:
        raise ValueError(f"{label} must contain 1-4 response pages")
    collected = []
    complete = True
    for index, page in enumerate(value):
        page = _response(page)
        if page["status"] != 200:
            gaps.append(f"{label} page {index + 1}: HTTP {page['status']}; permission or visibility unknown.")
            complete = False
            break
        if not isinstance(page["data"], list) or len(page["data"]) > 100:
            raise ValueError(f"{label} pages must contain at most 100 records")
        collected.extend(page["data"])
        if page.get("next") is False:
            if index != len(value) - 1:
                raise ValueError(f"{label} has pages after its last page")
            return collected, complete
        if page.get("next") is not True or index == len(value) - 1:
            gaps.append(f"{label} pagination is incomplete; absence cannot be inferred.")
            complete = False
            break
    return collected, complete


def _actors(value):
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ValueError("Bypass actors must be an object")
    actors = []
    for kind in ("users", "teams", "apps"):
        entries = value.get(kind, [])
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Bypass actor list is invalid")
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("Bypass actor is invalid")
            identifier = item.get("login") if kind == "users" else item.get("slug")
            if identifier is None:
                identifier = item.get("id")
            if not isinstance(identifier, (str, int)) or isinstance(identifier, bool):
                raise ValueError("Bypass actor identity is unavailable")
            actors.append({"type": kind, "id": identifier})
    return actors


def _review_rule(parameters):
    if not isinstance(parameters, dict):
        raise ValueError("Review rule parameters are unavailable")
    count = parameters.get("required_approving_review_count")
    if type(count) is not int or not 0 <= count <= 10:
        raise ValueError("Review approval count is unavailable")
    return {
        "approvals": count,
        "last_push_approval": parameters.get("require_last_push_approval"),
        "codeowner_review": parameters.get("require_code_owner_review"),
        "dismiss_stale_reviews": parameters.get("dismiss_stale_reviews_on_push"),
        "dismissal_restriction": parameters.get("dismissal_restriction"),
        "required_reviewers": parameters.get("required_reviewers", []),
    }


def governance_evidence(identity, evaluated_at, *, snapshot=None, request=None, branch=None):
    """Assess exact-branch controls; never score CODEOWNERS or guess ruleset patterns.

    snapshot uses read-only GitHub response envelopes for repository_metadata,
    branch_info, branch_protection, effective_rules (pages), rulesets (pages),
    and ruleset_details (id -> response). The effective endpoint includes
    active repository and organization rules, but not disabled/evaluate rules.
    evaluated_at=None is allowed only with an explicit live request callable;
    its evaluated and capture times are stamped after the last read.
    """
    if (snapshot is None) == (request is None):
        raise ValueError("Supply exactly one offline snapshot or explicit request callable")
    if evaluated_at is None and request is None:
        raise ValueError("Offline governance evidence requires an explicit evaluated_at")
    at = _time(evaluated_at, "evaluated_at") if evaluated_at is not None else None
    repo = _identity(identity)
    origin = "injected_read_only_request" if request is not None else "caller_supplied_snapshot"
    if request is not None:
        if not callable(request):
            raise ValueError("request must be an injected read-only callable")
        snapshot = _read_governance(identity, branch, request)
        ids = {rule.get("ruleset_id") for page in snapshot.get("effective_rules", [])
               if page["status"] == 200 and isinstance(page["data"], list)
               for rule in page["data"] if isinstance(rule, dict)}
        if len(ids) > 100:
            raise ValueError("Too many effective ruleset identities")
        for identifier in ids - {None}:
            if type(identifier) is not int or identifier < 1:
                raise ValueError("Invalid effective ruleset id")
            snapshot["ruleset_details"][str(identifier)] = _response(
                request(f"/repos/{repo.removeprefix('github.com/')}/rulesets/{identifier}"))
        snapshot["captured_at"] = datetime.now(timezone.utc).isoformat()
        if at is None:
            at = _time(snapshot["captured_at"], "evaluated_at")
    _bound_evidence(identity, snapshot, at)
    ref = identity.get("ref")
    if snapshot.get("branch") is None and branch is None and \
            (not ref or _SHA.fullmatch(ref)):
        metadata = _response(snapshot.get("repository_metadata"))
        if metadata["status"] != 200:
            return {
                "status": "unknown",
                "provenance": {"evidence_type": origin, "authenticated_by_module": False},
                "facts": {"target": repo, "branch": None, "default_branch": None,
                          "evaluated_at": at.isoformat(), "captured_at": snapshot["captured_at"],
                          "protected_branch": None, "required_reviews": None,
                          "predicates": {"protected_branch": {"value": None, "sources": []},
                                         "required_reviews": {"value": None, "sources": []}}},
                "gaps": [f"Repository metadata unavailable (HTTP {metadata['status']}); "
                         "select an explicit branch or inspect default branch with read access."],
                "limitations": ["Settings were not inspected; missing access is not proof of no protection."],
            }
    name = _branch(snapshot.get("branch"))
    if branch is not None and name != _branch(branch):
        raise ValueError("Snapshot branch does not match requested branch")
    if ref and not _SHA.fullmatch(ref) and name != _branch(ref):
        raise ValueError("Snapshot branch does not match verified target ref")
    metadata = _response(snapshot.get("repository_metadata"))
    gaps = []
    if metadata["status"] == 200:
        if not isinstance(metadata.get("data"), dict) or \
                not isinstance(metadata["data"].get("full_name"), str) or \
                metadata["data"]["full_name"].lower() != repo.removeprefix("github.com/").lower():
            raise ValueError("Repository metadata must match verified identity")
        default = _branch(metadata["data"].get("default_branch"))
        if branch is None and not ref and name != default:
            raise ValueError("Snapshot branch does not match repository default")
    else:
        default = None
        gaps.append(f"Repository metadata unavailable (HTTP {metadata['status']}); "
                    "the named branch is not confirmed as default.")
    info = _response(snapshot.get("branch_info"))
    protected_hint = None
    if info["status"] == 200 and isinstance(info["data"], dict) and \
            info["data"].get("name") == name and type(info["data"].get("protected")) is bool:
        protected_hint = info["data"]["protected"]
        commit = identity.get("commit") or identity.get("git_commit")
        if commit and (not isinstance(info["data"].get("commit"), dict) or
                       info["data"]["commit"].get("sha") != commit):
            gaps.append("Branch tip differs from the target revision (or is unavailable); controls describe the branch now.")
    else:
        gaps.append(f"Branch metadata unavailable (HTTP {info['status']}) or does not match branch.")
    protection = _response(snapshot.get("branch_protection"))
    legacy = None
    legacy_disabled = protection["status"] == 200 and isinstance(protection.get("data"), dict) \
        and protection["data"].get("enabled") is False
    review_policies = []
    bypass = []
    if protection["status"] == 200 and isinstance(protection.get("data"), dict) and \
            protection["data"].get("enabled") is not False:
        legacy = protection["data"]
        reviews = legacy.get("required_pull_request_reviews")
        if isinstance(reviews, dict):
            try:
                count = reviews.get("required_approving_review_count")
                if type(count) is not int or not 0 <= count <= 6:
                    raise ValueError("Legacy review approval count unavailable")
                review_policies.append({
                    "source": "branch_protection", "approvals": count,
                    "last_push_approval": reviews.get("require_last_push_approval"),
                    "codeowner_review": reviews.get("require_code_owner_reviews"),
                    "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews"),
                    "dismissal_restrictions": _actors(reviews.get("dismissal_restrictions")),
                })
                bypass.extend(_actors(reviews.get("bypass_pull_request_allowances")))
            except ValueError as exc:
                gaps.append(str(exc))
        if isinstance(legacy.get("enforce_admins"), dict) and \
                legacy["enforce_admins"].get("enabled") is False:
            bypass.append({"type": "RepositoryAdmin", "id": None, "mode": "legacy"})
        elif not isinstance(legacy.get("enforce_admins"), dict) or \
                type(legacy["enforce_admins"].get("enabled")) is not bool:
            gaps.append("Legacy admin enforcement is unavailable; administrative bypass unknown.")
        force = legacy.get("allow_force_pushes")
        if isinstance(force, dict) and force.get("enabled") is True:
            gaps.append("Legacy protection permits force pushes.")
    elif not legacy_disabled:
        gaps.append(f"Branch protection unavailable (HTTP {protection['status']}); 403/404 is not proof of absence.")
    rules, rules_complete = _collect_pages(snapshot.get("effective_rules"), "Effective branch rules", gaps)
    listed, list_complete = _collect_pages(snapshot.get("rulesets"), "Ruleset inventory", gaps)
    details = snapshot.get("ruleset_details")
    if not isinstance(details, dict) or len(details) > 100:
        raise ValueError("Ruleset details must be a bounded id-to-response mapping")
    active = []
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            gaps.append("Unrecognized effective branch rule.")
            continue
        rid = rule.get("ruleset_id")
        if type(rid) is not int or rid < 1:
            gaps.append("Effective rule missing ruleset identity; bypass cannot be checked.")
        if rule["type"] == "pull_request":
            try:
                review_policies.append({"source": "ruleset", "ruleset_id": rid,
                                        **_review_rule(rule.get("parameters"))})
            except ValueError as exc:
                gaps.append(str(exc))
        active.append({"type": rule["type"], "ruleset_id": rid,
                       "source": rule.get("ruleset_source"),
                       "source_type": rule.get("ruleset_source_type")})
    seen = {r["ruleset_id"] for r in active if r["ruleset_id"] is not None}
    for rid in seen:
        detail = details.get(str(rid))
        if detail is None:
            gaps.append(f"Ruleset {rid} details unavailable; bypass actors unknown.")
            continue
        detail = _response(detail)
        data = detail.get("data")
        if detail["status"] != 200 or not isinstance(data, dict) or \
                data.get("id") != rid or data.get("enforcement") != "active":
            gaps.append(f"Ruleset {rid} details unavailable or not actively enforced; bypass actors unknown.")
            continue
        actors = data.get("bypass_actors")
        if not isinstance(actors, list) or len(actors) > 100:
            gaps.append(f"Ruleset {rid} bypass list unavailable.")
            continue
        for actor in actors:
            if not isinstance(actor, dict) or actor.get("actor_type") not in (
                    "Integration", "OrganizationAdmin", "RepositoryRole", "Team", "DeployKey", "User"):
                gaps.append(f"Ruleset {rid} bypass actor type unavailable.")
                continue
            bypass.append({"ruleset_id": rid, "type": actor["actor_type"],
                           "id": actor.get("actor_id"),
                           "mode": actor.get("bypass_mode", "always")})
    inventory = []
    for item in listed:
        if not isinstance(item, dict) or type(item.get("id")) is not int or \
                item.get("enforcement") not in ("active", "evaluate", "disabled"):
            gaps.append("Ruleset inventory entry incomplete.")
            continue
        inventory.append({"id": item["id"], "source_type": item.get("source_type"),
                          "enforcement": item["enforcement"],
                          "effective_for_branch": item["id"] in seen})
    if not list_complete:
        gaps.append("Ruleset inventory cannot establish disabled/evaluate context.")
    protected = True if protected_hint is True or legacy is not None or active else None
    required_reviews = True if any(r["approvals"] > 0 for r in review_policies) else None
    if required_reviews is None and legacy is not None and rules_complete and not gaps:
        required_reviews = False
    if protected is None and protected_hint is False and legacy_disabled and rules_complete:
        protected = False
    if protected_hint is not None and protected is not None and protected_hint != protected:
        gaps.append("Branch protected flag conflicts with visible protection/rules.")
    if protected_hint is True and legacy_disabled and not active and rules_complete:
        gaps.append("Branch reports protection, but visible controls do not explain it.")
    if required_reviews is None and legacy_disabled and rules_complete and not gaps:
        required_reviews = False
    if protected is None:
        gaps.append("Branch protection is unconfirmed; inspect branch settings with read access.")
    if required_reviews is None:
        gaps.append("Required nonauthor approvals are unconfirmed; inspect active review rules.")
    if bypass:
        gaps.append("Bypass actors or roles can evade at least one review control; inspect their scope.")
    owner_review = True if any(r.get("codeowner_review") is True for r in review_policies) else (
        False if review_policies and all(r.get("codeowner_review") is False for r in review_policies)
        else None)
    protection_sources = (
        (["branch_info.protected"] if protected_hint is True else []) +
        (["branch_protection"] if legacy is not None else []) +
        [f"effective_rules.ruleset_id={rule['ruleset_id']}" for rule in active])
    review_sources = [
        "branch_protection.required_pull_request_reviews"
        if policy["source"] == "branch_protection"
        else f"effective_rules.ruleset_id={policy['ruleset_id']}"
        for policy in review_policies if policy["approvals"] > 0]
    if protected is False:
        protection_sources = ["branch_info.protected", "branch_protection.enabled",
                              "effective_rules (complete, empty)"]
    if required_reviews is False:
        review_sources = ["branch_protection.enabled",
                          "effective_rules (complete, no required approvals)"]
    return {
        "status": "ok" if not gaps else "partial" if legacy is not None or active or protected_hint is not None
        else "unknown",
        "provenance": {"evidence_type": origin, "authenticated_by_module": False},
        "facts": {"target": repo, "branch": name, "default_branch": default,
                  "evaluated_at": at.isoformat(), "captured_at": snapshot["captured_at"],
                  "protected_branch": protected, "branch_protected_hint": protected_hint,
                  "branch_protection_status": "enabled" if legacy is not None else
                  "disabled" if legacy_disabled else "unknown",
                  "required_reviews": required_reviews, "review_policies": review_policies,
                  "predicates": {"protected_branch": {"value": protected,
                                                     "sources": protection_sources},
                                 "required_reviews": {"value": required_reviews,
                                                      "sources": review_sources}},
                  "effective_rules": active, "ruleset_inventory": inventory,
                  "bypass_actors": bypass, "codeowners_enforcement": owner_review},
        "gaps": gaps,
        "limitations": ["GitHub settings are point-in-time, not proof each PR received human review.",
                        "Ruleset inventory conditions are not guessed; only the exact-branch effective API establishes applicability.",
                        "CODEOWNERS presence alone cannot establish enforced reviews."],
    }


def maintenance_evidence(identity, evaluated_at, evidence):
    """Summarize declared support and observed activity without abandonment thresholds."""
    at = _time(evaluated_at, "evaluated_at")
    repo = _bound_evidence(identity, evidence, at)
    allowed = {"schema_version", "target", "revision", "captured_at", "repository",
               "latest_commit", "latest_release", "support", "maintainers"}
    if set(evidence) - allowed:
        raise ValueError("Unknown maintenance evidence fields")
    facts = {"target": repo, "evaluated_at": at.isoformat(),
             "captured_at": evidence["captured_at"]}
    gaps = []
    metadata = evidence.get("repository")
    if metadata is not None:
        if not isinstance(metadata, dict) or type(metadata.get("archived")) is not bool:
            raise ValueError("Repository activity needs an explicit archive flag")
        facts["archived"] = metadata["archived"]
        if metadata.get("pushed_at") is not None:
            facts["last_push_age_days"] = _age(_time(metadata["pushed_at"], "pushed_at", at), at)
        if metadata["archived"]:
            gaps.append("Repository is archived; confirm any externally maintained successor or support.")
    else:
        gaps.append("Repository archive and push status not observed.")
    commit = evidence.get("latest_commit")
    if commit is not None:
        if not isinstance(commit, dict):
            raise ValueError("latest_commit must be an object")
        facts["last_commit_age_days"] = _age(_time(commit.get("committed_at"), "committed_at", at), at)
        facts["last_commit_author_type"] = _text(commit.get("author_type"), "author_type", 64)
    else:
        gaps.append("Latest commit and human authorship not observed.")
    release = evidence.get("latest_release")
    if release is not None:
        if not isinstance(release, dict) or type(release.get("draft")) is not bool or \
                type(release.get("prerelease")) is not bool:
            raise ValueError("Release needs explicit draft and prerelease flags")
        if release["draft"] or release["prerelease"]:
            gaps.append("Supplied release is draft/prerelease; latest stable release remains unknown.")
        else:
            facts["latest_stable_release"] = {
                "tag": _text(release.get("tag_name"), "release tag", 255),
                "published_at": release.get("published_at"),
                "age_days": _age(_time(release.get("published_at"), "published_at", at), at)}
    else:
        gaps.append("Latest stable release not observed; this does not establish release cadence.")
    support = evidence.get("support")
    if support is not None:
        if not isinstance(support, dict) or support.get("status") not in ("supported", "eol"):
            raise ValueError("Support declaration must state supported or eol")
        declared = _time(support.get("declared_at"), "support declared_at", at)
        facts["support"] = {"status": support["status"], "scope": _text(support.get("scope"), "support scope"),
                            "source": _text(support.get("source"), "support source"),
                            "declared_at": declared.isoformat(),
                            "evidence_type": support.get("evidence_type")}
        if support.get("evidence_type") not in ("manual_observation", "self_report"):
            raise ValueError("Support declaration needs evidence_type")
        if support.get("eol_at") is not None:
            eol = _time(support["eol_at"], "eol_at")
            if (support["status"] == "eol") != (eol <= at):
                raise ValueError("Support status contradicts EOL date")
            facts["support"]["eol_at"] = eol.isoformat()
        if support["status"] == "eol":
            gaps.append("Declared support has ended for the stated scope; plan mitigation.")
        if support["evidence_type"] == "self_report":
            gaps.append("Support declaration is self-reported, not independently authenticated.")
    else:
        gaps.append("Support/EOL status not declared; archive or activity alone cannot establish it.")
    people = evidence.get("maintainers", [])
    if not isinstance(people, list) or len(people) > 32:
        raise ValueError("Maintainers must be a bounded list")
    facts["maintainers"] = []
    for person in people:
        if not isinstance(person, dict) or person.get("evidence_type") not in (
                "manual_observation", "self_report"):
            raise ValueError("Maintainer needs an evidence type")
        facts["maintainers"].append({
            "identity": _text(person.get("identity"), "maintainer identity", 255),
            "source": _text(person.get("source"), "maintainer source"),
            "evidence_type": person["evidence_type"],
            "last_human_review_age_days": _age(
                _time(person.get("last_human_review_at"), "last_human_review_at", at), at),
        })
    if not people:
        gaps.append("No human maintainer/reviewer evidence; contributors and bot commits are not substitutes.")
    if people and any(p["evidence_type"] == "self_report" for p in people):
        gaps.append("Self-reported maintainer identities or reviews are not independently authenticated.")
    return {
        "status": "ok" if not gaps else "partial" if facts.get("archived") is not None or
        "support" in facts or facts["maintainers"] or "last_commit_age_days" in facts else "unknown",
        "provenance": {"evidence_type": "caller_supplied_snapshot", "authenticated_by_module": False},
        "facts": facts, "gaps": gaps,
        "limitations": ["No abandonment, release-cadence, bus-factor, or freshness threshold is inferred.",
                        "Evidence sources are not independently verified."],
    }


def threat_evidence(identity, evaluated_at, evidence):
    """Record a bounded, reviewed threat-model area without implying whole-project coverage."""
    at = _time(evaluated_at, "evaluated_at")
    target, revision_verified = _threat_target(identity, evidence, at)
    if set(evidence) != {"schema_version", "target", "revision", "captured_at", "areas"}:
        raise ValueError("Threat evidence requires target, revision, capture time, and areas")
    areas = evidence["areas"]
    if not isinstance(areas, list) or not 1 <= len(areas) <= 32:
        raise ValueError("Provide 1-32 reviewed threat-model areas")
    reviewed = []
    gaps = []
    seen = set()
    for area in areas:
        fields = {"scope", "source", "reference", "reviewed_at", "reviewer",
                  "evidence_type", "coverage", "assets", "trust_boundaries", "limitations"}
        if not isinstance(area, dict) or set(area) != fields:
            raise ValueError("Threat area has missing or extra fields")
        scope = _text(area["scope"], "scope")
        if scope in seen:
            raise ValueError("Duplicate reviewed scope")
        seen.add(scope)
        if area["coverage"] not in ("current", "partial", "none") or \
                area["evidence_type"] not in ("manual_observation", "self_report"):
            raise ValueError("Invalid reviewed coverage or evidence type")
        entry = {"scope": scope, "source": _text(area["source"], "source"),
                 "reference": _text(area["reference"], "reference"),
                 "reviewer": _text(area["reviewer"], "reviewer"),
                 "reviewed_at": _time(area["reviewed_at"], "reviewed_at", at).isoformat(),
                 "coverage": area["coverage"], "evidence_type": area["evidence_type"]}
        for key in ("assets", "trust_boundaries", "limitations"):
            values = area[key]
            if not isinstance(values, list) or len(values) > 32:
                raise ValueError(f"{key} must be a bounded list")
            entry[key] = [_text(value, key) for value in values]
        if entry["coverage"] == "current" and not (
                entry["assets"] and entry["trust_boundaries"]):
            raise ValueError("Current scoped coverage needs assets and trust boundaries")
        reviewed.append(entry)
        if entry["coverage"] != "current":
            gaps.append(f"{scope}: {entry['coverage']} coverage; review uncovered assets and boundaries.")
        if entry["evidence_type"] == "self_report":
            gaps.append(f"{scope}: review is self-reported, not independently authenticated.")
        if entry["limitations"]:
            gaps.append(f"{scope}: documented limitations need follow-up.")
    gaps.append("Other project areas remain unknown unless separately reviewed.")
    return {
        "status": "partial",
        "facts": {"target": target, "revision": evidence["revision"],
                  "revision_verified": revision_verified,
                  "evaluated_at": at.isoformat(), "captured_at": evidence["captured_at"],
                  "reviewed_areas": reviewed, "project_wide_coverage": None},
        "gaps": gaps,
        "limitations": ["References are not fetched or independently verified.",
                        "A reviewer name or document filename is not proof of independent or adequate review.",
                        "The declared revision is not independently bound to an immutable target."
                        if not revision_verified else "Evidence covers only its declared reviewed scope."],
    }
