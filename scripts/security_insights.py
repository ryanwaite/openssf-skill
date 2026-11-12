"""Optional, local-only Security Insights v2.2.0 self-report ingestion.

No acquisition, URL following, inheritance resolution, scoring, or baseline
conformance is performed here. CUE and a safe YAML parser are optional tools.
"""

from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit


_RELEASE = "2.2.0"
_SCHEMA = Path(__file__).resolve().parent.parent / "references/security-insights/schema-v2.2.0.cue"
_SCHEMA_SHA256 = "4e4b61470b5484fc8969f2a8a77ffbe0712a7c8a870c2079188f246c14cd58b1"
_SCHEMA_SOURCE = ("https://github.com/ossf/security-insights/blob/"
                  "701ac2a02ef17fc8b316f5df685428773c51372a/spec/schema.cue")
_MAX_BYTES = 256_000
_STALE_DAYS = 365
_CANDIDATES = ("security-insights.yml", "security-insights.yaml",
               "security-insights.json", ".github/security-insights.yml",
               ".github/security-insights.yaml", ".github/security-insights.json")
_REPO = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\Z")


def _result(status, facts=None, gaps=None):
    return {"status": status, "facts": facts or {}, "gaps": gaps or []}


def _identity(identity):
    if not isinstance(identity, dict) or identity.get("kind") not in ("repo", "local_directory"):
        raise ValueError("Security Insights requires a repository or local directory target")
    if identity.get("kind") == "local_directory":
        path = identity.get("path")
        if not isinstance(path, str) or not Path(path).is_dir():
            raise ValueError("A local directory target path is required")
    repo = identity.get("repo")
    if repo is not None and (not isinstance(repo, str) or not _REPO.fullmatch(repo)):
        raise ValueError("Invalid target repository identity")
    return repo


def _when(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("evaluated_at must be a timezone-aware ISO-8601 timestamp") from exc
    else:
        raise ValueError("evaluated_at must be a timezone-aware ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise ValueError("evaluated_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _no_constant(_):
    raise ValueError("Non-finite JSON value")


def _parse(content, suffix):
    text = content.decode("utf-8-sig")
    if suffix == ".json":
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    if suffix not in (".yaml", ".yml"):
        raise ValueError("Only .json, .yaml and .yml Security Insights files are supported")
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("YAML parsing requires optional PyYAML; use a JSON file or install PyYAML") from exc

    class StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ValueError("YAML aliases are not accepted")
            return super().compose_node(parent, index)

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.MappingNode):
                raise ValueError("Expected YAML mapping")
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key == "<<" or key in result:
                    raise ValueError("Duplicate, merge, or non-string YAML key")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        if any(isinstance(token, (yaml.TagToken, yaml.AnchorToken, yaml.AliasToken))
               for token in yaml.scan(text)):
            raise ValueError("Explicit YAML tags, anchors, and aliases are not accepted")
        return yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid or unsupported YAML syntax") from exc


def _safe_url(value, label, gaps):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or \
            any(ord(c) < 33 or ord(c) == 127 for c in value):
        gaps.append(f"{label}: URL is missing or unsafe; link omitted.")
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or \
                parsed.username is not None or parsed.password is not None or \
                parsed.query or parsed.fragment or parsed.port is not None or \
                "\\" in value or parsed.hostname.endswith(".") or \
                parsed.netloc != parsed.hostname and \
                parsed.netloc != f"[{parsed.hostname}]":
            raise ValueError("unsafe URL")
    except ValueError:
        gaps.append(f"{label}: URL contains unsupported components or possible credentials; link omitted.")
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _github_repo(url):
    if not url:
        return None
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return None
    parts = parsed.path.removesuffix("/").removesuffix(".git").strip("/").split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        return None
    return f"github.com/{parts[0]}/{parts[1]}".lower()


def _github_document_repo(url):
    if not url:
        return None
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in (
            "github.com", "raw.githubusercontent.com"):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                                 for part in parts[:2]):
        return None
    return f"github.com/{parts[0]}/{parts[1]}".lower()


def _date(value, label, at, gaps):
    if isinstance(value, date) and not isinstance(value, datetime):
        value = value.isoformat()
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        gaps.append(f"{label}: expected an ISO calendar date.")
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        gaps.append(f"{label}: invalid calendar date.")
        return None
    if parsed > at.date():
        gaps.append(f"{label}: date is in the future relative to evaluated_at.")
    return parsed


def _section(doc, key, gaps):
    value = doc.get(key)
    if value is not None and not isinstance(value, dict):
        gaps.append(f"{key}: expected an object.")
        return None
    return value


def _schema_validation(path, content, schema_path, cue_executable):
    schema = _SCHEMA if schema_path is None else Path(schema_path)
    if schema.suffix != ".cue":
        return "unknown", "Caller-supplied trusted CUE schema file unavailable."
    try:
        if hashlib.sha256(schema.read_bytes()).hexdigest() != _SCHEMA_SHA256:
            return "unknown", "CUE schema does not match pinned v2.2.0 release; validation skipped."
    except OSError:
        return "unknown", "Pinned released schema unavailable; validation skipped."
    tool = cue_executable or shutil.which("cue")
    if not tool:
        return "unknown", "CUE CLI unavailable; full released schema validation not performed."
    tool_path = shutil.which(str(tool)) if "/" not in str(tool) else str(tool)
    if not tool_path:
        return "unknown", "CUE CLI unavailable; full released schema validation not performed."
    tool_path = str(Path(tool_path).resolve())
    try:
        proc = subprocess.run(
            [tool_path, "vet", "-d", "#SecurityInsights", str(schema.resolve()), str(path)],
            cwd=_SCHEMA.parent, env={
                "CUE_REGISTRY": "none", "HOME": os.devnull,
                "XDG_CONFIG_HOME": os.devnull, "XDG_CACHE_HOME": os.devnull,
            }, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", "CUE CLI failed or timed out; full schema validation unknown."
    try:
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(content).digest():
            return "unknown", "Document changed during CUE validation; validation unknown."
    except OSError:
        return "unknown", "Document unavailable after CUE validation; validation unknown."
    if proc.returncode:
        return "invalid", "CUE schema validation rejected this document (see local CUE CLI for details)."
    return "valid", None


def read_security_insights(identity, file_path, evaluated_at, *,
                           schema_path=None, cue_executable=None):
    """Read an explicitly selected local file with target/revision-bound provenance.

    schema_path, when supplied, must be a caller-trusted byte-identical copy
    of the released CUE schema, never a path from the reported document.
    """
    repo = _identity(identity)
    at = _when(evaluated_at)
    path = Path(file_path).expanduser().absolute()
    if identity["kind"] == "local_directory":
        root = Path(identity["path"]).resolve()
        try:
            local_path_ok = (path.is_relative_to(root) and path.resolve().is_relative_to(root)
                             and not path.is_symlink()
                             and not any(parent.is_symlink() for parent in path.parents
                                         if parent.is_relative_to(root)))
        except (OSError, RuntimeError):
            local_path_ok = False
        if not local_path_ok:
            return _result("error", gaps=["Security Insights file must be inside the local target, without symlinks."])
    if not path.exists():
        return _result("not_reported", gaps=["Security Insights file not found; controls are unknown, not absent."])
    if not path.is_file() or path.is_symlink():
        return _result("error", gaps=["Security Insights path must be a regular, non-symlink file."])
    try:
        if path.stat().st_size > _MAX_BYTES:
            return _result("error", gaps=["Security Insights document exceeds 256 KB."])
        with path.open("rb") as stream:
            content = stream.read(_MAX_BYTES + 1)
        if len(content) > _MAX_BYTES:
            return _result("error", gaps=["Security Insights document exceeds 256 KB."])
    except OSError:
        return _result("error", gaps=["Security Insights document could not be read."])
    revision = identity.get("git_commit") or identity.get("commit") or identity.get("ref")
    facts = {
        "target": identity.get("repo") or identity.get("requested") or identity.get("path"),
        "revision": revision, "revision_bound": (
            identity["kind"] == "local_directory" and identity.get("git_dirty") is False
            and bool(identity.get("git_commit"))),
        "git_dirty": identity.get("git_dirty"),
        "document_path": str(path),
        "document_sha256": hashlib.sha256(content).hexdigest(),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "evaluated_at": at.isoformat(),
        "schema_source": _SCHEMA_SOURCE if schema_path is None else "caller_supplied_trusted_schema",
        "schema_validation": "unknown",
        "trust": "self_report",
    }
    gaps = []
    try:
        document = _parse(content, path.suffix.lower())
    except ImportError as exc:
        return _result("partial", facts, [str(exc), "No claims were extracted."])
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        return _result("error", facts, [f"Security Insights document could not be safely parsed: {type(exc).__name__}."])
    if not isinstance(document, dict) or not isinstance(document.get("header"), dict):
        return _result("error", facts, ["Security Insights root and header must be objects."])
    header = document["header"]
    version = header.get("schema-version")
    facts["claimed_schema_version"] = version if isinstance(version, str) and len(version) <= 32 else None
    if version != _RELEASE:
        return _result("error", facts, ["Only the released Security Insights v2.2.0 schema is supported; "
                                        "claimed version is missing, older, development, or unknown."])
    facts["schema_version"] = _RELEASE
    updated = _date(header.get("last-updated"), "header.last-updated", at, gaps)
    reviewed = _date(header.get("last-reviewed"), "header.last-reviewed", at, gaps)
    facts["last_updated"] = updated.isoformat() if updated else None
    facts["last_reviewed"] = reviewed.isoformat() if reviewed else None
    if reviewed and updated and reviewed < updated:
        gaps.append("header.last-reviewed predates last-updated; review after changes is unknown.")
    if reviewed and (at.date() - reviewed).days > _STALE_DAYS:
        gaps.append("header.last-reviewed is over 365 days old; current applicability unknown.")
    canonical = _safe_url(header.get("url"), "header.url", gaps)
    facts["claimed_canonical_url"] = canonical
    malformed_scope = canonical is None
    inheritance = header.get("project-si-source")
    if inheritance is not None:
        facts["claimed_project_si_source"] = _safe_url(
            inheritance, "header.project-si-source", gaps)
        malformed_scope |= facts["claimed_project_si_source"] is None
        gaps.append("Project inheritance is not fetched or resolved; inherited claims are unknown.")
    project = _section(document, "project", gaps)
    repository = _section(document, "repository", gaps)
    malformed_scope |= any(key in document and document[key] is not None and
                           not isinstance(document[key], dict)
                           for key in ("project", "repository"))
    if project is None and repository is None:
        gaps.append("Neither local project nor repository scope is reported.")
    claimed_repositories = []
    if project is not None:
        listed = project.get("repositories")
        if not isinstance(listed, list) or not listed or len(listed) > 100:
            gaps.append("project.repositories must list 1-100 repositories.")
            malformed_scope = True
        else:
            for index, entry in enumerate(listed):
                if not isinstance(entry, dict):
                    gaps.append(f"project.repositories[{index}]: expected an object.")
                    malformed_scope = True
                    continue
                url = _safe_url(entry.get("url"), f"project.repositories[{index}].url", gaps)
                if url:
                    claimed_repositories.append(url)
                else:
                    malformed_scope = True
    facts["claimed_project_repositories"] = claimed_repositories
    repository_url = (_safe_url(repository.get("url"), "repository.url", gaps)
                      if repository is not None else None)
    malformed_scope |= repository is not None and repository_url is None
    facts["claimed_repository_url"] = repository_url
    project_match = (None if project is None or repo is None else
                     any(_github_repo(url) == repo.lower() for url in claimed_repositories))
    repository_match = (None if repository is None or repo is None else
                        _github_repo(repository_url) == repo.lower())
    canonical_repo = _github_document_repo(canonical)
    canonical_mismatch = bool(repo and canonical_repo and canonical_repo != repo.lower())
    facts["scope_match"] = {"project": project_match, "repository": repository_match,
                            "canonical_url": False if canonical_mismatch else
                            (True if canonical_repo and repo else None)}
    if project_match is False or repository_match is False or canonical_mismatch:
        gaps.append("Reported project/repository/canonical GitHub scope does not match target; "
                    "claims withheld.")
        return _result("error", facts, gaps)
    if repo is None:
        gaps.append("Target has no verified repository identity; project/repository scope cannot be matched.")
    if project is None:
        gaps.append("Local project scope not reported; inheritance is not resolved.")
    if repository is None:
        gaps.append("Local repository scope not reported.")
    freshness_ok = bool(reviewed and updated and reviewed >= updated and
                        reviewed <= at.date() and updated <= at.date() and
                        (at.date() - reviewed).days <= _STALE_DAYS)
    # Never label structural parsing as full released-schema validation.
    validation, detail = _schema_validation(path, content, schema_path, cue_executable)
    facts["schema_validation"] = validation
    if detail:
        gaps.append(detail)
    if validation == "invalid":
        gaps.append("Malformed released-schema shape; claims withheld.")
        return _result("error", facts, gaps)
    if malformed_scope:
        gaps.append("Malformed required header or reported scope; claims withheld.")
        return _result("error", facts, gaps)
    if not freshness_ok or repo is None:
        gaps.append("Freshness or repository scope unresolved; claims withheld.")
        return _result("partial", facts, gaps)
    claims = []

    def claim(scope, field, value):
        if value is not None:
            claims.append({"scope": scope, "field": field, "value": value,
                           "evidence_type": "self_report", "verified": False,
                           "source": f"{path}#{scope}.{field}"})

    if project is not None:
        documentation = _section(project, "documentation", gaps)
        if project.get("documentation") is not None and documentation is None:
            return _result("error", facts, gaps + ["Malformed project documentation; claims withheld."])
        if documentation is not None:
            for key in ("design", "support-policy"):
                if key in documentation:
                    claim("project", f"documentation.{key}", _safe_url(
                        documentation[key], f"project.documentation.{key}", gaps))
        vulnerability = _section(project, "vulnerability-reporting", gaps)
        if vulnerability is None:
            return _result("error", facts, gaps + ["Malformed project vulnerability reporting; claims withheld."])
        if vulnerability is not None:
            if type(vulnerability.get("reports-accepted")) is bool:
                claim("project", "vulnerability-reporting.reports-accepted",
                      vulnerability["reports-accepted"])
            if "policy" in vulnerability:
                claim("project", "vulnerability-reporting.policy",
                      _safe_url(vulnerability["policy"], "project.vulnerability-reporting.policy", gaps))
    if repository is not None:
        if repository.get("status") in (
                "active", "abandoned", "concept", "inactive", "moved",
                "suspended", "unsupported", "WIP"):
            claim("repository", "status", repository["status"])
        else:
            gaps.append("repository.status is missing or not a released-schema status.")
            return _result("error", facts, gaps + ["Malformed repository status; claims withheld."])
        documentation = _section(repository, "documentation", gaps)
        if repository.get("documentation") is not None and documentation is None:
            return _result("error", facts, gaps + ["Malformed repository documentation; claims withheld."])
        if documentation is not None and "security-policy" in documentation:
            claim("repository", "documentation.security-policy", _safe_url(
                documentation["security-policy"], "repository.documentation.security-policy", gaps))
    facts["claims"] = claims
    if validation == "unknown":
        gaps.append("Extracted claims are unverified self-report; schema validity unknown.")
    else:
        gaps.append("Schema validity confirms format only; claims and URLs are not independently verified.")
    return _result("partial", facts, gaps)


def discover_security_insights(identity, evaluated_at, *, project_dir=None, file_path=None,
                               schema_path=None, cue_executable=None):
    """Explicit local directory discovery, or read an explicit file; never acquire."""
    _identity(identity)
    _when(evaluated_at)
    if project_dir is not None and file_path is not None:
        raise ValueError("Supply a project_dir or a file_path, not both")
    if file_path is not None:
        return read_security_insights(identity, file_path, evaluated_at,
                                      schema_path=schema_path, cue_executable=cue_executable)
    root = project_dir if project_dir is not None else identity.get("path")
    if root is None:
        raise ValueError("Repository targets require an explicit local project_dir or file_path")
    root = Path(root).expanduser().absolute()
    if not root.is_dir():
        return _result("error", gaps=["Security Insights project directory is unavailable."])
    if identity["kind"] == "local_directory" and root.resolve() != Path(identity["path"]).resolve():
        return _result("error", gaps=["Discovery directory does not match local target path."])
    matches = [root / candidate for candidate in _CANDIDATES if (root / candidate).exists()]
    if not matches:
        return _result("not_reported", gaps=["No local Security Insights file reported; "
                                             "controls are unknown, not absent."])
    if len(matches) != 1:
        return _result("error", gaps=["Multiple Security Insights files found; "
                                      "select one explicit local file."])
    return read_security_insights(identity, matches[0], evaluated_at,
                                  schema_path=schema_path, cue_executable=cue_executable)
