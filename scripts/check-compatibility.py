#!/usr/bin/env python3
"""Validate copyable workflow examples offline; optionally check their refs online.

PyYAML is only needed for this maintainer/CI check, not for using the skill.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
ACTION = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[A-Za-z0-9_./-]+)?@([A-Za-z0-9_.-]+)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(\S+)\s+#\s*(v\d+\.\d+\.\d+)\s*$", re.MULTILINE
)
FENCE = re.compile(r"^```(yaml|yml)\s*$", re.IGNORECASE)
MAX_REQUESTS = 40


class ValidationError(ValueError):
    pass


def yaml_blocks(text, source):
    """Return (line, content) for explicit YAML fences, never raw Markdown."""
    blocks = []
    start = None
    content = []
    for line, value in enumerate(text.splitlines(), 1):
        if start is None:
            if FENCE.fullmatch(value):
                start = line + 1
                content = []
        elif value == "```":
            blocks.append((start, "\n".join(content) + "\n"))
            start = None
        else:
            content.append(value)
    if start is not None:
        raise ValidationError(f"{source}:{start - 1}: unterminated YAML fence")
    return blocks


def examples(root, excluded=None):
    """Yield template YAML, GitLab fenced YAML, and runnable reference workflows."""
    templates = sorted((root / "workflows").glob("*.yml.template"))
    if not templates:
        raise ValidationError("no workflow templates found")
    for path in templates:
        text = path.read_text(encoding="utf-8")
        if path.name.startswith("gitlab-"):
            blocks = yaml_blocks(text, path.relative_to(root))
            if not blocks:
                raise ValidationError(f"{path.relative_to(root)}: no YAML fences")
            for line, block in blocks:
                yield str(path.relative_to(root)), line, block, "gitlab"
        else:
            yield str(path.relative_to(root)), 1, text, "github-template"
    for path in sorted((root / "references").rglob("*.md")):
        for line, block in yaml_blocks(path.read_text(encoding="utf-8"), path.relative_to(root)):
            if (re.search(r"(?m)^name:\s*", block)
                    and re.search(r"(?m)^on:\s*", block)
                    and re.search(r"(?m)^jobs:\s*", block)):
                yield str(path.relative_to(root)), line, block, "github-example"
            elif excluded is not None:
                reason = (
                    "unsafe illustration" if re.search(r"(?im)^\s*#.*\b(dangerous|bad)\b", block)
                    else "partial workflow fragment" if re.search(r"(?m)^\s*(on|jobs|uses):", block)
                    else "non-workflow YAML"
                )
                excluded.append((str(path.relative_to(root)), line, reason))
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        yield str(path.relative_to(root)), 1, path.read_text(encoding="utf-8"), "github-ci"


def load_yaml(source, text):
    try:
        import yaml
    except ImportError as exc:
        raise ValidationError("PyYAML is required for maintainer checks: install PyYAML==6.0.2") from exc

    class UniqueLoader(yaml.BaseLoader):
        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise ValidationError(f"{source}: duplicate YAML key {key!r}")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        return yaml.load(text, Loader=UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValidationError(f"{source}: invalid YAML: {exc}") from exc


def action_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses":
                yield child
            else:
                yield from action_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from action_refs(child)


def validate_workflow(value, source):
    if not isinstance(value, dict) or not value.get("name") or not value.get("on"):
        raise ValidationError(f"{source}: expected name and on in workflow")
    jobs = value.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValidationError(f"{source}: expected nonempty jobs mapping")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValidationError(f"{source}: job {job_name} must be a mapping")
        if "uses" in job:
            if "steps" in job or "runs-on" in job:
                raise ValidationError(f"{source}: reusable job {job_name} cannot declare steps/runs-on")
        else:
            if not job.get("runs-on") or not isinstance(job.get("steps"), list) or not job["steps"]:
                raise ValidationError(f"{source}: job {job_name} needs runs-on and nonempty steps")
            for step in job["steps"]:
                if not isinstance(step, dict) or ("uses" in step) == ("run" in step):
                    raise ValidationError(f"{source}: job {job_name} steps need exactly one of uses/run")


def validate_gitlab(value, source):
    if "stages" in value and (
        not isinstance(value["stages"], list) or not all(isinstance(s, str) for s in value["stages"])
    ):
        raise ValidationError(f"{source}: GitLab stages must be a list")
    jobs = {key: job for key, job in value.items() if key not in ("stages", "variables", "include")}
    if not jobs:
        raise ValidationError(f"{source}: expected at least one GitLab job")
    for name, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("script"), (str, list)):
            raise ValidationError(f"{source}: GitLab job {name} needs a script")


def validate_ref(ref, source, kind, policy):
    if not isinstance(ref, str):
        raise ValidationError(f"{source}: uses must be a string")
    if ref.startswith("./"):
        return None
    match = ACTION.fullmatch(ref)
    if not match or ".." in ref:
        raise ValidationError(f"{source}: malformed remote uses ref {ref!r}")
    repo, path, revision = match.groups()
    if any(entry["repository"] == repo and entry["ref"] == revision
           for entry in policy["forbidden_refs"]):
        raise ValidationError(f"{source}: unavailable ref {ref}; update the example")
    if kind in ("github-template", "github-ci") and not SHA.fullmatch(revision):
        exception = policy["tag_exception"]
        allowed = (repo == exception["repository"]
                   and path == "/" + exception["path"]
                   and re.fullmatch(exception["version_pattern"], revision))
        if not allowed:
            raise ValidationError(f"{source}: pin {ref} to a full commit SHA")
    return repo, path, revision


def runtime_notes(workflow, source, policy, version_comments):
    notes = []
    requirement = policy["runner_requirement"]
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            ref = step.get("uses", "")
            if not isinstance(ref, str) or not ref.startswith(requirement["repository"] + "@"):
                continue
            tag = version_comments.get(ref)
            if not tag:
                notes.append(
                    f"{source}: UNKNOWN: {ref} version is not annotated; check whether "
                    f"runner >= {requirement['minimum_runner']} is required"
                )
                continue
            major = int(tag.split(".", 1)[0].removeprefix("v"))
            if major >= requirement["major_version"] and job["runs-on"] not in (
                "ubuntu-latest", "ubuntu-24.04", "windows-latest", "macos-latest"
            ):
                notes.append(
                    f"{source}: UNKNOWN: {ref} requires runner >= {requirement['minimum_runner']}; "
                    "verify the self-hosted runner version separately"
                )
    return notes


def check_offline(root):
    policy = json.loads((root / "scripts" / "compatibility-policy.json").read_text(encoding="utf-8"))
    refs = {}
    counts = {"github-template": 0, "github-example": 0, "github-ci": 0, "gitlab": 0}
    selected = {}
    excluded = []
    notes = []
    for path, line, text, kind in examples(root, excluded):
        source = f"{path}:{line}"
        value = load_yaml(source, text)
        if not isinstance(value, dict) or not value:
            raise ValidationError(f"{source}: expected a nonempty YAML mapping")
        if kind == "gitlab":
            validate_gitlab(value, source)
        if kind.startswith("github"):
            validate_workflow(value, source)
            version_comments = dict(VERSION_COMMENT.findall(text))
            for ref in action_refs(value):
                parsed = validate_ref(ref, source, kind, policy)
                if parsed and kind == "github-template":
                    refs[parsed] = None
            if kind == "github-template":
                notes.extend(runtime_notes(value, source, policy, version_comments))
                for ref, tag in version_comments.items():
                    parsed = validate_ref(ref, source, kind, policy)
                    if parsed:
                        refs[parsed] = tag
            elif kind == "github-example":
                selected[path] = selected.get(path, 0) + 1
        counts[kind] += 1
    if selected != policy["reference_workflows"]:
        raise ValidationError(
            f"runnable Markdown workflow inventory changed: expected {policy['reference_workflows']}, "
            f"found {selected}; review examples and update the policy inventory"
        )
    return counts, refs, excluded, notes


def github_json(path, token):
    request = Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "openssf-skill-compatibility-check",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def check_live(refs, token):
    """Resolve each template ref; check version comments and reusable workflow paths."""
    checks = set()
    for (repo, path, revision), tag in refs.items():
        checks.add((repo, path, revision, tag))
    requests = sum(1 + bool(path) + bool(tag) for _, path, _, tag in checks)
    if requests > MAX_REQUESTS:
        raise ValidationError(f"live checks exceed the {MAX_REQUESTS}-request bound")
    errors = []
    for repo, path, revision, tag in sorted(checks, key=str):
        prefix = f"/repos/{repo}"
        try:
            commit = github_json(f"{prefix}/commits/{quote(revision, safe='')}", token)
            if SHA.fullmatch(revision) and commit["sha"] != revision:
                errors.append(f"{repo}@{revision}: resolved SHA mismatch")
            if tag:
                tagged = github_json(f"{prefix}/commits/{quote(tag, safe='')}", token)
                if tagged["sha"] != commit["sha"]:
                    errors.append(f"{repo}@{revision}: comment {tag} resolves to {tagged['sha']}")
            if path:
                github_json(f"{prefix}/contents/{quote(path.lstrip('/'), safe='/')}?ref={quote(revision, safe='')}", token)
        except (HTTPError, URLError, TimeoutError, KeyError, ValueError) as exc:
            detail = f"HTTP {exc.code}" if isinstance(exc, HTTPError) else type(exc).__name__
            errors.append(f"{repo}{path or ''}@{revision}: live lookup UNKNOWN ({detail})")
    return errors, len(checks)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="resolve template refs via GitHub API")
    args = parser.parse_args(argv)
    try:
        counts, refs, excluded, notes = check_offline(ROOT)
        print(f"Offline YAML/shape/ref checks: PASS {counts}")
        print(f"Reference exclusions ({len(excluded)} YAML fences):")
        for path, line, reason in excluded:
            print(f"  EXCLUDED {path}:{line}: {reason}")
        for note in notes:
            print(f"  {note}")
        if not args.live:
            print("Live ref availability: NOT RUN (scheduled/manual check only)")
            return 0
        import os
        checked_at = datetime.now(timezone.utc).isoformat()
        errors, count = check_live(refs, os.environ.get("GITHUB_TOKEN"))
        print(f"Live GitHub ref checks at {checked_at}: {count} refs, "
              f"{'FAIL' if errors else 'PASS'}")
        for error in errors:
            print(f"  ISSUE: {error}")
        return 1 if errors else 0
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"Compatibility validation: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
