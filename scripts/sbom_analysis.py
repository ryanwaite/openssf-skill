"""Optional local SPDX generation and unweighted advisory/inventory graph context.

Neither the Syft inventory nor graph reachability establishes package completeness,
runtime loading, exploitability, schema validation, or a new risk deduction.
"""

import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import unquote

from artifact_evidence import MAX_ARTIFACT, MAX_EVIDENCE, MAX_ITEMS, _file, _hash_file, ingest_spdx


_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi", "Go": "golang",
               "crates.io": "cargo", "Maven": "maven"}
_CONFIG = """check-for-app-update: false
cache:
  ttl: "0"
cpp:
  vcpkg-allow-git-clone: false
golang:
  use-packages-lib: false
  search-remote-licenses: false
java:
  use-network: false
  resolve-transitive-dependencies: false
javascript:
  search-remote-licenses: false
python:
  search-remote-licenses: false
source:
  file:
    digests:
      - sha256
"""
_TIMEOUT = 90
_MAX_DIRS = MAX_ITEMS
_MAX_ROUTES = 10_000
_MAX_PATH_NODES = 128


def _result(status, facts=None, *gaps):
    return {"status": status, "facts": facts or {}, "gaps": list(gaps)}


def _signature(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _snapshot(directory, excluded=None):
    """Bounded local tree fingerprint, not a proof of an immutable build."""
    digest = hashlib.sha256()
    files = 0
    dirs_seen = 0
    discovered_dirs = 1
    size = 0
    deadline = time.monotonic() + _TIMEOUT

    def check_time():
        if time.monotonic() >= deadline:
            raise TimeoutError("Source directory snapshot timed out.")

    pending = [directory]
    while pending:
        check_time()
        root = pending.pop()
        dirs_seen += 1
        if dirs_seen > _MAX_DIRS:
            raise ValueError("Source directory exceeds bounded directory limits.")
        files_here = []
        dirs_here = []
        with os.scandir(root) as entries:
            for entry in entries:
                check_time()
                path = Path(entry.path)
                if path == excluded:
                    continue
                if entry.is_symlink():
                    raise ValueError("Source directory contains a symlink.")
                if entry.is_dir(follow_symlinks=False):
                    dirs_here.append(path)
                    discovered_dirs += 1
                    if discovered_dirs > _MAX_DIRS:
                        raise ValueError("Source directory exceeds bounded directory limits.")
                elif entry.is_file(follow_symlinks=False):
                    files_here.append(path)
                    if files + len(files_here) > MAX_ITEMS:
                        raise ValueError("Source directory exceeds bounded inventory limits.")
                else:
                    raise ValueError("Source directory contains a non-regular file.")
        pending.extend(sorted(dirs_here, reverse=True))
        for path in sorted(files_here):
            check_time()
            stamp = path.stat()
            if path.is_symlink() or size + stamp.st_size > MAX_ARTIFACT:
                raise ValueError("Source directory changed or exceeds bounded inventory limits.")
            files += 1
            digest.update(str(path.relative_to(directory)).encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            digest.update(f"{stamp.st_size}:{stamp.st_mtime_ns}:{stamp.st_ctime_ns}".encode())
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    check_time()
                    size += len(block)
                    if size > MAX_ARTIFACT:
                        raise ValueError("Source directory grew beyond bounded inventory limits.")
                    digest.update(block)
            if _signature(path) != (stamp.st_dev, stamp.st_ino, stamp.st_size,
                                    stamp.st_mtime_ns, stamp.st_ctime_ns):
                raise ValueError("Source directory changed during snapshot.")
    return digest.hexdigest()


def _posix_pipes_available():
    return (os.name == "posix" and
            all(callable(getattr(os, name, None)) for name in
                ("read", "set_blocking", "killpg")) and
            callable(getattr(selectors, "DefaultSelector", None)) and
            hasattr(signal, "SIGKILL"))


def _scratch_directory(target):
    """Use private system temporary storage, not a writable target/caller directory."""
    return tempfile.TemporaryDirectory(prefix="openssf-sbom-")


def _run_syft(command, config_dir, output):
    """Stream bounded output to a private file; never expose tool diagnostics."""
    if not _posix_pipes_available():
        raise NotImplementedError("Bounded Syft execution requires POSIX pipes and process groups.")
    environment = {
        "PATH": os.defpath, "HOME": str(config_dir),
        "XDG_CONFIG_HOME": str(config_dir), "XDG_CACHE_HOME": str(config_dir),
        "XDG_DATA_HOME": str(config_dir), "TMPDIR": str(config_dir),
        "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
        "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "",
    }
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=environment,
                            start_new_session=True)
    selector = selectors.DefaultSelector()
    written = 0
    try:
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + _TIMEOUT
        with output.open("xb") as destination:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Syft timed out.")
                for key, _ in selector.select(remaining):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is proc.stdout:
                        written += len(block)
                        if written > MAX_EVIDENCE:
                            raise ValueError("Generated SPDX exceeds the size limit.")
                        destination.write(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Syft timed out.")
        return proc.wait(timeout=remaining)
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired,
            NotImplementedError, AttributeError):
        if proc.poll() is None:
            if callable(getattr(os, "killpg", None)):
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
            proc.wait()
        raise
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()


def generate_sbom(target_path, scope, *, expected_sha256=None, validate_schema=False):
    """Generate then ingest an SPDX 2.3 SBOM from an explicit local file or directory.

    build_output requires an independently expected digest of the *file*; a
    source_checkout requires an explicit directory. No image references, implicit
    downloads, builds, package installation, or output publication are accepted.
    Temporary generated data is deleted before returning inventory facts.
    """
    workspace = None
    try:
        if scope == "build_output":
            artifact = _file(target_path)
            stamp = _signature(artifact)
            if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
                raise ValueError("An independently expected artifact SHA-256 is required.")
            expected = expected_sha256.lower()
            if _hash_file(artifact) != expected:
                raise ValueError("Local artifact does not match the independently expected SHA-256.")
            source = "file:" + str(artifact)
            before = expected
        elif scope == "source_checkout":
            if expected_sha256 is not None:
                raise ValueError("Source checkout is not an independently bound build artifact.")
            if not isinstance(target_path, (str, Path)) or not str(target_path):
                raise ValueError("Explicit local source directory is required.")
            directory = Path(target_path)
            if ".." in directory.parts or "://" in str(directory) or \
                    directory.is_symlink() or not directory.is_dir():
                raise ValueError("Unsafe or missing local source directory.")
            directory = directory.resolve()
            source = "dir:" + str(directory)
            expected = None
            before = None
        else:
            raise ValueError("Only local build_output and source_checkout generation is supported.")
        tool = shutil.which("syft")
        if not tool:
            return _result("unknown", {"scope": scope, "expected_sha256": expected},
                           "Install an independently verified Syft v1.57.1 binary to optionally generate a local SPDX SBOM.")
        if not _posix_pipes_available():
            return _result("unknown", {"scope": scope, "expected_sha256": expected},
                           "Bounded Syft execution requires POSIX pipes and process groups.")
        workspace = _scratch_directory(directory if scope == "source_checkout" else artifact)
        scratch = Path(workspace.name)
        if scope == "source_checkout":
            before = _snapshot(directory, scratch)
        config = scratch / "config.yaml"
        config.write_text(_CONFIG, encoding="utf-8")
        config.chmod(0o600)
        output = scratch / "inventory.spdx.json"
        command = [tool, "--config", str(config), "scan", source,
                   "-o", "spdx-json@2.3", "--quiet"]
        if scope == "source_checkout" and scratch.is_relative_to(directory):
            command.extend(["--exclude", str(scratch) + "/**"])
        code = _run_syft(command, scratch, output)
        if scope == "build_output" and (artifact.is_symlink() or
                                        _signature(artifact) != stamp):
            raise ValueError("Local target changed during SBOM generation.")
        after = _hash_file(artifact) if scope == "build_output" else _snapshot(directory, scratch)
        if before != after or (scope == "build_output" and (
                artifact.is_symlink() or _signature(artifact) != stamp)):
            raise ValueError("Local target changed during SBOM generation.")
        if code:
            return _result("error", {"scope": scope, "expected_sha256": expected},
                           "Syft failed; no inventory or clean result inferred.")
        inventory = ingest_spdx(output, scope, subject_sha256=expected,
                                expected_sha256=expected, validate_schema=validate_schema)
        if inventory["status"] == "error":
            return inventory
        creators = json.loads(output.read_text(encoding="utf-8")).get(
            "creationInfo", {}).get("creators", [])
        syft_creator = next((creator for creator in creators
                             if isinstance(creator, str) and creator.lower().startswith("tool: syft-")),
                            None)
        inventory["facts"]["generation"] = {
            "tool": "syft", "tool_version": syft_creator.split("syft-", 1)[-1]
            if syft_creator else "unrecorded",
            "format": "SPDX-2.3", "input": source, "scope": scope,
            "expected_artifact_sha256": expected,
            "source_snapshot_sha256": before if scope == "source_checkout" else None,
            "update_check": False, "remote_enrichment": False,
            "network_isolation": "not_enforced",
        }
        inventory["gaps"].append(
            "Syft discovery is not proof of inventory completeness; network isolation is not kernel-enforced.")
        inventory["status"] = "partial"
        return inventory
    except (NotImplementedError, AttributeError):
        return _result("unknown", None, "Bounded Syft execution requires POSIX pipes and process groups.")
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
        if isinstance(exc, OSError):
            return _result("error", None, "Cannot read local target or run Syft.")
        return _result("error", None, str(exc) if not isinstance(
            exc, subprocess.TimeoutExpired) else "Syft timed out.")
    finally:
        if workspace is not None:
            workspace.cleanup()


def _package_identity(package, finding):
    """Match only versioned purls in supported namespaces, never fuzzy names."""
    if not isinstance(package, dict) or not isinstance(finding, dict):
        return False
    ecosystem = finding.get("ecosystem")
    name = finding.get("package")
    version = finding.get("version")
    if not all(isinstance(v, str) and v for v in (ecosystem, name, version)):
        return False
    expected_type = _ECOSYSTEMS.get(ecosystem)
    if not expected_type or package.get("version") != version:
        return False
    if package.get("name") != name:
        return False
    expected_name = name.replace(":", "/", 1) if ecosystem == "Maven" else name
    matches = set()
    for raw in package.get("purls", []):
        if not isinstance(raw, str) or not raw.startswith("pkg:") or "@" not in raw:
            continue
        base, tail = raw.rsplit("@", 1)
        if (unquote(base) == "pkg:" + expected_type + "/" + expected_name and
                unquote(tail.split("?", 1)[0].split("#", 1)[0]) == version):
            matches.add(raw)
    return bool(matches)


def _paths(facts):
    roots = facts.get("described_ids")
    if not isinstance(roots, list) or not roots:
        return {}
    adjacency = {}
    for edge in facts.get("relationships", []):
        if edge["type"] == "DEPENDS_ON":
            adjacency.setdefault(edge["from"], []).append((edge["to"], 1))
        elif edge["type"] == "DEPENDENCY_OF":
            adjacency.setdefault(edge["to"], []).append((edge["from"], 1))
        elif edge["type"] == "CONTAINS":
            adjacency.setdefault(edge["from"], []).append((edge["to"], 0))
    result = {}
    routes = 0
    for root in sorted(set(roots)):
        queue = [(0, 0, root, [root])]
        best = {root: (0, 0)}
        while queue:
            depth, hops, node, path = heapq.heappop(queue)
            if (depth, hops) != best[node]:
                continue
            for other, cost in sorted(adjacency.get(node, [])):
                rank = (depth + cost, hops + 1)
                if other not in best or rank < best[other]:
                    routes += 1
                    if routes > _MAX_ROUTES or len(path) >= _MAX_PATH_NODES:
                        raise ValueError("Inventory graph exceeds the bounded path budget.")
                    best[other] = rank
                    heapq.heappush(queue, (rank[0], rank[1], other, path + [other]))
                    result.setdefault(root, {})[other] = {
                        "root": root, "dependency_depth": rank[0], "path": path + [other]}
        result.setdefault(root, {})[root] = {
            "root": root, "dependency_depth": 0, "path": [root]}
    paths = {}
    for per_root in result.values():
        for node, route in per_root.items():
            paths.setdefault(node, []).append(route)
    return paths


def _triage(finding, signal_data):
    observed = []
    aliases = set(finding.get("aliases", [])) | {finding["id"]}
    for entry in signal_data.get("raw", {}).get("triage", []):
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package", {})
        if not isinstance(pkg, dict) or (pkg.get("ecosystem"), pkg.get("name"),
                pkg.get("version")) != (finding["ecosystem"], finding["package"],
                                        finding["version"]):
            continue
        for group in entry.get("findings", []):
            if not isinstance(group, dict) or not aliases.intersection(group.get("aliases", [])):
                continue
            observed.append({
                "version_status": group.get("version_status", "unresolved"),
                "records": [
                    {"id": record.get("id"), "aliases": record.get("aliases", []),
                     "withdrawn": record.get("withdrawn"),
                     "reported_version_status": record.get("reported_version_status")}
                    for record in group.get("records", []) if isinstance(record, dict)],
            })
    return observed


def correlate_sbom(sbom_result, known_vulns_signal):
    """Annotate already scored OSV findings with inventory paths, without rescoring.

    Graph paths mean *declared dependency/containment*, not executable-code
    reachability. A disconnected package is not evidence that it is absent.
    """
    try:
        if not isinstance(sbom_result, dict) or sbom_result.get("status") not in (
                "ok", "partial") or not isinstance(sbom_result.get("facts"), dict):
            return _result("unknown", None, "No usable SPDX 2.3 inventory graph was supplied.")
        facts = sbom_result["facts"]
        if not isinstance(known_vulns_signal, dict) or \
                known_vulns_signal.get("name") != "known_vulns" or \
                not isinstance(known_vulns_signal.get("raw"), dict):
            return _result("unknown", {"scope": facts.get("scope")},
                           "No normalized known_vulns findings were supplied; an empty match is not a clean scan.")
        findings = known_vulns_signal["raw"].get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_ITEMS:
            raise ValueError("Invalid or oversized known_vulns findings.")
        packages = facts.get("packages")
        if not isinstance(packages, list) or len(packages) > MAX_ITEMS:
            raise ValueError("Invalid or oversized SPDX package inventory.")
        paths = _paths(facts)
        matched = []
        unmatched = []
        for finding in findings:
            if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
                raise ValueError("Invalid normalized advisory finding.")
            candidates = [p for p in packages if _package_identity(p, finding)]
            if not candidates:
                unmatched.append(finding["id"])
                continue
            for package in candidates:
                if len(matched) >= _MAX_ROUTES:
                    raise ValueError("Advisory correlation exceeds the bounded result budget.")
                routes = paths.get(package["id"], [])
                depths = [route["dependency_depth"] for route in routes]
                relation = ("described_subject" if package["id"] in
                            facts.get("described_ids", []) else
                            "direct_dependency" if 1 in depths else
                            "transitive_dependency" if any(n > 1 for n in depths) else
                            "contained" if depths else "disconnected")
                matched.append({
                    "advisory_id": finding["id"],
                    "aliases": finding.get("aliases", []),
                    "ecosystem": finding["ecosystem"], "name": finding["package"],
                    "version": finding["version"], "spdx_id": package["id"],
                    "relation": relation, "paths": routes,
                    "severity": finding.get("severity"),
                    "triage": _triage(finding, known_vulns_signal),
                })
        gaps = [
            "Graph paths describe declared package relationships, not code execution or exploitability.",
            "This context does not modify known_vulns scoring or prove absence of unreported advisories.",
        ]
        if not facts.get("described_ids"):
            gaps.append("Described roots unavailable; graph paths cannot be inferred.")
        if unmatched:
            gaps.append("Some known advisories have no exact SPDX package URL/version identity match.")
        if any(p.get("version") in (None, "") or not p.get("purls") for p in packages):
            gaps.append("Some SPDX packages lack versions or purls; they cannot be precisely matched.")
        if any(m["relation"] == "disconnected" for m in matched):
            gaps.append("Some matched packages are disconnected from described subjects.")
        if any(sum(_package_identity(p, f) for p in packages) > 1 for f in findings):
            gaps.append("Multiple SPDX packages share an advisory identity; component attribution is ambiguous.")
        return _result("partial", {"scope": facts.get("scope"),
                                   "known_vulns_source": known_vulns_signal.get("source"),
                                   "known_vulns_status": known_vulns_signal.get("status"),
                                   "matched": matched, "unmatched_advisory_ids": unmatched,
                                   "finding_count": len(findings),
                                   "schema_validated": facts.get("quality", {}).get("schema_validated", False),
                                   "score_adjustment": None}, *gaps)
    except (KeyError, TypeError, ValueError):
        return _result("error", None,
                       "Inventory graph/findings are malformed or exceed the bounded path/result budget.")
