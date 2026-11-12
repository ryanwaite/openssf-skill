"""Explicit, bounded public remote acquisition for exact ensemble targets."""

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import time
from urllib import error, parse, request


MAX_RESPONSE = 8 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXTRACTED = 64 * 1024 * 1024
MAX_TAR_BYTES = MAX_EXTRACTED + 8 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_FILES = 2000
MAX_ENTRIES = 4000
MAX_PAGES = 20
_SHA = re.compile(r"[0-9a-fA-F]{40}")
_REPO_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")


class RemoteAcquisitionError(ValueError):
    """Public acquisition failed; messages are safe for user-facing reports."""


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RemoteAcquisitionError("Remote endpoint redirected; only fixed public API hosts are allowed")


def _read(url, *, payload=None, limit=MAX_RESPONSE):
    parts = parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in (
            "api.github.com", "codeload.github.com", "api.osv.dev") or \
            parts.username or parts.password or parts.port or parts.fragment:
        raise RemoteAcquisitionError("Remote endpoint is outside the public HTTPS allowlist")
    headers = {"Accept": "application/vnd.github+json" if parts.hostname == "api.github.com"
               else "application/json" if parts.hostname == "api.osv.dev"
               else "application/octet-stream", "User-Agent": "openssf-ensemble-eval"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    opener = request.build_opener(_NoRedirect())
    try:
        with opener.open(request.Request(url, data=payload, headers=headers), timeout=15) as response:
            if response.status != 200:
                raise RemoteAcquisitionError("Remote endpoint returned a non-success status")
            chunks = []
            size = 0
            deadline = time.monotonic() + 30
            while True:
                if time.monotonic() > deadline:
                    raise RemoteAcquisitionError("Remote request exceeded its time limit")
                chunk = response.read(min(65536, limit + 1 - size))
                size += len(chunk)
                if size > limit:
                    raise RemoteAcquisitionError("Remote response exceeds the configured size limit")
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
    except RemoteAcquisitionError:
        raise
    except (error.URLError, OSError, TimeoutError) as exc:
        raise RemoteAcquisitionError(
            "Remote request failed; verify public access and retry or supply local evidence"
        ) from exc


def _json(url, *, payload=None, limit=MAX_RESPONSE):
    raw = _read(url, payload=payload, limit=limit)
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise RemoteAcquisitionError("Remote endpoint returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise RemoteAcquisitionError("Remote endpoint returned an unexpected JSON shape")
    return data


def _entry_path(name, root):
    if not isinstance(name, str) or len(name) > 1024 or "\\" in name or "\x00" in name:
        raise RemoteAcquisitionError("Archive contains an unsafe entry path")
    path = PurePosixPath(name)
    parts = path.parts
    if not parts or len(parts) > 32 or parts[0] != root or path.is_absolute() or \
            any(part in (".", "..") for part in name.split("/")) or \
            any(":" in part or any(ord(char) < 32 for char in part) for part in parts):
        raise RemoteAcquisitionError("Archive contains an unsafe entry path")
    return parts[1:]


def _extract(raw, dest):
    start = time.monotonic()
    seen = {}
    files = total = entries = 0
    try:
        chunks = []
        tar_bytes = 0
        with gzip.GzipFile(fileobj=BytesIO(raw)) as compressed:
            while True:
                if time.monotonic() - start > 20:
                    raise RemoteAcquisitionError("Archive extraction exceeded its time limit")
                chunk = compressed.read(min(65536, MAX_TAR_BYTES + 1 - tar_bytes))
                tar_bytes += len(chunk)
                if tar_bytes > MAX_TAR_BYTES:
                    raise RemoteAcquisitionError("Archive exceeds the decompression size limit")
                if not chunk:
                    break
                chunks.append(chunk)
        with tarfile.open(fileobj=BytesIO(b"".join(chunks)), mode="r:") as archive:
            root = None
            for entry in archive:
                entries += 1
                if entries > MAX_ENTRIES:
                    raise RemoteAcquisitionError("Archive exceeds the entry count limit")
                if time.monotonic() - start > 20:
                    raise RemoteAcquisitionError("Archive extraction exceeded its time limit")
                if root is None:
                    root_parts = PurePosixPath(entry.name).parts
                    if not root_parts:
                        raise RemoteAcquisitionError("Archive contains an empty entry path")
                    root = root_parts[0]
                parts = _entry_path(entry.name, root)
                if not parts:
                    if not entry.isdir():
                        raise RemoteAcquisitionError("Archive root is not a directory")
                    continue
                relative = PurePosixPath(*parts).as_posix()
                if relative in seen or any(
                        seen.get(PurePosixPath(*parts[:index]).as_posix()) == "file"
                        for index in range(1, len(parts))):
                    raise RemoteAcquisitionError("Archive contains duplicate or conflicting entries")
                if not entry.isdir() and not entry.isfile():
                    raise RemoteAcquisitionError("Archive contains a link or unsupported entry")
                if entry.isdir() and entry.size:
                    raise RemoteAcquisitionError("Archive directory has unexpected contents")
                seen[relative] = "dir" if entry.isdir() else "file"
                target = dest.joinpath(*parts)
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                files += 1
                total += entry.size
                if files > MAX_FILES or entry.size < 0 or entry.size > MAX_FILE or \
                        total > MAX_EXTRACTED:
                    raise RemoteAcquisitionError("Archive exceeds the file or extraction size limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(entry)
                if stream is None:
                    raise RemoteAcquisitionError("Archive member could not be read")
                with target.open("xb") as output:
                    remaining = entry.size
                    while remaining:
                        if time.monotonic() - start > 20:
                            raise RemoteAcquisitionError("Archive extraction exceeded its time limit")
                        chunk = stream.read(min(65536, remaining))
                        if not chunk:
                            raise RemoteAcquisitionError("Archive member is truncated")
                        output.write(chunk)
                        remaining -= len(chunk)
            if files == 0:
                raise RemoteAcquisitionError("Archive has no regular files to scan")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise RemoteAcquisitionError("Repository archive is malformed or cannot be extracted") from exc
    return {"files": files, "extracted_bytes": total}


@contextmanager
def acquire_repository(identity):
    """Resolve a public GitHub commit and extract its archive into a cleaned-up directory."""
    if identity.get("kind") != "repo":
        raise RemoteAcquisitionError("Repository acquisition requires a GitHub repository target")
    parts = identity["repo"].split("/")
    if len(parts) != 3 or parts[0] != "github.com" or not all(
            _REPO_PART.fullmatch(part) and part not in (".", "..") for part in parts[1:]):
        raise RemoteAcquisitionError("Repository owner/name must be a public GitHub path")
    owner, repo = parts[1:]
    ref = identity.get("ref") or "HEAD"
    if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", ref) \
            or ".." in ref or ref.startswith(("/", "-")):
        raise RemoteAcquisitionError("Unsupported GitHub ref")
    base = f"https://api.github.com/repos/{owner}/{repo}"
    commit_info = _json(f"{base}/commits/{parse.quote(ref, safe='')}")
    commit = commit_info.get("sha")
    if not isinstance(commit, str) or not _SHA.fullmatch(commit):
        raise RemoteAcquisitionError("GitHub did not return a full commit SHA")
    commit = commit.lower()
    if identity.get("commit") and identity["commit"] != commit:
        raise RemoteAcquisitionError("GitHub returned a different commit than requested")
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit}"
    archive = _read(url, limit=MAX_ARCHIVE)
    with tempfile.TemporaryDirectory(prefix="openssf-remote-") as directory:
        source = Path(directory) / "source"
        source.mkdir()
        counts = _extract(archive, source)
        metadata = {
            "kind": "github_archive", "host": "github.com", "repo": identity["repo"],
            "requested_ref": identity.get("ref") or "HEAD", "commit": commit,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "archive_bytes": len(archive), **counts,
            "scope": "public commit archive; no submodules, build or code execution",
            "binding": "GitHub commit API SHA and commit-addressed codeload archive; "
                       "archive content is not independently attested",
        }
        yield source, metadata


def query_package(identity):
    """Read only official OSV advisories for one exact package version."""
    if identity.get("kind") != "package":
        raise RemoteAcquisitionError("OSV query requires an exact-version package target")
    query = {"package": {"ecosystem": identity["ecosystem"], "name": identity["name"]},
             "version": identity["version"]}
    advisories = []
    seen = set()
    total_bytes = 0
    deadline = time.monotonic() + 90
    for page in range(1, MAX_PAGES + 1):
        if time.monotonic() > deadline:
            raise RemoteAcquisitionError("OSV query exceeded its time limit")
        body = json.dumps(query).encode("utf-8")
        raw = _read("https://api.osv.dev/v1/query", payload=body)
        total_bytes += len(raw)
        if total_bytes > MAX_RESPONSE:
            raise RemoteAcquisitionError("OSV query exceeded the total response size limit")
        try:
            result = json.loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise RemoteAcquisitionError("OSV query returned invalid JSON") from exc
        if not isinstance(result, dict) or set(result) - {"vulns", "next_page_token"} or \
                not isinstance(result.get("vulns", []), list):
            raise RemoteAcquisitionError("OSV query returned an invalid advisory list")
        advisories.extend(result.get("vulns", []))
        if len(advisories) > 2000:
            raise RemoteAcquisitionError("OSV query exceeded the advisory count limit")
        token = result.get("next_page_token")
        if token is None:
            break
        if not isinstance(token, str) or not token or len(token) > 4096 or token in seen:
            raise RemoteAcquisitionError("OSV query returned an invalid pagination token")
        seen.add(token)
        query["page_token"] = token
    else:
        raise RemoteAcquisitionError("OSV query pagination exceeded its page limit")
    metadata = {
        "kind": "osv_version_query", "host": "api.osv.dev",
        "purl": identity["purl"], "ecosystem": identity["ecosystem"],
        "name": identity["name"], "version": identity["version"],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "pages": page, "advisories": len(advisories),
        "scope": "exact-version OSV advisory lookup only; no package content, "
                 "malicious-code absence, or dependency closure verified",
    }
    return advisories, metadata
