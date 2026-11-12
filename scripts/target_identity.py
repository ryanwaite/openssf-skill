"""Explicit, non-acquiring target resolution for the ensemble evaluator."""

import hashlib
import re
import subprocess
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA = re.compile(r"[0-9a-fA-F]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}")
_VERSION = re.compile(r"[^\s/@?#]+")
_ECOSYSTEMS = {"npm", "PyPI", "Go", "crates.io", "Maven", "NuGet", "RubyGems"}
_PURL_TYPES = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
               "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems"}
_ECOSYSTEM_PURL = {value: key for key, value in _PURL_TYPES.items()}
_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
              "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
              "Cargo.lock", "go.mod", "go.sum", "Gemfile.lock", "composer.lock"}


def _git(path: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                               "-c", "core.hooksPath=/dev/null", "-C", str(path), *args],
                              capture_output=True,
                              text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _repo(value: str) -> str | None:
    if value.startswith("git@github.com:"):
        value = value.removeprefix("git@github.com:")
    if value.startswith("https://github.com/"):
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port:
            return None
        value = parsed.path.lstrip("/")
    elif value.startswith("github.com/"):
        value = value.removeprefix("github.com/")
    value = value.removesuffix(".git").rstrip("/")
    return f"github.com/{value}" if _REPO.fullmatch(value) else None


def _file_kind(path: Path) -> str:
    if path.name.endswith((".spdx.json", ".spdx", ".spdx.yml", ".spdx.rdf",
                           ".spdx.rdf.xml")):
        return "spdx"
    if path.name in _LOCKFILES:
        return "lockfile"
    return "file"


def _local(requested: str) -> dict:
    path = Path(requested).expanduser().resolve(strict=True)
    if not (path.is_dir() or path.is_file()):
        raise ValueError("Local target must be a regular file or directory")
    result = {"requested": requested, "kind": "local_directory" if path.is_dir()
              else "local_file", "path": str(path), "resolved": True, "immutable": False}
    if path.is_file():
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        result.update(file_type=_file_kind(path), sha256=digest,
                      identifier=f"sha256:{digest}", immutable=True, verified=True)
        return result
    root = _git(path, "rev-parse", "--show-toplevel")
    if root and Path(root).resolve() == path:
        commit = _git(path, "rev-parse", "--verify", "HEAD")
        status = _git(path, "status", "--porcelain", "--untracked-files=all")
        result["git_commit"] = commit if commit and _SHA.fullmatch(commit) else None
        result["git_dirty"] = status != "" if status is not None else None
        origin = _git(path, "remote", "get-url", "origin")
        repo = _repo(origin) if origin else None
        if repo:
            result["repo"] = repo
        if result["git_commit"] and result["git_dirty"] is False:
            result.update(identifier=f"{result['git_commit']}@{path}",
                          immutable=True, verified=True)
        else:
            result["identifier"] = str(path)
    else:
        result["identifier"] = str(path)
    return result


def _package(requested: str, ecosystem: str | None) -> dict:
    if requested.startswith("pkg:"):
        parsed = urlsplit(requested)
        if parsed.query or parsed.fragment or parsed.netloc:
            raise ValueError("Purl qualifiers and subpaths are not supported")
        match = re.fullmatch(r"pkg:([^/]+)/(.+)@([^/@]+)", requested)
        if not match or match[1].lower() not in _PURL_TYPES:
            raise ValueError("Use a supported exact-version package purl")
        purl_type, name, version = match.groups()
        ecosystem_from_purl = _PURL_TYPES[purl_type.lower()]
        name, version = unquote(name), unquote(version)
        if ecosystem_from_purl == "Maven":
            if name.count("/") != 1 or any(not part for part in name.split("/")):
                raise ValueError("Maven purls require group/artifact")
            name = name.replace("/", ":")
        if ecosystem and ecosystem != ecosystem_from_purl:
            raise ValueError("Purl ecosystem conflicts with --ecosystem")
        ecosystem = ecosystem_from_purl
    else:
        if not ecosystem:
            raise ValueError("Package targets require --ecosystem and an exact version")
        if ecosystem not in _ECOSYSTEMS:
            raise ValueError("Unsupported package ecosystem")
        if requested.startswith("@") and ecosystem == "npm":
            match = re.fullmatch(r"(@[^/@\s]+/[^/@\s]+)@([^/@\s]+)", requested)
        else:
            match = re.fullmatch(r"([^/@\s]+)@([^/@\s]+)", requested)
        if not match:
            raise ValueError("Package targets require an exact version (name@version)")
        name, version = match.groups()
    if not name or not _VERSION.fullmatch(version) or \
            any(char in version for char in "^~><*,|") or \
            version.lower() in ("latest", "next", "stable") or \
            version.upper().endswith("-SNAPSHOT") or \
            any(ch.isspace() or ch in "?#" for ch in name) or \
            (ecosystem == "npm" and name.startswith("@") and
             not re.fullmatch(r"@[^/@\s]+/[^/@\s]+", name)):
        raise ValueError("Invalid package name or exact version")
    purl_name = name.replace(":", "/") if ecosystem == "Maven" else name
    purl = f"pkg:{_ECOSYSTEM_PURL[ecosystem]}/{quote(purl_name, safe='/')}@{quote(version, safe='')}"
    return {"requested": requested, "kind": "package", "ecosystem": ecosystem,
            "name": name, "version": version, "purl": purl,
            "identifier": f"{ecosystem}:{name}@{version}",
            "resolved": True, "immutable": False, "verified": False}


def resolve_target(requested: str, ecosystem: str | None = None) -> dict:
    """Resolve identity without cloning, installing, pulling, or querying registries."""
    if not isinstance(requested, str) or not requested or requested != requested.strip():
        raise ValueError("Target must be a non-empty path or exact target specification")
    if ecosystem is not None and ecosystem not in _ECOSYSTEMS:
        raise ValueError("Unsupported package ecosystem")
    file_name = Path(requested).name
    local_file_name = file_name in _LOCKFILES or file_name.endswith(
        (".spdx.json", ".spdx", ".spdx.yml", ".spdx.rdf", ".spdx.rdf.xml"))
    if requested.startswith(("./", "../", "/", "~/")) or requested in (".", "..") \
            or local_file_name and "/" not in requested:
        if ecosystem:
            raise ValueError("--ecosystem applies only to package targets")
        try:
            return _local(requested)
        except (OSError, ValueError) as exc:
            raise ValueError("Local target path does not exist or cannot be read") from exc
    if requested.startswith("pkg:"):
        return _package(requested, ecosystem)
    if "@sha256:" in requested:
        if ecosystem:
            raise ValueError("--ecosystem applies only to package targets")
        image, sep, digest = requested.rpartition("@")
        if sep and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*", image) and \
                ".." not in image and "://" not in image and "//" not in image and \
                _DIGEST.fullmatch(digest):
            return {"requested": requested, "kind": "image", "image": image,
                    "digest": digest.lower(), "identifier": f"{image}@{digest.lower()}",
                    "resolved": True, "immutable": True, "verified": False}
        raise ValueError("OCI image requires name@sha256:<64 hex digits>")
    if requested.startswith(("https://", "github.com/")) or \
            _REPO.fullmatch(requested.split("@", 1)[0]):
        if ecosystem:
            raise ValueError("--ecosystem applies only to package targets")
        base, _, ref = requested.partition("@")
        repo = _repo(base)
        if not repo or (ref and not re.fullmatch(r"[A-Za-z0-9._/-]+", ref)) or \
                ref.startswith(("-", "/")) or ".." in ref:
            raise ValueError("Supported repository target is a GitHub owner/repo with optional @ref")
        commit = ref.lower() if _SHA.fullmatch(ref) else None
        return {"requested": requested, "kind": "repo", "repo": repo,
                "ref": ref or None, "commit": commit,
                "identifier": f"{repo}@{ref or 'HEAD'}",
                "resolved": bool(commit), "immutable": bool(commit),
                "verified": False}
    if "://" in requested:
        raise ValueError("Only GitHub HTTPS repository URLs are supported")
    if "/" in requested and not requested.startswith("@"):
        raise ValueError("Use ./ for a local path, or a supported GitHub owner/repo")
    return _package(requested, ecosystem)
