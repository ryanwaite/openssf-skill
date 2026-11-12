"""Target parsing and immutable-scope regression tests."""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from target_identity import resolve_target


class TestTargetIdentity(unittest.TestCase):
    def test_local_directory_and_file_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = resolve_target(str(root))
            self.assertEqual(source["kind"], "local_directory")
            self.assertFalse(source["immutable"])
            lockfile = root / "package-lock.json"
            lockfile.write_text('{"lockfileVersion":3}')
            file_target = resolve_target(str(lockfile))
            self.assertEqual(file_target["file_type"], "lockfile")
            self.assertEqual(file_target["sha256"],
                             hashlib.sha256(lockfile.read_bytes()).hexdigest())
            self.assertTrue(file_target["verified"])
            spdx = root / "artifact.spdx.json"
            spdx.write_text('{"spdxVersion":"SPDX-2.3"}')
            self.assertEqual(resolve_target(str(spdx))["file_type"], "spdx")

    def test_git_clean_vs_dirty_and_safe_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", directory, "init", "-q"], check=True)
            subprocess.run(["git", "-C", directory, "config", "user.email",
                            "tester@example.test"], check=True)
            subprocess.run(["git", "-C", directory, "config", "user.name", "Test"], check=True)
            (root / "README").write_text("content")
            subprocess.run(["git", "-C", directory, "add", "README"], check=True)
            subprocess.run(["git", "-C", directory, "commit", "-qm", "initial"], check=True)
            subprocess.run(["git", "-C", directory, "remote", "add", "origin",
                            "git@github.com:example/repo.git"], check=True)
            clean = resolve_target(directory)
            self.assertTrue(clean["immutable"])
            self.assertEqual(clean["repo"], "github.com/example/repo")
            (root / "untracked").write_text("changed")
            dirty = resolve_target(directory)
            self.assertTrue(dirty["git_dirty"])
            self.assertFalse(dirty["immutable"])
            self.assertEqual(dirty["git_commit"], clean["git_commit"])

    def test_exact_remote_package_and_image_coordinates(self):
        commit = "a" * 40
        repo = resolve_target(f"https://github.com/example/repo@{commit}")
        self.assertEqual((repo["kind"], repo["commit"], repo["immutable"]),
                         ("repo", commit, True))
        branch = resolve_target("example/repo@main")
        self.assertFalse(branch["immutable"])
        self.assertEqual(branch["ref"], "main")
        pkg = resolve_target("@scope/name@1.2.3", "npm")
        self.assertEqual((pkg["ecosystem"], pkg["name"], pkg["version"]),
                         ("npm", "@scope/name", "1.2.3"))
        self.assertFalse(pkg["immutable"])
        purl = resolve_target("pkg:npm/%40scope/name@1.2.3")
        self.assertEqual(purl["identifier"], pkg["identifier"])
        maven = resolve_target("pkg:maven/example.group/library@1.2.3")
        self.assertEqual(maven["name"], "example.group:library")
        self.assertEqual(maven["purl"], "pkg:maven/example.group/library@1.2.3")
        self.assertEqual(resolve_target("example.group:library@1.2.3", "Maven")["purl"],
                         maven["purl"])
        image = resolve_target("registry.example/app@sha256:" + "f" * 64)
        self.assertEqual(image["kind"], "image")
        self.assertTrue(image["immutable"])
        self.assertFalse(image["verified"])

    def test_missing_paths_and_unsupported_or_ambiguous_targets(self):
        for target, ecosystem in (
                ("./missing/lockfile", None), ("/nonexistent/lockfile", None),
                ("package-lock.json", None), ("left-pad", None),
                ("left-pad@1.0", None), ("ftp://github.com/x/y", None),
                ("https://gitlab.com/x/y", None),
                ("registry/app@sha256:ab", None),
                ("pkg:npm/name@1?arch=amd64", None)):
            with self.subTest(target=target), self.assertRaises(ValueError):
                resolve_target(target, ecosystem)
        self.assertEqual(resolve_target("left-pad@1.0", "npm")["version"], "1.0")
        for target in ("left-pad@latest", "left-pad@^1.0", "left-pad@1.*"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                resolve_target(target, "npm")


if __name__ == "__main__":
    unittest.main()
