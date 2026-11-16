"""Synthetic, local-only SPDX generation and unweighted advisory graph tests."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import artifact_evidence as ae
import sbom_analysis as sb


class SBOMAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.artifact = self.root / "artifact.bin"
        self.artifact.write_bytes(b"already built")
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()

    def document(self, *, described=True):
        return {
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": "https://spdx.org/spdxdocs/synthetic-example",
            "name": "synthetic", "dataLicense": "CC0-1.0",
            "creationInfo": {"created": "2026-11-12T12:00:00Z",
                             "creators": ["Tool: syft-1.57.1"]},
            "packages": [
                {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0",
                 "checksums": [{"algorithm": "SHA256", "checksumValue": self.digest}]},
                {"SPDXID": "SPDXRef-direct", "name": "pkg", "versionInfo": "2.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/pkg@2.0"}]},
                {"SPDXID": "SPDXRef-transitive", "name": "dep", "versionInfo": "3.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/dep@3.0"}]},
                {"SPDXID": "SPDXRef-disconnected", "name": "alone", "versionInfo": "1.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/alone@1.0"}]},
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app",
                 "relationshipType": "DESCRIBES"},
                {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-direct",
                 "relationshipType": "DEPENDS_ON"},
                {"spdxElementId": "SPDXRef-transitive", "relatedSpdxElement": "SPDXRef-direct",
                 "relationshipType": "DEPENDENCY_OF"},
            ] if described else [],
            **({"documentDescribes": ["SPDXRef-app"]} if described else {}),
        }

    def inventory(self, document=None):
        path = self.root / "inventory.json"
        path.write_text(json.dumps(document or self.document()), encoding="utf-8")
        return ae.ingest_spdx(path, "build_output", subject_sha256=self.digest,
                              expected_sha256=self.digest)

    def finding(self, name, version, advisory, ecosystem="npm"):
        return {"id": advisory, "aliases": [advisory], "ecosystem": ecosystem,
                "package": name, "version": version, "severity": "HIGH"}

    def known(self, findings, source="OSV-Scanner", triage=None):
        return {"name": "known_vulns", "status": "ok", "source": source,
                "raw": {"findings": findings, "triage": triage or []}}

    def mock_syft(self, command, scratch, output):
        self.assertIn("spdx-json@2.3", command)
        self.assertEqual(command[command.index("--config") + 1],
                         str(scratch / "config.yaml"))
        config = (scratch / "config.yaml").read_text()
        for line in ("check-for-app-update: false", "vcpkg-allow-git-clone: false",
                     "use-packages-lib: false", "use-network: false",
                     "search-remote-licenses: false"):
            self.assertIn(line, config)
        output.write_text(json.dumps(self.document()), encoding="utf-8")
        return 0

    def test_generation_binds_expected_artifact_and_cleans_scratch(self):
        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"), \
                patch.object(sb, "_run_syft", side_effect=self.mock_syft):
            result = sb.generate_sbom(self.artifact, "build_output",
                                      expected_sha256=self.digest)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["generation"]["tool_version"], "1.57.1")
        self.assertTrue(result["facts"]["independent_digest_match"])
        self.assertEqual(result["facts"]["described_ids"], ["SPDXRef-app"])
        self.assertFalse(result["facts"]["quality"]["schema_validated"])
        self.assertFalse(list(self.root.rglob(".openssf-sbom-*")))

    def test_missing_tool_digest_mismatch_and_unsafe_target(self):
        with patch.object(sb.shutil, "which", return_value=None):
            result = sb.generate_sbom(self.artifact, "build_output",
                                      expected_sha256=self.digest)
        self.assertEqual(result["status"], "unknown")
        with patch.object(sb, "_run_syft") as run:
            self.assertEqual(sb.generate_sbom(self.artifact, "build_output",
                                              expected_sha256="f" * 64)["status"], "error")
            run.assert_not_called()
        link = self.root / "link"
        link.symlink_to(self.artifact)
        self.assertEqual(sb.generate_sbom(link, "build_output",
                                          expected_sha256=self.digest)["status"], "error")
        self.assertEqual(sb.generate_sbom("registry.example/test", "oci_image")["status"], "error")

    def test_subprocess_output_is_bounded_and_environment_isolated(self):
        output = self.root / "output.json"
        script = ("import os,sys; "
                  "assert 'SYFT_REGISTRY_AUTH' not in os.environ; "
                  "assert os.environ['GOPROXY']=='off'; "
                  "sys.stdout.write('x'*128)")
        with patch.dict(os.environ, {"SYFT_REGISTRY_AUTH": "synthetic-token"}), \
                patch.object(sb, "MAX_EVIDENCE", 32):
            with self.assertRaisesRegex(ValueError, "exceeds the size limit"):
                sb._run_syft([sys.executable, "-c", script], self.root, output)

    def test_missing_posix_capability_skips_generation(self):
        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"), \
                patch.object(sb, "_posix_pipes_available", return_value=False), \
                patch.object(sb, "_run_syft") as run:
            result = sb.generate_sbom(self.artifact, "build_output",
                                      expected_sha256=self.digest)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("POSIX pipes", result["gaps"][0])
        run.assert_not_called()

    def test_private_scratch_does_not_require_writable_artifact_parent(self):
        directory = sb._scratch_directory(self.artifact)
        try:
            self.assertFalse(Path(directory.name).is_relative_to(self.root))
            self.assertEqual(Path(directory.name).stat().st_mode & 0o777, 0o700)
        finally:
            directory.cleanup()
        source = self.root / "source"
        source.mkdir()
        directory = sb._scratch_directory(source)
        try:
            self.assertFalse(Path(directory.name).is_relative_to(self.root))
            self.assertFalse(Path(directory.name).is_relative_to(source))
        finally:
            directory.cleanup()

    def test_scanned_root_excludes_private_scratch_when_it_is_inside(self):
        source = self.root / "source"
        source.mkdir()
        (source / "package.json").write_text('{"name":"synthetic"}')
        original_directory = tempfile.TemporaryDirectory

        def inside_root(target):
            self.assertEqual(target, source)
            return original_directory(prefix=".openssf-sbom-", dir=source)

        def inspect(command, scratch, output):
            self.assertTrue(scratch.is_relative_to(source))
            self.assertEqual(command[command.index("--exclude") + 1],
                             str(scratch) + "/**")
            return self.mock_syft(command, scratch, output)

        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"), \
                patch.object(sb, "_scratch_directory", side_effect=inside_root), \
                patch.object(sb, "_run_syft", side_effect=inspect):
            result = sb.generate_sbom(source, "source_checkout")
        self.assertEqual(result["status"], "partial")
        self.assertFalse(list(source.glob(".openssf-sbom-*")))

    def test_snapshot_bounds_directories_time_and_actual_growth(self):
        source = self.root / "source"
        source.mkdir()
        for name in ("a", "b"):
            (source / name).mkdir()
        with patch.object(sb, "_MAX_DIRS", 2):
            with self.assertRaisesRegex(ValueError, "directory limits"):
                sb._snapshot(source)
        with patch.object(sb.time, "monotonic", side_effect=[100, 191]):
            with self.assertRaisesRegex(TimeoutError, "timed out"):
                sb._snapshot(source)
        file = source / "a" / "package.json"
        file.write_bytes(b"x")
        original_open = Path.open

        def grow_on_open(path, *args, **kwargs):
            if path == file:
                with original_open(file, "wb") as stream:
                    stream.write(b"x" * 64)
            return original_open(path, *args, **kwargs)

        with patch.object(sb, "MAX_ARTIFACT", 32), \
                patch.object(Path, "open", grow_on_open):
            with self.assertRaisesRegex(ValueError, "grew beyond"):
                sb._snapshot(source)

    def test_generation_error_target_change_and_cleanup(self):
        def mutate(command, scratch, output):
            self.mock_syft(command, scratch, output)
            self.artifact.write_bytes(b"changed")
            return 0

        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"):
            with patch.object(sb, "_run_syft", return_value=2):
                result = sb.generate_sbom(self.artifact, "build_output",
                                          expected_sha256=self.digest)
                self.assertEqual(result["status"], "error")
            with patch.object(sb, "_run_syft", side_effect=mutate):
                result = sb.generate_sbom(self.artifact, "build_output",
                                          expected_sha256=self.digest)
                self.assertEqual(result["status"], "error")
                self.assertIn("changed during", result["gaps"][0])
            with patch.object(sb, "_run_syft", side_effect=TimeoutError("Syft timed out.")):
                self.assertEqual(sb.generate_sbom(self.artifact, "build_output",
                                                  expected_sha256=hashlib.sha256(
                                                      self.artifact.read_bytes()).hexdigest())
                                 ["status"], "error")
        self.assertFalse(list(self.root.rglob(".openssf-sbom-*")))

    def test_explicit_source_directory_is_not_release_binding(self):
        source = self.root / "source"
        source.mkdir()
        (source / "package.json").write_text('{"name":"synthetic"}')
        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"), \
                patch.object(sb, "_run_syft", side_effect=self.mock_syft):
            result = sb.generate_sbom(source, "source_checkout")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["generation"]["scope"], "source_checkout")
        self.assertIsNone(result["facts"]["generation"]["expected_artifact_sha256"])
        self.assertIn("source checkout", " ".join(result["gaps"]).lower())
        self.assertEqual(sb.generate_sbom(source, "source_checkout",
                                          expected_sha256=self.digest)["status"], "error")

        def mutate(command, scratch, output):
            self.mock_syft(command, scratch, output)
            (source / "package.json").write_text('{"name":"changed"}')
            return 0

        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"), \
                patch.object(sb, "_run_syft", side_effect=mutate):
            changed = sb.generate_sbom(source, "source_checkout")
        self.assertIn("changed during", changed["gaps"][0])
        (source / "link").symlink_to(self.artifact)
        with patch.object(sb.shutil, "which", return_value="/usr/bin/syft"):
            self.assertEqual(sb.generate_sbom(source, "source_checkout")["status"], "error")

    def test_graph_direct_transitive_cycle_containment_and_disconnected(self):
        doc = self.document()
        doc["relationships"].extend([
            {"spdxElementId": "SPDXRef-direct", "relatedSpdxElement": "SPDXRef-app",
             "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-transitive",
             "relationshipType": "CONTAINS"},
        ])
        findings = [self.finding("pkg", "2.0", "GHSA-direct"),
                    self.finding("dep", "3.0", "GHSA-transitive"),
                    self.finding("alone", "1.0", "GHSA-disconnected")]
        result = sb.correlate_sbom(self.inventory(doc), self.known(findings))
        matches = {m["advisory_id"]: m for m in result["facts"]["matched"]}
        self.assertEqual(matches["GHSA-direct"]["relation"], "direct_dependency")
        self.assertEqual(matches["GHSA-transitive"]["relation"], "contained")
        self.assertEqual(matches["GHSA-disconnected"]["relation"], "disconnected")
        self.assertIsNone(result["facts"]["score_adjustment"])
        doc["relationships"] = [r for r in doc["relationships"]
                                if r["relationshipType"] != "CONTAINS"]
        result = sb.correlate_sbom(self.inventory(doc), self.known(findings))
        matches = {m["advisory_id"]: m for m in result["facts"]["matched"]}
        self.assertEqual(matches["GHSA-transitive"]["relation"], "transitive_dependency")

    def test_precise_namespaces_versions_ambiguity_and_triage_provenance(self):
        doc = self.document()
        doc["packages"].append(
            {"SPDXID": "SPDXRef-duplicate", "name": "pkg", "versionInfo": "2.0",
             "externalRefs": [{"referenceType": "purl",
                               "referenceLocator": "pkg:npm/pkg@2.0"}]})
        triage = [{"package": {"ecosystem": "npm", "name": "pkg", "version": "2.0"},
                   "findings": [{"aliases": ["GHSA-direct", "CVE-alias"],
                                 "version_status": "unresolved", "records": [
                                     {"id": "GHSA-direct", "aliases": ["CVE-alias"],
                                      "withdrawn": None,
                                      "reported_version_status": "unresolved"}]}]}]
        findings = [self.finding("pkg", "2.0", "GHSA-direct"),
                    self.finding("pkg", "2.0", "GHSA-wrong-eco", "PyPI"),
                    self.finding("pkg", "1.9", "GHSA-wrong-version")]
        result = sb.correlate_sbom(self.inventory(doc), self.known(
            findings, source="OSV API", triage=triage))
        self.assertEqual(len(result["facts"]["matched"]), 2)
        self.assertEqual(result["facts"]["known_vulns_source"], "OSV API")
        self.assertEqual(result["facts"]["matched"][0]["triage"][0]["version_status"],
                         "unresolved")
        self.assertEqual(set(result["facts"]["unmatched_advisory_ids"]),
                         {"GHSA-wrong-eco", "GHSA-wrong-version"})
        self.assertIn("ambiguous", " ".join(result["gaps"]))

    def test_pinned_syft_ecosystem_identities_match_normalized_osv_names(self):
        doc = self.document()
        observed = [
            ("scoped", "@example/scoped-package", "1.2.3",
             "pkg:npm/%40example/scoped-package@1.2.3", "npm",
             "@example/scoped-package"),
            ("python", "foo-bar", "1.0", "pkg:pypi/foo-bar@1.0",
             "PyPI", "Foo_Bar"),
            ("go", "github.com/google/uuid", "v1.6.0",
             "pkg:golang/github.com/google/uuid@v1.6.0", "Go",
             "github.com/google/uuid"),
            ("maven", "guava", "31.1-jre",
             "pkg:maven/com.google.guava/guava@31.1-jre", "Maven",
             "com.google.guava:guava"),
        ]
        findings = []
        for component, display, version, purl, ecosystem, identity in observed:
            doc["packages"].append({
                "SPDXID": "SPDXRef-" + component, "name": display, "versionInfo": version,
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                  "referenceType": "purl", "referenceLocator": purl}]})
            doc["relationships"].append({
                "spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-" + component,
                "relationshipType": "CONTAINS"})
            findings.append(self.finding(identity, version, "GHSA-" + component, ecosystem))
        result = sb.correlate_sbom(self.inventory(doc), self.known(findings))
        self.assertEqual(result["status"], "partial")
        self.assertEqual({m["advisory_id"]: (m["spdx_id"], m["relation"])
                          for m in result["facts"]["matched"]},
                         {"GHSA-" + item[0]: ("SPDXRef-" + item[0], "contained")
                          for item in observed})
        self.assertEqual(result["facts"]["unmatched_advisory_ids"], [])
        findings[1]["package"] = "foo.bar"
        dotted = sb.correlate_sbom(self.inventory(doc), self.known(findings))
        self.assertIn("GHSA-python", [m["advisory_id"] for m in dotted["facts"]["matched"]])

    def test_purl_conflicts_qualifiers_and_unrelated_display_names_do_not_match(self):
        cases = [
            ("pkg:maven/other.group/guava@31.1-jre", "guava", "Maven",
             "com.google.guava:guava"),
            ("pkg:maven/com.google.guava/guava@31.1-jre", "other", "Maven",
             "com.google.guava:guava"),
            ("pkg:npm/lodash@4.17.21?repository_url=example.org", "lodash",
             "npm", "lodash"),
            ("pkg:npm/lodash@4.17.21#lib", "lodash", "npm", "lodash"),
            ("pkg:golang/github.com/google/uuid@v1.6.0", "google/uuid", "Go",
             "github.com/google/uuid"),
            ("pkg:pypi/foo-bar@1.0", "other-bar", "PyPI", "foo_bar"),
            ("pkg:pypi/foo-bar@1.0", "foo-bar", "npm", "foo-bar"),
        ]
        for purl, display, ecosystem, identity in cases:
            with self.subTest(purl=purl, display=display, ecosystem=ecosystem):
                version = "31.1-jre" if ecosystem == "Maven" else \
                    "v1.6.0" if ecosystem == "Go" else \
                    "1.0" if ecosystem == "PyPI" else "4.17.21"
                doc = self.document()
                doc["packages"][1].update(
                    {"name": display, "versionInfo": version,
                     "externalRefs": [{"referenceType": "purl",
                                       "referenceLocator": purl}]})
                finding = self.finding(identity, version, "GHSA-unrelated", ecosystem)
                result = sb.correlate_sbom(self.inventory(doc), self.known([finding]))
                self.assertEqual(result["facts"]["matched"], [])
        doc = self.document()
        doc["packages"][1]["externalRefs"].append(
            {"referenceType": "purl", "referenceLocator": "pkg:npm/other@2.0"})
        result = sb.correlate_sbom(self.inventory(doc),
                                   self.known([self.finding("pkg", "2.0", "GHSA-ambiguous")]))
        self.assertEqual(result["facts"]["matched"], [])
        self.assertIn("Multiple unequal", " ".join(result["gaps"]))
        doc["packages"][1]["externalRefs"][-1]["referenceLocator"] = "pkg:npm/pkg@2.0"
        result = sb.correlate_sbom(self.inventory(doc),
                                   self.known([self.finding("pkg", "2.0", "GHSA-duplicate")]))
        self.assertEqual(len(result["facts"]["matched"]), 1)

    def test_missing_purl_or_version_never_infers_package_match(self):
        doc = self.document()
        doc["packages"][1].pop("externalRefs")
        doc["packages"][2].pop("versionInfo")
        result = sb.correlate_sbom(self.inventory(doc), self.known([
            self.finding("pkg", "2.0", "GHSA-purl"),
            self.finding("dep", "3.0", "GHSA-version")]))
        self.assertEqual(result["facts"]["matched"], [])
        self.assertEqual(len(result["facts"]["unmatched_advisory_ids"]), 2)
        self.assertIn("lack versions or purls", " ".join(result["gaps"]))

    def test_absence_unsupported_spdx_and_unscannable_evidence(self):
        inventory = self.inventory()
        self.assertEqual(sb.correlate_sbom(inventory, None)["status"], "unknown")
        empty = sb.correlate_sbom(inventory, self.known([]))
        self.assertEqual(empty["facts"]["matched"], [])
        self.assertIn("does not", " ".join(empty["gaps"]))
        doc = self.document()
        doc["spdxVersion"] = "SPDX-3.0"
        self.assertEqual(sb.correlate_sbom(self.inventory(doc),
                                           self.known([]))["status"], "unknown")
        spdx3 = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {"type": "CreationInfo", "specVersion": "3.0.1",
                 "@id": "_:CreationInfo-1"},
                {"type": "SpdxDocument", "spdxId": "SPDXRef:Document-1"},
                {"type": "software_Package", "name": "pkg",
                 "spdxId": "SPDXRef:Package-npm-pkg"},
            ],
        }
        unsupported = self.inventory(spdx3)
        self.assertEqual(unsupported["status"], "error")
        self.assertIn("Only SPDX JSON 2.3", unsupported["gaps"][0])
        self.assertEqual(sb.correlate_sbom(unsupported, self.known([]))["status"], "unknown")
        self.assertEqual(self.inventory()["facts"]["packages"][1]["name"], "pkg")

    def test_graph_budget_cannot_expand_into_unbounded_report(self):
        with patch.object(sb, "_MAX_ROUTES", 1):
            result = sb.correlate_sbom(self.inventory(),
                                       self.known([self.finding("dep", "3.0", "GHSA-budget")]))
        self.assertEqual(result["status"], "error")
        self.assertIn("budget", " ".join(result["gaps"]))


if __name__ == "__main__":
    unittest.main()
