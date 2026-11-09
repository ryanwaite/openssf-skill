"""Regression tests for extracting and checking copyable workflow examples."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_compatibility", ROOT / "scripts" / "check-compatibility.py"
)
compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compat)


GITHUB = """name: Example
on:
  push:
jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
"""

GITLAB = """# GitLab examples
## First
```yaml
stages: [test]
test:
  script: echo ok
```
## Second
```yml
stages: [build]
build:
  script: echo build
```
"""


@unittest.skipIf(importlib.util.find_spec("yaml") is None, "optional CI-only PyYAML unavailable")
class TestCompatibility(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ("workflows", "references", "scripts", ".github/workflows"):
            (self.root / directory).mkdir(parents=True)
        (self.root / "workflows" / "example.yml.template").write_text(GITHUB)
        (self.root / "workflows" / "gitlab-ci-security.yml.template").write_text(GITLAB)
        (self.root / "references" / "guide.md").write_text(
            "# Examples\n```yaml\n" + GITHUB + "```\n"
            "```yaml\n# Short fragment is not a full workflow\nuses: actions/checkout@v4\n```\n"
            "```yaml\n# Dangerous anti-pattern, not runnable advice\non: pull_request_target\n"
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n```\n"
        )
        (self.root / "scripts" / "compatibility-policy.json").write_text(
            json.dumps({
                **json.loads((ROOT / "scripts" / "compatibility-policy.json").read_text()),
                "reference_workflows": {"references/guide.md": 1},
            })
        )

    def test_extracts_templates_gitlab_fences_and_full_markdown_workflow(self):
        counts, refs, excluded, notes = compat.check_offline(self.root)
        self.assertEqual(counts, {
            "github-template": 1, "github-example": 1, "github-ci": 0, "gitlab": 2
        })
        self.assertEqual(refs, {
            ("actions/checkout", None, "11bd71901bbe5b1630ceea73d27597364c9af683"): "v4.2.2"
        })
        self.assertEqual([reason for _, _, reason in excluded], [
            "partial workflow fragment", "unsafe illustration"
        ])
        self.assertEqual(notes, [])

    def test_direct_gitlab_yaml_is_validated_not_silently_skipped(self):
        template = self.root / "workflows" / "gitlab-ci-security.yml.template"
        template.write_text("stages: [test]\nscan:\n  stage: test\n  script: echo ok\n")
        counts, _, _, _ = compat.check_offline(self.root)
        self.assertEqual(counts["gitlab"], 1)
        template.write_text("stages: [test]\nscan:\n  stage: test\n")
        with self.assertRaisesRegex(compat.ValidationError, "needs a script"):
            compat.check_offline(self.root)

    def test_inventory_fails_if_runnable_example_disappears(self):
        (self.root / "references" / "guide.md").write_text("# No workflow here\n")
        with self.assertRaisesRegex(compat.ValidationError, "inventory changed"):
            compat.check_offline(self.root)

    def test_rejects_unterminated_markdown_fence(self):
        (self.root / "workflows" / "gitlab-ci-security.yml.template").write_text(
            "```yaml\nstages: [test]\n"
        )
        with self.assertRaisesRegex(compat.ValidationError, "unterminated YAML fence"):
            compat.check_offline(self.root)

    def test_rejects_invalid_extracted_gitlab_yaml(self):
        (self.root / "workflows" / "gitlab-ci-security.yml.template").write_text(
            GITLAB.replace("stages: [build]", "stages: [build")
        )
        with self.assertRaisesRegex(compat.ValidationError, "invalid YAML"):
            compat.check_offline(self.root)

    def test_rejects_gitlab_snippet_without_job_script(self):
        (self.root / "workflows" / "gitlab-ci-security.yml.template").write_text(
            GITLAB.replace("script: echo build", "stage: build")
        )
        with self.assertRaisesRegex(compat.ValidationError, "needs a script"):
            compat.check_offline(self.root)

    def test_rejects_malformed_and_duplicate_yaml(self):
        for text, error in (
            (GITHUB.replace("steps:\n", "steps: [\n"), "invalid YAML"),
            (GITHUB + "jobs: {}\n", "duplicate YAML key"),
            (GITHUB.replace("    runs-on: ubuntu-latest", "    runs-on: "), "runs-on"),
        ):
            with self.subTest(error=error):
                (self.root / "workflows" / "example.yml.template").write_text(text)
                with self.assertRaisesRegex(compat.ValidationError, error):
                    compat.check_offline(self.root)

    def test_rejects_unavailable_action_and_unpinned_template(self):
        for ref in ("google/osv-scanner-action@v1",
                    "google/osv-scanner-action@v2.7.1", "actions/checkout@v4"):
            with self.subTest(ref=ref):
                (self.root / "workflows" / "example.yml.template").write_text(
                    GITHUB.replace(
                        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                        ref,
                    )
                )
                with self.assertRaises(compat.ValidationError):
                    compat.check_offline(self.root)

    def test_slsa_exception_is_only_full_semver_for_specific_workflow(self):
        ref = "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
        source = "workflows/example.yml.template"
        policy = json.loads((self.root / "scripts" / "compatibility-policy.json").read_text())
        self.assertEqual(
            compat.validate_ref(ref, source, "github-template", policy),
            ("slsa-framework/slsa-github-generator",
             "/.github/workflows/generator_generic_slsa3.yml", "v2.1.0"),
        )
        for invalid in (
            ref.replace("@v2.1.0", "@v2"),
            ref.replace("generator_generic_slsa3.yml", "other.yml"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(compat.ValidationError):
                    compat.validate_ref(invalid, source, "github-template", policy)

    def test_dependency_review_runtime_requirement_marks_unverified_as_unknown(self):
        source = "workflows/dependency-review.yml.template"
        policy = json.loads((self.root / "scripts" / "compatibility-policy.json").read_text())
        workflow = compat.load_yaml(source, GITHUB)
        workflow["jobs"]["example"]["steps"][0]["uses"] = (
            "actions/dependency-review-action@" + "a" * 40
        )
        ref = workflow["jobs"]["example"]["steps"][0]["uses"]
        self.assertIn("UNKNOWN", compat.runtime_notes(workflow, source, policy, {})[0])
        self.assertEqual(compat.runtime_notes(workflow, source, policy, {ref: "v5.0.0"}), [])
        workflow["jobs"]["example"]["runs-on"] = ["self-hosted"]
        self.assertIn(
            "verify the self-hosted runner",
            compat.runtime_notes(workflow, source, policy, {ref: "v5.0.0"})[0],
        )

    def test_live_ref_comment_mismatch_is_actionable(self):
        refs = {("actions/checkout", None, "11bd71901bbe5b1630ceea73d27597364c9af683"): "v4.2.2"}

        def fake_api(path, token):
            return {"sha": "0" * 40 if path.endswith("v4.2.2") else
                    "11bd71901bbe5b1630ceea73d27597364c9af683"}

        with patch.object(compat, "github_json", side_effect=fake_api):
            errors, count = compat.check_live(refs, None)
        self.assertEqual(count, 1)
        self.assertIn("comment v4.2.2 resolves to", errors[0])

    def test_live_unavailable_ref_is_not_reported_clean(self):
        from urllib.error import HTTPError
        refs = {("actions/checkout", None, "11bd71901bbe5b1630ceea73d27597364c9af683"): None}
        with patch.object(compat, "github_json", side_effect=HTTPError("", 404, "", {}, None)):
            errors, count = compat.check_live(refs, None)
        self.assertEqual(count, 1)
        self.assertIn("UNKNOWN (HTTP 404)", errors[0])

    def test_sso_restricted_api_checks_tag_and_action_path_without_claiming_api_success(self):
        from urllib.error import HTTPError
        ref = ("github/codeql-action", "/upload-sarif", "9418214df1f2c4b8128c770156c409013b07d6b9")
        denied = HTTPError("", 403, "", {"X-GitHub-SSO": "required"}, None)
        with patch.object(compat, "github_json", side_effect=denied), \
             patch.object(compat, "git_tag_sha", return_value=ref[2]) as tag, \
             patch.object(compat, "raw_path_exists", return_value=True) as path:
            errors, count = compat.check_live({ref: "v3.39.3"}, None)
        self.assertEqual((errors, count), ([], 1))
        tag.assert_called_once()
        path.assert_called_once()

        with patch.object(compat, "github_json", side_effect=denied), \
             patch.object(compat, "git_tag_sha", return_value="0" * 40):
            errors, _ = compat.check_live({ref: "v3.39.3"}, None)
        self.assertIn("SSO required, fallback unverified", errors[0])

    def test_annotated_tag_fallback_resolves_peeled_commit(self):
        response = subprocess.CompletedProcess(
            [], 0, "0" * 40 + "\trefs/tags/v3.39.3\n"
            + "9" * 40 + "\trefs/tags/v3.39.3^{}\n", ""
        )
        with patch.object(compat.subprocess, "run", return_value=response):
            self.assertEqual(
                compat.git_tag_sha("github/codeql-action", "v3.39.3", lambda: None),
                "9" * 40,
            )


class TestExtractionWithoutTooling(unittest.TestCase):
    def test_extract_markdown_fences_without_yaml_dependency(self):
        blocks = compat.yaml_blocks(
            "# GitLab\n```yaml\nstages: [test]\n```\n"
            "```yml\njob:\n  script: echo ok\n```\n",
            "guide.md",
        )
        self.assertEqual([line for line, _ in blocks], [3, 6])


if __name__ == "__main__":
    unittest.main()
