#!/usr/bin/env python3
"""
Tests for the OpenSSF Security Assessment Script.

Run with: python3 -m pytest tests/ -v
Or:       python3 tests/test_assess_project.py
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path so we can import the script
_script_dir = str(Path(__file__).resolve().parent.parent / 'scripts')
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

# Import uses importlib to handle the hyphen-free module name
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "assess_project",
    Path(__file__).resolve().parent.parent / 'scripts' / 'assess-project.py'
)
assess_project = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(assess_project)


class TestDetectLanguages(unittest.TestCase):
    """Test language detection from project files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_detect_python_by_requirements(self):
        (self.project / 'requirements.txt').write_text('flask==3.0.0\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('python', lang_names)

    def test_detect_python_by_pyproject(self):
        (self.project / 'pyproject.toml').write_text('[project]\nname = "test"\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('python', lang_names)

    def test_detect_javascript_by_package_json(self):
        (self.project / 'package.json').write_text('{"name": "test"}\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('javascript', lang_names)

    def test_detect_go_by_go_mod(self):
        (self.project / 'go.mod').write_text('module example.com/test\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('go', lang_names)

    def test_detect_rust_by_cargo_toml(self):
        (self.project / 'Cargo.toml').write_text('[package]\nname = "test"\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('rust', lang_names)

    def test_detect_java_by_pom(self):
        (self.project / 'pom.xml').write_text('<project></project>\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('java', lang_names)

    def test_detect_ruby_by_gemfile(self):
        (self.project / 'Gemfile').write_text("source 'https://rubygems.org'\n")
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('ruby', lang_names)

    def test_detect_no_languages_in_empty_project(self):
        langs = assess_project.detect_languages(self.project)
        self.assertEqual(langs, [])

    def test_detect_multiple_languages(self):
        (self.project / 'package.json').write_text('{"name": "test"}\n')
        (self.project / 'requirements.txt').write_text('flask\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('python', lang_names)
        self.assertIn('javascript', lang_names)

    def test_detect_python_by_extension_in_subdir(self):
        subdir = self.project / 'src'
        subdir.mkdir()
        (subdir / 'app.py').write_text('print("hello")\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertIn('python', lang_names)

    def test_excludes_node_modules(self):
        """Ensure files in node_modules don't trigger language detection."""
        nm = self.project / 'node_modules' / 'somepkg'
        nm.mkdir(parents=True)
        (nm / 'index.js').write_text('module.exports = {};\n')
        langs = assess_project.detect_languages(self.project)
        lang_names = [l['language'] for l in langs]
        self.assertNotIn('javascript', lang_names)

    def test_excludes_nested_vendor_and_git_without_reentering(self):
        for folder in ('node_modules', '.git', 'vendor', '.venv'):
            nested = self.project / 'packages' / 'app' / folder / 'pkg'
            nested.mkdir(parents=True)
            (nested / 'Cargo.toml').write_text('[package]\n')
            (nested / 'index.js').write_text('var x = 1;\n')
        (self.project / 'packages' / 'app' / 'src').mkdir()
        (self.project / 'packages' / 'app' / 'src' / 'main.py').write_text('pass\n')
        self.assertEqual([lang['language'] for lang in
                          assess_project.detect_languages(self.project)], ['python'])

    def test_detects_monorepo_indicator_beneath_source(self):
        nested = self.project / 'packages' / 'service'
        nested.mkdir(parents=True)
        (nested / 'go.mod').write_text('module example.com/service\n')
        self.assertIn('go', [lang['language'] for lang in
                             assess_project.detect_languages(self.project)])

    def test_package_manager_populated(self):
        (self.project / 'go.mod').write_text('module test\n')
        langs = assess_project.detect_languages(self.project)
        go_lang = [l for l in langs if l['language'] == 'go'][0]
        self.assertEqual(go_lang['package_manager'], 'go modules')


class TestCheckSecurityArtifacts(unittest.TestCase):
    """Test security artifact detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_security_md_detected(self):
        (self.project / 'SECURITY.md').write_text('# Security\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['security_policy']['exists'])
        self.assertEqual(artifacts['security_policy']['path'], 'SECURITY.md')

    def test_security_md_in_github_dir(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'SECURITY.md').write_text('# Security\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['security_policy']['exists'])
        self.assertEqual(artifacts['security_policy']['path'], '.github/SECURITY.md')

    def test_license_detected(self):
        (self.project / 'LICENSE').write_text('MIT License\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['license']['exists'])

    def test_dependabot_yml_detected(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'dependabot.yml').write_text('version: 2\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['dependabot']['exists'])

    def test_dependabot_yaml_detected(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'dependabot.yaml').write_text('version: 2\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['dependabot']['exists'])

    def test_renovate_detected(self):
        (self.project / 'renovate.json').write_text('{}\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['renovate']['exists'])

    def test_missing_artifacts_in_empty_project(self):
        artifacts = assess_project.check_security_artifacts(self.project)
        for name, info in artifacts.items():
            self.assertFalse(info['exists'], f'{name} should not exist in empty project')

    def test_codeowners_detected(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'CODEOWNERS').write_text('* @owner\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['codeowners']['exists'])

    def test_scorecard_workflow_yml(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'scorecard.yml').write_text('name: Scorecard\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['scorecard_workflow']['exists'])

    def test_scorecard_workflow_yaml(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'scorecard.yaml').write_text('name: Scorecard\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['scorecard_workflow']['exists'])

    def test_codeql_workflow_detected(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'codeql.yml').write_text('name: CodeQL\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['codeql_workflow']['exists'])

    def test_codeql_analysis_yaml_detected(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'codeql-analysis.yaml').write_text('name: CodeQL\n')
        artifacts = assess_project.check_security_artifacts(self.project)
        self.assertTrue(artifacts['codeql_workflow']['exists'])


class TestCheckCISetup(unittest.TestCase):
    """Test CI/CD configuration detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_github_actions_detected(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'ci.yml').write_text('name: CI\n')
        ci = assess_project.check_ci_setup(self.project)
        self.assertTrue(ci['has_ci'])
        self.assertIn('github_actions', ci['ci_systems'])

    def test_gitlab_ci_detected(self):
        (self.project / '.gitlab-ci.yml').write_text('stages:\n')
        ci = assess_project.check_ci_setup(self.project)
        self.assertTrue(ci['has_ci'])
        self.assertIn('gitlab_ci', ci['ci_systems'])

    def test_no_ci_in_empty_project(self):
        ci = assess_project.check_ci_setup(self.project)
        self.assertFalse(ci['has_ci'])
        self.assertEqual(ci['ci_systems'], {})

    def test_test_directory_detected(self):
        (self.project / 'tests').mkdir()
        ci = assess_project.check_ci_setup(self.project)
        self.assertTrue(ci['has_tests'])

    def test_test_files_detected(self):
        (self.project / 'test_main.py').write_text('def test_pass(): pass\n')
        ci = assess_project.check_ci_setup(self.project)
        self.assertTrue(ci['has_tests'])

    def test_workflows_count_yml_and_yaml(self):
        wf = self.project / '.github' / 'workflows'
        wf.mkdir(parents=True)
        (wf / 'ci.yml').write_text('name: CI\n')
        (wf / 'release.yaml').write_text('name: Release\n')
        (wf / 'README.md').write_text('# Workflows\n')
        ci = assess_project.check_ci_setup(self.project)
        self.assertEqual(ci['workflows_count'], 2)


class TestBranchProtectionIndicators(unittest.TestCase):
    """Test branch protection indicator detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_pr_template_detected(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'PULL_REQUEST_TEMPLATE.md').write_text('## Description\n')
        bp = assess_project.check_branch_protection_indicators(self.project)
        self.assertTrue(bp['pr_template_exists'])

    def test_codeowners_detected(self):
        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'CODEOWNERS').write_text('* @owner\n')
        bp = assess_project.check_branch_protection_indicators(self.project)
        self.assertTrue(bp['codeowners_exists'])

    def test_no_indicators_in_empty_project(self):
        bp = assess_project.check_branch_protection_indicators(self.project)
        self.assertFalse(bp['pr_template_exists'])
        self.assertFalse(bp['codeowners_exists'])
        self.assertEqual(bp['status'], 'unknown')


class TestSecurityCapabilities(unittest.TestCase):
    """Local configuration is neither enabled defaults nor execution evidence."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.project = Path(self.tmpdir.name)
        self.workflows = self.project / '.github' / 'workflows'
        self.workflows.mkdir(parents=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def capabilities(self):
        return assess_project.check_security_capabilities(
            self.project, assess_project.check_security_artifacts(self.project))

    def test_named_file_does_not_prove_codeql(self):
        (self.workflows / 'codeql.yml').write_text('name: CodeQL\njobs: {}\n')
        self.assertEqual(self.capabilities()['code_scanning']['status'], 'unknown')

    def test_custom_named_workflow_detects_codeql_and_gitleaks_config_alone_does_not(self):
        (self.project / '.gitleaks.toml').write_text('[extend]\nuseDefault = true\n')
        (self.workflows / 'security.yml').write_text(
            'steps:\n  - uses: github/codeql-action/analyze@v4\n')
        caps = self.capabilities()
        self.assertEqual(caps['code_scanning']['status'], 'configured')
        self.assertEqual(caps['secrets_scanning']['status'], 'unknown')
        self.assertTrue(caps['secrets_scanning']['config_only'])
        self.assertIn('unverified', caps['code_scanning']['note'])

    def test_reusable_workflow_stays_unknown(self):
        (self.workflows / 'ci.yaml').write_text(
            'jobs:\n  scan:\n    uses: org/shared/.github/workflows/scan.yml@v1\n')
        caps = self.capabilities()
        self.assertEqual(caps['code_scanning']['status'], 'unknown')
        self.assertEqual(caps['secrets_scanning']['status'], 'unknown')
        self.assertEqual(caps['reusable_workflows']['evidence'], ['.github/workflows/ci.yaml'])


class TestGenerateRecommendations(unittest.TestCase):
    """Test recommendation generation logic."""

    def _empty_artifacts(self):
        return {k: {'exists': False, 'path': None, 'description': '', 'priority': 'medium'}
                for k in ['security_policy', 'license', 'dependabot', 'renovate',
                          'scorecard_workflow', 'codeql_workflow', 'sbom', 'threat_model',
                          'contributing', 'codeowners']}

    def test_critical_security_policy_recommendation(self):
        artifacts = self._empty_artifacts()
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': False, 'has_tests': False})
        actions = [r['action'] for r in recs]
        self.assertIn('Create SECURITY.md', actions)
        # Should be highest priority
        sec_rec = [r for r in recs if r['action'] == 'Create SECURITY.md'][0]
        self.assertEqual(sec_rec['priority'], 'high')
        self.assertNotIn('critical', [rec['priority'] for rec in recs])

    def test_no_security_policy_rec_when_exists(self):
        artifacts = self._empty_artifacts()
        artifacts['security_policy']['exists'] = True
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': False, 'has_tests': False})
        actions = [r['action'] for r in recs]
        self.assertNotIn('Create SECURITY.md', actions)

    def test_dependabot_recommendation_when_missing(self):
        artifacts = self._empty_artifacts()
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': True, 'has_tests': True})
        actions = [r['action'] for r in recs]
        self.assertIn('Enable Dependabot or Renovate', actions)

    def test_no_dependabot_rec_when_renovate_exists(self):
        artifacts = self._empty_artifacts()
        artifacts['renovate']['exists'] = True
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': True, 'has_tests': True})
        actions = [r['action'] for r in recs]
        self.assertNotIn('Enable Dependabot or Renovate', actions)

    def test_language_specific_recommendations(self):
        artifacts = self._empty_artifacts()
        languages = [{'language': 'python', 'package_manager': 'pip/poetry/pipenv'}]
        recs = assess_project.generate_recommendations(languages, artifacts, {'has_ci': True, 'has_tests': True})
        actions = [r['action'] for r in recs]
        pip_audit_recs = [a for a in actions if 'pip-audit' in a]
        self.assertTrue(len(pip_audit_recs) > 0, 'Should recommend pip-audit for Python')
        self.assertLess(
            actions.index('Check known vulnerability advisories for direct dependencies'),
            actions.index('Enable Dependabot or Renovate'))

    def test_multiple_language_recommendations(self):
        artifacts = self._empty_artifacts()
        languages = [
            {'language': 'python', 'package_manager': 'pip'},
            {'language': 'javascript', 'package_manager': 'npm'},
        ]
        recs = assess_project.generate_recommendations(languages, artifacts, {'has_ci': True, 'has_tests': True})
        actions = ' '.join(r['action'] for r in recs)
        self.assertIn('pip-audit', actions)
        self.assertIn('npm audit', actions)

    def test_recommendations_sorted_by_priority(self):
        artifacts = self._empty_artifacts()
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': True, 'has_tests': False})
        priorities = [r['priority'] for r in recs]
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        priority_values = [priority_order[p] for p in priorities]
        self.assertEqual(priority_values, sorted(priority_values))

    def test_scorecard_recommended_when_ci_exists(self):
        artifacts = self._empty_artifacts()
        recs = assess_project.generate_recommendations(
            [], artifacts, {'has_ci': True, 'has_tests': True,
                            'ci_systems': {'github_actions': True}})
        actions = [r['action'] for r in recs]
        self.assertTrue(any('Scorecard coverage' in action for action in actions))

    def test_no_scorecard_when_no_ci(self):
        artifacts = self._empty_artifacts()
        recs = assess_project.generate_recommendations([], artifacts, {'has_ci': False, 'has_tests': False})
        actions = [r['action'] for r in recs]
        self.assertFalse(any('Scorecard coverage' in action for action in actions))

    def test_gitlab_only_has_no_github_workflow_recommendations(self):
        recs = assess_project.generate_recommendations(
            [{'language': 'python'}], self._empty_artifacts(),
            {'has_ci': True, 'has_tests': True, 'ci_systems': {'gitlab_ci': True}})
        actions = ' '.join(rec['action'] for rec in recs)
        self.assertNotIn('CodeQL', actions)
        self.assertNotIn('Scorecard', actions)
        self.assertNotIn('workflow', actions)
        self.assertIn('pip-audit', actions)

    def test_github_unsupported_language_skips_codeql(self):
        recs = assess_project.generate_recommendations(
            [{'language': 'elixir'}], self._empty_artifacts(),
            {'has_ci': True, 'has_tests': True, 'ci_systems': {'github_actions': True}})
        self.assertFalse(any('CodeQL' in r['action'] for r in recs))

    def test_config_without_scan_does_not_suppress_action(self):
        artifacts = self._empty_artifacts()
        artifacts['gitleaks_config'] = {'exists': True}
        recs = assess_project.generate_recommendations(
            [], artifacts, {'has_ci': False, 'has_tests': True})
        self.assertTrue(any('targeted secrets scan' in r['action'] for r in recs))

    def test_known_local_workflow_is_still_unverified(self):
        recs = assess_project.generate_recommendations(
            [], self._empty_artifacts(), {'has_ci': True, 'has_tests': True,
                                          'ci_systems': {'github_actions': True}},
            capabilities={'secrets_scanning': {'status': 'configured'},
                          'scorecard': {'status': 'configured'}})
        actions = [r['action'] for r in recs]
        self.assertIn('Verify secrets scanning runs and review findings', actions)
        self.assertFalse(any('Scorecard coverage' in action for action in actions))


class TestCalculateSecurityScore(unittest.TestCase):
    """Test security score calculation."""

    def _empty_artifacts(self):
        return {k: {'exists': False}
                for k in ['security_policy', 'license', 'dependabot', 'renovate',
                          'scorecard_workflow', 'codeql_workflow', 'sbom', 'threat_model']}

    def test_zero_score_empty_project(self):
        artifacts = self._empty_artifacts()
        ci = {'has_ci': False, 'has_tests': False}
        score = assess_project.calculate_security_score(artifacts, ci)
        self.assertEqual(score['score'], 0)
        self.assertEqual(score['grade'], 'F')

    def test_perfect_score(self):
        artifacts = {k: {'exists': True}
                     for k in ['security_policy', 'license', 'dependabot', 'renovate',
                               'scorecard_workflow', 'codeql_workflow', 'sbom', 'threat_model']}
        ci = {'has_ci': True, 'has_tests': True}
        bp = {'pr_template_exists': True, 'codeowners_exists': True}
        score = assess_project.calculate_security_score(artifacts, ci, bp)
        self.assertEqual(score['score'], 100)
        self.assertEqual(score['grade'], 'A')

    def test_security_policy_weighted_higher(self):
        """Security policy is a critical check, weighted x3."""
        artifacts_with_sec = self._empty_artifacts()
        artifacts_with_sec['security_policy']['exists'] = True
        ci = {'has_ci': False, 'has_tests': False}

        artifacts_with_sbom = self._empty_artifacts()
        artifacts_with_sbom['sbom']['exists'] = True

        score_sec = assess_project.calculate_security_score(artifacts_with_sec, ci)
        score_sbom = assess_project.calculate_security_score(artifacts_with_sbom, ci)
        self.assertGreater(score_sec['score'], score_sbom['score'],
                          'Security policy (critical, 3x weight) should score higher than SBOM (medium, 1x)')

    def test_grade_boundaries(self):
        """Test that letter grades correspond to correct score ranges."""
        artifacts = self._empty_artifacts()
        ci = {'has_ci': False, 'has_tests': False}
        score = assess_project.calculate_security_score(artifacts, ci)

        if score['score'] >= 80:
            self.assertEqual(score['grade'], 'A')
        elif score['score'] >= 60:
            self.assertEqual(score['grade'], 'B')
        elif score['score'] >= 40:
            self.assertEqual(score['grade'], 'C')
        elif score['score'] >= 20:
            self.assertEqual(score['grade'], 'D')
        else:
            self.assertEqual(score['grade'], 'F')

    def test_perfect_readiness_is_not_posture_verdict(self):
        artifacts = {k: {'exists': True} for k in self._empty_artifacts()}
        score = assess_project.calculate_security_score(
            artifacts, {'has_ci': True, 'has_tests': True})
        self.assertEqual(score['kind'], 'local_artifact_readiness')
        self.assertEqual(score['assurance'], 'unverified')
        self.assertNotIn('security posture', score['assessment'].lower())

    def test_branch_protection_affects_score(self):
        artifacts = self._empty_artifacts()
        ci = {'has_ci': True, 'has_tests': True}
        bp_none = {}
        bp_full = {'pr_template_exists': True, 'codeowners_exists': True}

        score_no_bp = assess_project.calculate_security_score(artifacts, ci, bp_none)
        score_bp = assess_project.calculate_security_score(artifacts, ci, bp_full)
        self.assertGreater(score_bp['score'], score_no_bp['score'])


class TestEndToEnd(unittest.TestCase):
    """End-to-end test: create a project fixture and run the full assessment."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.project = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_minimal_project(self):
        """Minimal project produces valid JSON structure."""
        (self.project / 'main.py').write_text('print("hello")\n')
        (self.project / 'requirements.txt').write_text('flask\n')

        languages = assess_project.detect_languages(self.project)
        artifacts = assess_project.check_security_artifacts(self.project)
        ci_setup = assess_project.check_ci_setup(self.project)
        bp = assess_project.check_branch_protection_indicators(self.project)
        recs = assess_project.generate_recommendations(languages, artifacts, ci_setup, bp)
        score = assess_project.calculate_security_score(artifacts, ci_setup, bp)

        # Verify structure
        self.assertIsInstance(languages, list)
        self.assertIsInstance(artifacts, dict)
        self.assertIsInstance(ci_setup, dict)
        self.assertIsInstance(recs, list)
        self.assertIsInstance(score, dict)
        self.assertIn('grade', score)
        self.assertIn('score', score)

    def test_well_configured_project(self):
        """A project with many security artifacts should score well."""
        (self.project / 'SECURITY.md').write_text('# Security\n')
        (self.project / 'LICENSE').write_text('MIT\n')
        (self.project / 'CONTRIBUTING.md').write_text('# Contributing\n')

        gh = self.project / '.github'
        gh.mkdir()
        (gh / 'dependabot.yml').write_text('version: 2\n')
        (gh / 'CODEOWNERS').write_text('* @owner\n')
        (gh / 'PULL_REQUEST_TEMPLATE.md').write_text('## Description\n')

        wf = gh / 'workflows'
        wf.mkdir()
        (wf / 'ci.yml').write_text('name: CI\n')
        (wf / 'scorecard.yml').write_text('name: Scorecard\n')
        (wf / 'codeql.yml').write_text('name: CodeQL\n')

        (self.project / 'tests').mkdir()
        (self.project / 'requirements.txt').write_text('flask\n')

        languages = assess_project.detect_languages(self.project)
        artifacts = assess_project.check_security_artifacts(self.project)
        ci_setup = assess_project.check_ci_setup(self.project)
        bp = assess_project.check_branch_protection_indicators(self.project)
        score = assess_project.calculate_security_score(artifacts, ci_setup, bp)

        self.assertGreaterEqual(score['score'], 60)
        self.assertIn(score['grade'], ['A', 'B'])

    def test_output_is_serializable(self):
        """The full report should be JSON-serializable."""
        (self.project / 'main.py').write_text('print("hello")\n')

        languages = assess_project.detect_languages(self.project)
        artifacts = assess_project.check_security_artifacts(self.project)
        ci_setup = assess_project.check_ci_setup(self.project)
        bp = assess_project.check_branch_protection_indicators(self.project)
        recs = assess_project.generate_recommendations(languages, artifacts, ci_setup, bp)
        score = assess_project.calculate_security_score(artifacts, ci_setup, bp)

        report = {
            'languages': languages,
            'security_artifacts': artifacts,
            'ci_setup': ci_setup,
            'branch_protection_indicators': bp,
            'security_score': score,
            'recommendations': recs,
        }

        # Should not raise
        json_str = json.dumps(report, indent=2)
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

    def test_cli_needs_only_stdlib_and_prioritizes_local_action(self):
        (self.project / 'src.py').write_text('pass\n')
        proc = subprocess.run(
            [sys.executable, '-S', str(Path(_script_dir) / 'assess-project.py'),
             str(self.project)],
            cwd=self.project, env={'PATH': ''}, capture_output=True, text=True, check=True)
        report = json.loads(proc.stdout)
        self.assertEqual(report['readiness_score'], report['security_score'])
        self.assertEqual(report['security_score']['assurance'], 'unverified')
        self.assertEqual(report['recommendations'][0]['action'], 'Create SECURITY.md')
        self.assertEqual(report['summary']['critical_issues'], 0)


if __name__ == '__main__':
    unittest.main()
