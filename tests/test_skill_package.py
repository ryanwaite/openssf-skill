"""Smoke-test the documented full-skill layout in disposable destinations."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parent.parent
ASSETS = (
    'SKILL.md', 'skills/advisor/SKILL.md', 'skills/audit/SKILL.md',
    'scripts/assess-project.py', 'scripts/ensemble-eval.py',
    'references/security-policies/security-md-guide.md',
    'templates/SECURITY.md.template', 'workflows/scorecard.yml.template',
    'ensemble/risk-model.md',
    'scripts/sbom_analysis.py', 'scripts/spdx_validation.py',
    'scripts/security_insights.py', 'scripts/registry_evidence.py',
    'references/sbom/spdx-2.3.schema.json',
    'references/security-insights/schema-v2.2.0.cue',
)


class TestSkillPackage(unittest.TestCase):
    def test_supported_project_and_personal_destinations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / 'target'
            target.mkdir()
            (target / 'app.py').write_text('pass\n')
            locations = (
                root / 'copilot-project' / '.github/skills/openssf',
                root / 'copilot-alt-project' / '.agents/skills/openssf',
                root / 'claude-project' / '.claude/skills/openssf',
                root / 'home' / '.copilot/skills/openssf',
                root / 'home' / '.agents/skills/openssf',
                root / 'home' / '.claude/skills/openssf',
            )
            for location in locations:
                with self.subTest(location=location):
                    shutil.copytree(
                        SOURCE, location,
                        ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
                    for asset in ASSETS:
                        self.assertTrue((location / asset).is_file(), asset)
                    run = subprocess.run(
                        [sys.executable, '-S', str(location / 'scripts/assess-project.py'),
                         str(target)],
                        cwd=target, capture_output=True, text=True, check=True)
                    result = json.loads(run.stdout)
                    self.assertIn('python', [item['language'] for item in result['languages']])
                    self.assertEqual(result['project_path'], str(target))
                    audit = subprocess.run(
                        [sys.executable, '-S', str(location / 'scripts/ensemble-eval.py'),
                         '--target', str(target), '--mode', 'produce'],
                        cwd=target, env={**os.environ, 'PATH': ''},
                        capture_output=True, text=True, check=True)
                    report = json.loads(audit.stdout)
                    self.assertEqual(report['verdict']['outcome'], 'INCOMPLETE')
                    self.assertTrue(report['actions'])

    def test_instructions_only_does_not_install_skill_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / '.github'
            dest.mkdir()
            shutil.copyfile(SOURCE / '.github/copilot-instructions.md',
                            dest / 'copilot-instructions.md')
            self.assertTrue((dest / 'copilot-instructions.md').is_file())
            self.assertFalse((dest / 'skills/openssf/SKILL.md').exists())


if __name__ == '__main__':
    unittest.main()
