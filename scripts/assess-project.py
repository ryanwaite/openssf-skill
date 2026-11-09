#!/usr/bin/env python3
"""
OpenSSF Local Project Inventory

Inventories a project's local security indicators by detecting:
- Programming languages and frameworks
- Existing security artifacts
- CI/CD configuration
- Security gaps and recommendations

Usage: python3 assess-project.py [project_path]

Output: JSON report with project context and prioritized recommendations.
"""

import sys
import json
import fnmatch
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Iterator

# Directories to exclude from recursive file searches
_EXCLUDED_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', '.tox',
                  '.venv', 'venv', 'dist', 'build', '.eggs'}


def _source_files(project_path: Path) -> Iterator[str]:
    """Walk source once, pruning excluded directories at every depth."""
    for root, dirs, files in os.walk(project_path, followlinks=False):
        dirs[:] = [name for name in dirs
                   if name not in _EXCLUDED_DIRS
                   and not (Path(root) / name).is_symlink()]
        for name in files:
            yield name


def detect_languages(project_path: Path) -> List[Dict[str, Any]]:
    """Detect programming languages from package files and extensions."""
    indicators = {
        'python': {
            'files': ['pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile', 'setup.cfg'],
            'extensions': ['.py'],
            'package_manager': 'pip/poetry/pipenv'
        },
        'javascript': {
            'files': ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            'extensions': ['.js', '.mjs', '.cjs'],
            'package_manager': 'npm/yarn/pnpm'
        },
        'typescript': {
            'files': ['tsconfig.json'],
            'extensions': ['.ts', '.tsx'],
            'package_manager': 'npm/yarn/pnpm'
        },
        'go': {
            'files': ['go.mod', 'go.sum'],
            'extensions': ['.go'],
            'package_manager': 'go modules'
        },
        'rust': {
            'files': ['Cargo.toml', 'Cargo.lock'],
            'extensions': ['.rs'],
            'package_manager': 'cargo'
        },
        'java': {
            'files': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
            'extensions': ['.java'],
            'package_manager': 'maven/gradle'
        },
        'kotlin': {
            'files': ['build.gradle.kts'],
            'extensions': ['.kt', '.kts'],
            'package_manager': 'gradle'
        },
        'ruby': {
            'files': ['Gemfile', 'Gemfile.lock', '*.gemspec'],
            'extensions': ['.rb'],
            'package_manager': 'bundler'
        },
        'php': {
            'files': ['composer.json', 'composer.lock'],
            'extensions': ['.php'],
            'package_manager': 'composer'
        },
        'dotnet': {
            'files': ['*.csproj', '*.fsproj', '*.vbproj', '*.sln'],
            'extensions': ['.cs', '.fs', '.vb'],
            'package_manager': 'nuget'
        },
        'swift': {
            'files': ['Package.swift'],
            'extensions': ['.swift'],
            'package_manager': 'swift package manager'
        },
        'elixir': {
            'files': ['mix.exs'],
            'extensions': ['.ex', '.exs'],
            'package_manager': 'hex'
        },
    }

    found = set()
    for name in _source_files(project_path):
        for lang, config in indicators.items():
            if lang not in found and (
                    any(fnmatch.fnmatchcase(name, pattern) for pattern in config['files'])
                    or name.endswith(tuple(config['extensions']))):
                found.add(lang)
        if len(found) == len(indicators):
            break
    return [
        {'language': lang, 'package_manager': config['package_manager']}
        for lang, config in indicators.items()
        if lang in found
    ]


def check_security_artifacts(project_path: Path) -> Dict[str, Dict[str, Any]]:
    """Check for existing security-related files."""
    artifacts = {
        'security_policy': {
            'paths': ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'],
            'description': 'Vulnerability reporting policy',
            'priority': 'high'
        },
        'license': {
            'paths': ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'LICENSE-MIT', 'LICENSE-APACHE'],
            'description': 'Open source license',
            'priority': 'high'
        },
        'contributing': {
            'paths': ['CONTRIBUTING.md', '.github/CONTRIBUTING.md'],
            'description': 'Contribution guidelines',
            'priority': 'medium'
        },
        'code_of_conduct': {
            'paths': ['CODE_OF_CONDUCT.md', '.github/CODE_OF_CONDUCT.md'],
            'description': 'Community code of conduct',
            'priority': 'low'
        },
        'codeowners': {
            'paths': ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'],
            'description': 'Code ownership definitions',
            'priority': 'medium'
        },
        'dependabot': {
            'paths': ['.github/dependabot.yml', '.github/dependabot.yaml'],
            'description': 'Automated dependency updates',
            'priority': 'high'
        },
        'renovate': {
            'paths': ['renovate.json', '.renovaterc', '.renovaterc.json', '.github/renovate.json'],
            'description': 'Automated dependency updates (Renovate)',
            'priority': 'high'
        },
        'scorecard_workflow': {
            'paths': ['.github/workflows/scorecard.yml', '.github/workflows/scorecard.yaml'],
            'description': 'OpenSSF Scorecard automation',
            'priority': 'medium'
        },
        'codeql_workflow': {
            'paths': ['.github/workflows/codeql.yml', '.github/workflows/codeql.yaml',
                      '.github/workflows/codeql-analysis.yml', '.github/workflows/codeql-analysis.yaml'],
            'description': 'CodeQL security scanning',
            'priority': 'medium'
        },
        'sbom': {
            'paths': ['sbom.json', 'sbom.xml', 'sbom.spdx', 'sbom.spdx.json', 'bom.json', 'bom.xml'],
            'description': 'Software Bill of Materials',
            'priority': 'medium'
        },
        'threat_model': {
            'paths': ['THREAT_MODEL.md', 'docs/threat-model.md', 'docs/security/threat-model.md', 'THREATS.md'],
            'description': 'Threat model documentation',
            'priority': 'medium'
        },
        'security_txt': {
            'paths': ['.well-known/security.txt', 'security.txt'],
            'description': 'Security contact information (RFC 9116)',
            'priority': 'low'
        },
        'slsa_provenance_workflow': {
            'paths': ['.github/workflows/slsa-provenance.yml', '.github/workflows/slsa-provenance.yaml',
                      '.github/workflows/slsa.yml', '.github/workflows/slsa.yaml',
                      '.github/workflows/provenance.yml', '.github/workflows/provenance.yaml'],
            'description': 'SLSA provenance generation workflow',
            'priority': 'medium'
        },
        'sbom_workflow': {
            'paths': ['.github/workflows/sbom.yml', '.github/workflows/sbom.yaml',
                      '.github/workflows/sbom-generation.yml', '.github/workflows/sbom-generation.yaml'],
            'description': 'SBOM generation workflow',
            'priority': 'medium'
        },
        'pre_commit_config': {
            'paths': ['.pre-commit-config.yaml', '.pre-commit-config.yml'],
            'description': 'Pre-commit hooks configuration',
            'priority': 'low'
        },
        'gitleaks_config': {
            'paths': ['.gitleaks.toml', '.gitleaks.yaml'],
            'description': 'Gitleaks secret scanning configuration',
            'priority': 'low'
        },
        'secrets_scanning_workflow': {
            'paths': ['.github/workflows/gitleaks.yml', '.github/workflows/gitleaks.yaml',
                      '.github/workflows/trufflehog.yml', '.github/workflows/trufflehog.yaml',
                      '.github/workflows/secrets.yml', '.github/workflows/secrets.yaml'],
            'description': 'Secrets scanning workflow',
            'priority': 'medium'
        },
    }

    results = {}

    for artifact, config in artifacts.items():
        found_path = None
        for path in config['paths']:
            if (project_path / path).exists():
                found_path = path
                break

        results[artifact] = {
            'exists': found_path is not None,
            'path': found_path,
            'description': config['description'],
            'priority': config['priority']
        }

    return results


def check_ci_setup(project_path: Path) -> Dict[str, Any]:
    """Check CI/CD configuration."""
    workflows_dir = project_path / '.github' / 'workflows'

    ci_systems = {
        'github_actions': workflows_dir.is_dir() and any(
            p.is_file() and p.suffix in ('.yml', '.yaml')
            for p in workflows_dir.iterdir()),
        'gitlab_ci': (project_path / '.gitlab-ci.yml').exists(),
        'circle_ci': (project_path / '.circleci' / 'config.yml').exists(),
        'travis_ci': (project_path / '.travis.yml').exists(),
        'jenkins': (project_path / 'Jenkinsfile').exists(),
        'azure_pipelines': (project_path / 'azure-pipelines.yml').exists(),
    }

    # Check for test directories and test file patterns
    test_indicators = [
        (project_path / 'tests').exists(),
        (project_path / 'test').exists(),
        (project_path / '__tests__').exists(),
        (project_path / 'spec').exists(),
        bool(list(project_path.glob('*_test.go'))),
        bool(list(project_path.glob('test_*.py'))),
        bool(list(project_path.glob('*_test.py'))),
        bool(list(project_path.glob('*.test.js'))),
        bool(list(project_path.glob('*.spec.js'))),
        bool(list(project_path.glob('*.test.ts'))),
        bool(list(project_path.glob('*.spec.ts'))),
    ]

    return {
        'ci_systems': {k: v for k, v in ci_systems.items() if v},
        'has_ci': any(ci_systems.values()),
        'has_tests': any(test_indicators),
        'workflows_count': len([f for f in workflows_dir.iterdir()
                                if f.is_file() and f.suffix in ('.yml', '.yaml')])
        if workflows_dir.is_dir() else 0
    }


def check_branch_protection_indicators(project_path: Path) -> Dict[str, Any]:
    """Check for indicators of branch protection (can't fully verify without API)."""
    # Check for PR template (suggests review process)
    pr_template_exists = any([
        (project_path / '.github' / 'PULL_REQUEST_TEMPLATE.md').exists(),
        (project_path / '.github' / 'pull_request_template.md').exists(),
        (project_path / 'docs' / 'pull_request_template.md').exists(),
    ])

    # Check CODEOWNERS (suggests review requirements)
    codeowners_exists = any([
        (project_path / 'CODEOWNERS').exists(),
        (project_path / '.github' / 'CODEOWNERS').exists(),
    ])

    return {
        'pr_template_exists': pr_template_exists,
        'codeowners_exists': codeowners_exists,
        'status': 'unknown',
        'note': 'PR templates and CODEOWNERS do not prove enforced review or branch protection; verify forge rulesets/settings separately'
    }


def check_security_capabilities(project_path: Path, artifacts: Dict[str, Dict]) -> Dict[str, Dict[str, Any]]:
    """Identify local scan configuration, not remote enablement or successful runs."""
    workflows = project_path / '.github' / 'workflows'
    patterns = {
        'code_scanning': r'(?im)^\s*(?:-\s*)?uses:\s*github/codeql-action/(?:init|analyze)\b',
        'secrets_scanning': r'(?im)^\s*(?:-\s*)?(?:uses:\s*(?:gitleaks/gitleaks-action|trufflesecurity/trufflehog)|run:\s*["\x27]?(?:\S+\s+)*?(?:gitleaks|trufflehog)\b)',
        'scorecard': r'(?im)^\s*(?:-\s*)?uses:\s*ossf/scorecard-action\b',
    }
    matches = {key: [] for key in patterns}
    reusable = []
    unreadable = []
    if workflows.is_dir() and not workflows.is_symlink():
        for path in sorted(workflows.iterdir()):
            if path.is_symlink() or not path.is_file() or path.suffix not in ('.yml', '.yaml'):
                continue
            relative = path.relative_to(project_path).as_posix()
            try:
                if path.stat().st_size > 256_000:
                    unreadable.append(relative)
                    continue
                text = path.read_text(encoding='utf-8')
            except (OSError, UnicodeError):
                unreadable.append(relative)
                continue
            for key, pattern in patterns.items():
                if re.search(pattern, text):
                    matches[key].append(relative)
            if re.search(r'(?im)^\s*(?:-\s*)?uses:\s*(?:\./|[\w.-]+/[\w.-]+/)\.github/workflows/', text):
                reusable.append(relative)

    capabilities = {}
    for key in patterns:
        paths = matches[key]
        capabilities[key] = {
            'status': 'configured' if paths else 'unknown',
            'evidence': paths,
            'note': ('Local workflow reference found; execution and results unverified.'
                     if paths else
                     'No recognized local workflow; forge defaults, centralized/reusable workflows and scan runs unverified.')
        }
    capabilities['secrets_scanning']['config_only'] = (
        artifacts.get('gitleaks_config', {}).get('exists', False)
        and not matches['secrets_scanning'])
    capabilities['reusable_workflows'] = {
        'status': 'unknown', 'evidence': reusable,
        'note': 'Referenced reusable workflow contents and execution cannot be verified locally.'
    }
    capabilities['unreadable_workflows'] = unreadable
    capabilities['dependency_updates'] = {
        'status': 'configured' if (artifacts['dependabot']['exists'] or artifacts['renovate']['exists']) else 'unknown',
        'note': 'Configuration presence does not verify that updates are enabled or running.'
    }
    return capabilities


def generate_recommendations(
    languages: List[Dict],
    artifacts: Dict[str, Dict],
    ci_setup: Dict[str, Any],
    branch_protection: Dict[str, Any] = None,
    capabilities: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """Recommend incremental actions; missing local files are not incidents."""
    recommendations = []
    branch_protection = branch_protection or {}
    capabilities = capabilities or {}
    github_actions = ci_setup.get('ci_systems', {}).get('github_actions', False)
    lang_names = {lang['language'] for lang in languages}

    # A missing policy is actionable, not evidence of an active vulnerability.
    if not artifacts['security_policy']['exists']:
        recommendations.append({
            'priority': 'high',
            'category': 'documentation',
            'action': 'Create SECURITY.md',
            'reason': 'Provide a private way to report vulnerabilities; no scanner or account setup is needed to draft the policy.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    if lang_names:
        recommendations.append({
            'priority': 'high',
            'category': 'dependencies',
            'action': 'Check known vulnerability advisories for direct dependencies',
            'reason': 'Start with the dependencies in the existing manifests/lockfiles; triage known critical fixes first. Use a package-manager audit if already available, or review advisories manually.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Optional automation; file absence is not evidence of vulnerable dependencies.
    if not artifacts['dependabot']['exists'] and not artifacts['renovate']['exists']:
        recommendations.append({
            'priority': 'medium',
            'category': 'dependencies',
            'action': 'Enable Dependabot or Renovate',
            'reason': 'Automated dependency updates help patch vulnerabilities quickly.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    # Licensing matters for distribution, but is not an urgent security risk.
    if not artifacts['license']['exists']:
        recommendations.append({
            'priority': 'low',
            'category': 'legal',
            'action': 'Add LICENSE file',
            'reason': 'Clear licensing is required for open source projects and helps users understand usage rights.',
            'effort': 'low',
            'time_estimate': '5 minutes'
        })

    # CI templates only apply to the CI service and supported languages.
    if github_actions and capabilities.get('scorecard', {}).get('status') != 'configured':
        recommendations.append({
            'priority': 'medium',
            'category': 'security_scanning',
            'action': 'Check Scorecard coverage; optionally add a GitHub Actions workflow',
            'reason': 'No recognized local Scorecard action; hosted or centralized scanning may already exist.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    if (github_actions and lang_names.intersection({
            'python', 'javascript', 'typescript', 'go', 'rust', 'java', 'kotlin',
            'ruby', 'swift', 'dotnet'})
            and capabilities.get('code_scanning', {}).get('status') != 'configured'):
        recommendations.append({
            'priority': 'medium',
            'category': 'security_scanning',
            'action': 'Check code scanning coverage (CodeQL if supported)',
            'reason': 'GitHub default setup or centralized scanning may be enabled; verify before adding a workflow.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Medium: Tests
    if not ci_setup.get('has_tests'):
        recommendations.append({
            'priority': 'medium',
            'category': 'quality',
            'action': 'Add automated tests',
            'reason': 'Tests help ensure security fixes don\'t introduce regressions.',
            'effort': 'high',
            'time_estimate': 'varies'
        })

    # Medium: SBOM
    if not artifacts['sbom']['exists']:
        recommendations.append({
            'priority': 'medium',
            'category': 'supply_chain',
            'action': 'Generate SBOM',
            'reason': 'Software Bill of Materials improves supply chain transparency and helps with vulnerability tracking.',
            'effort': 'medium',
            'time_estimate': '30 minutes'
        })

    # Medium: Threat model
    if not artifacts['threat_model']['exists']:
        recommendations.append({
            'priority': 'medium',
            'category': 'documentation',
            'action': 'Create threat model',
            'reason': 'Systematic threat identification helps prioritize security efforts.',
            'effort': 'medium',
            'time_estimate': '1-2 hours'
        })

    # Low: Contributing guide
    if not artifacts['contributing']['exists']:
        recommendations.append({
            'priority': 'low',
            'category': 'documentation',
            'action': 'Add CONTRIBUTING.md',
            'reason': 'Helps contributors understand security requirements for pull requests.',
            'effort': 'low',
            'time_estimate': '20 minutes'
        })

    # Low: CODEOWNERS
    if not artifacts['codeowners']['exists']:
        recommendations.append({
            'priority': 'low',
            'category': 'governance',
            'action': 'Add CODEOWNERS file',
            'reason': 'Ensures security-sensitive areas have designated reviewers.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    # Medium: PR template (branch protection indicator)
    if not branch_protection.get('pr_template_exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'governance',
            'action': 'Add pull request template',
            'reason': 'PR templates encourage security-focused reviews and consistent review processes.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Medium: SLSA provenance
    if github_actions and not artifacts.get('slsa_provenance_workflow', {}).get('exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'supply_chain',
            'action': 'Add SLSA provenance workflow',
            'reason': 'SLSA provenance provides verifiable evidence of where and how artifacts were built.',
            'effort': 'medium',
            'time_estimate': '30 minutes'
        })

    # Medium: SBOM workflow
    if github_actions and not artifacts.get('sbom_workflow', {}).get('exists') and not artifacts.get('sbom', {}).get('exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'supply_chain',
            'action': 'Add automated SBOM generation workflow',
            'reason': 'Automating SBOM generation ensures every release includes a software inventory.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Medium: Secrets scanning
    if capabilities.get('secrets_scanning', {}).get('status') != 'configured':
        recommendations.append({
            'priority': 'high' if artifacts.get('gitleaks_config', {}).get('exists') else 'medium',
            'category': 'security_scanning',
            'action': 'Run a targeted secrets scan or verify existing scan coverage',
            'reason': 'A Gitleaks config or named workflow alone does not prove a scan ran; use an available local scanner or verify existing CI/forge results.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })
    else:
        recommendations.append({
            'priority': 'low',
            'category': 'security_scanning',
            'action': 'Verify secrets scanning runs and review findings',
            'reason': 'Local workflow configuration does not establish successful execution.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    # Low: Pre-commit hooks
    if not artifacts.get('pre_commit_config', {}).get('exists'):
        recommendations.append({
            'priority': 'low',
            'category': 'quality',
            'action': 'Add pre-commit hooks',
            'reason': 'Pre-commit hooks catch security issues (secrets, linting) before code enters version control.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Language-specific recommendations
    lang_audit_tools = {
        'python': ('pip-audit', 'pip-audit scans Python dependencies for known vulnerabilities.'),
        'javascript': ('npm audit', 'npm audit scans Node.js dependencies for known vulnerabilities.'),
        'go': ('govulncheck', 'govulncheck checks Go dependencies against the Go vulnerability database.'),
        'rust': ('cargo audit', 'cargo audit checks Rust crate dependencies for known vulnerabilities.'),
        'ruby': ('bundler-audit', 'bundler-audit scans Ruby gem dependencies for known vulnerabilities.'),
        'java': ('OWASP Dependency-Check', 'OWASP Dependency-Check scans Java dependencies for known CVEs.'),
        'php': ('composer audit', 'composer audit scans PHP dependencies for known vulnerabilities.'),
        'dotnet': ('dotnet list package --vulnerable', 'NuGet audit scans .NET dependencies for known vulnerabilities.'),
    }

    for lang_name, (tool, reason) in lang_audit_tools.items():
        if lang_name in lang_names:
            recommendations.append({
                'priority': 'medium',
                'category': 'dependencies',
                'action': f'Run {tool} for {lang_name} dependency scanning',
                'reason': reason,
                'effort': 'low',
                'time_estimate': '10 minutes'
            })

    # Sort by priority
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    recommendations.sort(key=lambda x: priority_order.get(x['priority'], 99))

    return recommendations


def calculate_security_score(artifacts: Dict, ci_setup: Dict,
                             branch_protection: Dict = None) -> Dict[str, Any]:
    """Calculate a legacy, presence-based local readiness band, not assurance."""
    branch_protection = branch_protection or {}
    total_checks = 0
    passed_checks = 0

    # Legacy weights retained for consumers of security_score/checks_passed.
    critical_items = ['security_policy', 'license']
    for item in critical_items:
        total_checks += 3
        if artifacts.get(item, {}).get('exists'):
            passed_checks += 3

    # High priority check: dependency updates (either Dependabot or Renovate)
    total_checks += 1
    if artifacts.get('dependabot', {}).get('exists') or artifacts.get('renovate', {}).get('exists'):
        passed_checks += 1

    # Medium priority checks
    medium_items = ['scorecard_workflow', 'codeql_workflow', 'sbom', 'threat_model']
    for item in medium_items:
        total_checks += 1
        if artifacts.get(item, {}).get('exists'):
            passed_checks += 1

    # CI/CD checks
    total_checks += 2
    if ci_setup.get('has_ci'):
        passed_checks += 1
    if ci_setup.get('has_tests'):
        passed_checks += 1

    # Branch protection indicators
    if branch_protection:
        total_checks += 2
        if branch_protection.get('pr_template_exists'):
            passed_checks += 1
        if branch_protection.get('codeowners_exists'):
            passed_checks += 1

    score = round((passed_checks / total_checks) * 100) if total_checks > 0 else 0

    if score >= 80:
        grade = 'A'
        assessment = 'High local artifact readiness; controls not verified'
    elif score >= 60:
        grade = 'B'
        assessment = 'Moderate local artifact readiness; controls not verified'
    elif score >= 40:
        grade = 'C'
        assessment = 'Partial local artifact readiness; controls not verified'
    elif score >= 20:
        grade = 'D'
        assessment = 'Few local artifacts found; controls not verified'
    else:
        grade = 'F'
        assessment = 'Few or no local artifacts found; controls not verified'

    return {
        'kind': 'local_artifact_readiness',
        'assurance': 'unverified',
        'score': score,
        'grade': grade,  # Legacy readiness band; not the audit/OSPS Baseline grade.
        'assessment': assessment,
        'checks_passed': passed_checks,
        'total_checks': total_checks
    }


def main():
    """Run security assessment and output JSON report."""
    # Determine project path
    if len(sys.argv) > 1:
        project_path = Path(sys.argv[1]).resolve()
    else:
        project_path = Path.cwd()

    if not project_path.is_dir():
        print(json.dumps({'error': f'Not a project directory: {project_path}'}))
        sys.exit(1)

    # Run assessment
    languages = detect_languages(project_path)
    artifacts = check_security_artifacts(project_path)
    ci_setup = check_ci_setup(project_path)
    branch_protection = check_branch_protection_indicators(project_path)
    capabilities = check_security_capabilities(project_path, artifacts)
    recommendations = generate_recommendations(languages, artifacts, ci_setup, branch_protection, capabilities)
    security_score = calculate_security_score(artifacts, ci_setup, branch_protection)

    # Build report
    report = {
        'project_path': str(project_path),
        'languages': languages,
        'security_artifacts': artifacts,
        'ci_setup': ci_setup,
        'branch_protection_indicators': branch_protection,
        'capabilities': capabilities,
        'readiness_score': security_score,
        'security_score': security_score,
        'recommendations': recommendations,
        'summary': {
            'languages_detected': len(languages),
            'artifacts_present': sum(1 for a in artifacts.values() if a['exists']),
            'artifacts_missing': sum(1 for a in artifacts.values() if not a['exists']),
            'recommendations_count': len(recommendations),
            'critical_issues': sum(1 for r in recommendations if r['priority'] == 'critical'),
            'high_issues': sum(1 for r in recommendations if r['priority'] == 'high')
        }
    }

    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
