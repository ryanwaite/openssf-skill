#!/usr/bin/env python3
"""
OpenSSF Security Assessment Script

Analyzes a project's security posture by detecting:
- Programming languages and frameworks
- Existing security artifacts
- CI/CD configuration
- Security gaps and recommendations

Usage: python3 assess-project.py [project_path]

Output: JSON report with project context and prioritized recommendations.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Any

# Directories to exclude from recursive file searches
_EXCLUDED_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', '.tox',
                  '.venv', 'venv', 'dist', 'build', '.eggs'}


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

    detected = []

    for lang, config in indicators.items():
        found = False

        # Check for indicator files (top-level and one level of recursion)
        for pattern in config['files']:
            # Check top-level match
            if list(project_path.glob(pattern)):
                found = True
                break
            # Check subdirectories, excluding common non-source dirs
            for child in project_path.iterdir():
                if child.is_dir() and child.name not in _EXCLUDED_DIRS:
                    if list(child.rglob(pattern)):
                        found = True
                        break
            if found:
                break

        # Check for file extensions if not found by indicator files
        if not found:
            for ext in config['extensions']:
                for child in project_path.iterdir():
                    if child.is_dir() and child.name not in _EXCLUDED_DIRS:
                        if list(child.rglob(f'*{ext}')):
                            found = True
                            break
                    elif child.suffix == ext:
                        found = True
                        break
                if found:
                    break

        if found:
            detected.append({
                'language': lang,
                'package_manager': config['package_manager']
            })

    return detected


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
        'github_actions': workflows_dir.exists(),
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
                                if f.suffix in ('.yml', '.yaml')]) if workflows_dir.exists() else 0
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
        'note': 'Branch protection settings require GitHub API to fully verify'
    }


def generate_recommendations(
    languages: List[Dict],
    artifacts: Dict[str, Dict],
    ci_setup: Dict[str, Any],
    branch_protection: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """Generate prioritized security recommendations based on assessment."""
    recommendations = []
    branch_protection = branch_protection or {}

    # Critical: Security policy
    if not artifacts['security_policy']['exists']:
        recommendations.append({
            'priority': 'critical',
            'category': 'documentation',
            'action': 'Create SECURITY.md',
            'reason': 'Required for responsible vulnerability disclosure. Users and researchers need to know how to report security issues.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # High: Dependency updates
    if not artifacts['dependabot']['exists'] and not artifacts['renovate']['exists']:
        recommendations.append({
            'priority': 'high',
            'category': 'dependencies',
            'action': 'Enable Dependabot or Renovate',
            'reason': 'Automated dependency updates help patch vulnerabilities quickly.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    # High: License
    if not artifacts['license']['exists']:
        recommendations.append({
            'priority': 'high',
            'category': 'legal',
            'action': 'Add LICENSE file',
            'reason': 'Clear licensing is required for open source projects and helps users understand usage rights.',
            'effort': 'low',
            'time_estimate': '5 minutes'
        })

    # Medium: Scorecard
    if ci_setup.get('has_ci') and not artifacts['scorecard_workflow']['exists']:
        recommendations.append({
            'priority': 'medium',
            'category': 'security_scanning',
            'action': 'Add OpenSSF Scorecard workflow',
            'reason': 'Continuous security posture monitoring helps identify issues early.',
            'effort': 'low',
            'time_estimate': '10 minutes'
        })

    # Medium: CodeQL
    if ci_setup.get('has_ci') and not artifacts['codeql_workflow']['exists']:
        recommendations.append({
            'priority': 'medium',
            'category': 'security_scanning',
            'action': 'Enable CodeQL analysis',
            'reason': 'Static analysis catches common vulnerability patterns automatically.',
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
    if ci_setup.get('has_ci') and not artifacts.get('slsa_provenance_workflow', {}).get('exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'supply_chain',
            'action': 'Add SLSA provenance workflow',
            'reason': 'SLSA provenance provides verifiable evidence of where and how artifacts were built.',
            'effort': 'medium',
            'time_estimate': '30 minutes'
        })

    # Medium: SBOM workflow
    if ci_setup.get('has_ci') and not artifacts.get('sbom_workflow', {}).get('exists') and not artifacts.get('sbom', {}).get('exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'supply_chain',
            'action': 'Add automated SBOM generation workflow',
            'reason': 'Automating SBOM generation ensures every release includes a software inventory.',
            'effort': 'low',
            'time_estimate': '15 minutes'
        })

    # Medium: Secrets scanning
    if ci_setup.get('has_ci') and not artifacts.get('secrets_scanning_workflow', {}).get('exists') and not artifacts.get('gitleaks_config', {}).get('exists'):
        recommendations.append({
            'priority': 'medium',
            'category': 'security_scanning',
            'action': 'Add secrets scanning (Gitleaks or TruffleHog)',
            'reason': 'Secrets scanning detects leaked API keys, passwords, and tokens before they reach production.',
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
    lang_names = {l['language'] for l in languages}

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
    """Calculate a simple security posture score."""
    branch_protection = branch_protection or {}
    total_checks = 0
    passed_checks = 0

    # Critical checks (weighted x3)
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
        assessment = 'Strong security posture'
    elif score >= 60:
        grade = 'B'
        assessment = 'Good foundation, room for improvement'
    elif score >= 40:
        grade = 'C'
        assessment = 'Basic security, significant gaps'
    elif score >= 20:
        grade = 'D'
        assessment = 'Minimal security controls'
    else:
        grade = 'F'
        assessment = 'Critical security gaps'

    return {
        'score': score,
        'grade': grade,
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

    if not project_path.exists():
        print(json.dumps({'error': f'Path does not exist: {project_path}'}))
        sys.exit(1)

    # Run assessment
    languages = detect_languages(project_path)
    artifacts = check_security_artifacts(project_path)
    ci_setup = check_ci_setup(project_path)
    branch_protection = check_branch_protection_indicators(project_path)
    recommendations = generate_recommendations(languages, artifacts, ci_setup, branch_protection)
    security_score = calculate_security_score(artifacts, ci_setup, branch_protection)

    # Build report
    report = {
        'project_path': str(project_path),
        'languages': languages,
        'security_artifacts': artifacts,
        'ci_setup': ci_setup,
        'branch_protection_indicators': branch_protection,
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
