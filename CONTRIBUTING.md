# Contributing to OpenSSF Security Skill

Thank you for your interest in improving this security skill! This project aims to make OpenSSF security best practices accessible to developers through AI coding assistants.

## How to Contribute

### 1. Fork and Clone

```bash
git clone https://github.com/<your-username>/openssf-skill.git
cd openssf-skill
```

### 2. Create a Branch

```bash
git checkout -b feature/your-improvement
```

### 3. Make Your Changes

Follow the guidelines below for the type of content you're adding or modifying.

### 4. Submit a Pull Request

- Write a clear PR title and description
- Reference any related issues
- Explain what changed and why

---

## Areas for Contribution

### Reference Documents (`references/`)

- Add coverage for missing security topics
- Update outdated tool versions, commands, or URLs
- Add language-specific examples (Rust, Ruby, PHP, Swift, etc.)
- Improve clarity or add practical examples

### Templates (`templates/`)

- Improve existing templates with better defaults
- Add templates for new security artifacts (e.g., incident response plan)

### Workflow Templates (`workflows/`)

- Add templates for other CI systems (CircleCI, Jenkins, Azure Pipelines)
- Update GitHub Actions versions and hashes
- Add new security scanning workflows

### Assessment Script (`scripts/assess-project.py`)

- Add detection for new security artifacts
- Improve language detection accuracy
- Add new recommendation categories
- Write tests (see `tests/` directory)

### Copilot Instructions (`.github/copilot-instructions.md`)

- Add language-specific security examples
- Improve code pattern guidance

### Skill Definition (`SKILL.md`)

- Improve task descriptions or workflow guidance
- Add new security task categories

---

## Content Guidelines

### Accuracy

- Verify all commands, tool versions, and URLs before submitting
- Reference official documentation where possible
- Clearly distinguish between security requirements ("must") and recommendations ("should")

### Consistency

- Use the existing file structure and formatting patterns
- Follow Markdown conventions used in other reference docs
- Use tables for comparisons, code blocks for commands

### Security

- Hash-pin all GitHub Actions in workflow templates (not just version tags)
- Follow the security patterns this project teaches
- Never include real secrets, API keys, or credentials — even in examples
- Use obviously fake placeholder values (e.g., `AKIAIOSFODNN7EXAMPLE`)

### Code Style (Python)

- No external dependencies — `assess-project.py` must use only the Python standard library
- Type hints on function signatures
- Docstrings on all functions
- Follow PEP 8 conventions

---

## Testing

### Assessment Script

Run the script against this repository to verify it still works:

```bash
python3 scripts/assess-project.py .
```

Verify the output is valid JSON:

```bash
python3 scripts/assess-project.py . | python3 -m json.tool > /dev/null
```

Run syntax check:

```bash
python3 -c "import py_compile; py_compile.compile('scripts/assess-project.py', doraise=True)"
```

Run tests:

```bash
python3 -m pytest tests/ -v
```

### Markdown

- Check for broken links
- Verify code blocks have the correct language tag
- Ensure tables render correctly

---

## Reporting Issues

- Use GitHub Issues to report bugs, suggest improvements, or request new features
- Include enough context for someone to understand and reproduce the issue
- Tag issues with appropriate labels (bug, enhancement, documentation)

---

## Code of Conduct

Be respectful and constructive. We're all working toward the same goal: making it easier for developers to build secure software.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
