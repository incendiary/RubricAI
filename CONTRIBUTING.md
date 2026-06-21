# Contributing to RubricAI

Thank you for your interest in contributing to RubricAI! This guide explains how to set up your development environment, run tests, and maintain code quality.

## Development Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements-lock.txt
pip install -e . --no-deps
pip install -e ".[dev]"  # If dev extras are defined
```

## Running Tests and Linters

```bash
# Run tests
pytest

# Run linters
black .
ruff check .
isort .

# Run all pre-commit hooks
pre-commit run --all-files
```

### Troubleshooting

**Watch the server log in real time:**

```bash
tail -f ~/.local/share/rubricai/rubricai.log
```

Each `bom_check` call logs one line per component showing which fetcher was used (OSV or NVD), how many CVEs came back, and any rate-limit or HTTP errors. This is the fastest way to diagnose unexpected zero-result responses or slow queries.

---

## Secrets Baseline Maintenance

This project uses [detect-secrets](https://github.com/Yelp/detect-secrets) to scan the codebase for hardcoded credentials, API keys, and other secrets. The baseline file (`.secrets.baseline`) records intentional test fixtures and audited non-secret patterns so the CI secret-scan job does not flag them.

### Regenerating the baseline

After adding new intentional test fixtures (like test API keys or mock credentials), regenerate the baseline:

```bash
detect-secrets scan > .secrets.baseline
```

Commit the updated `.secrets.baseline`:

```bash
git add .secrets.baseline
git commit -m "chore: regenerate secrets baseline"
```

### Allowlisting intentional fixtures

For intentional test fixtures (e.g., placeholder strings like `"secret-key"` used in tests), add a `# pragma: allowlist secret` comment on the line above or inline:

```python
# pragma: allowlist secret
"API_KEY": "test-key-value"
```

Or inline (on the same line):

```python
"API_KEY": "test-key-value"  # pragma: allowlist secret
```

This tells `detect-secrets` to allowlist this string so it doesn't get flagged as a new secret on the next scan.

### Machine-specific paths

The baseline is regenerated on each developer's machine and should **not** contain machine-specific absolute paths (like `/Users/alice/...` or `/home/bob/...`). If you see such paths in a diff, regenerate the baseline on your machine and commit the result — the paths will normalize to your environment.

### CI verification

The CI pipeline runs `detect-secrets scan --baseline .secrets.baseline` to verify that no new unaudited secrets have been introduced. If the job fails:

1. Check the job logs for the flagged finding (usually a filename and line number)
2. If it's intentional (a test fixture), add `# pragma: allowlist secret` and regenerate:
   ```bash
   detect-secrets scan > .secrets.baseline
   ```
3. If it's accidental (a real credential), remove it and never commit it
4. Regenerate and commit:
   ```bash
   git add .secrets.baseline
   git commit -m "chore: regenerate secrets baseline"
   ```

---

## Code Quality Standards

- **Python:** Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) conventions. The project uses [Black](https://github.com/psf/black) for formatting, [Ruff](https://github.com/astral-sh/ruff) for linting, and [isort](https://pycqa.github.io/isort/) for import sorting.
- **Pre-commit hooks:** Run `pre-commit run --all-files` before pushing to catch formatting and linting issues early.
- **Tests:** Add tests for new features and bug fixes. Run `pytest` to verify all tests pass.

---

## Submitting Changes

1. Create a feature branch: `git checkout -b feat/your-feature`
2. Make your changes and commit with clear, concise messages
3. Run linters and tests locally: `black .`, `ruff check .`, `pytest`
4. Push your branch and open a pull request
5. Ensure CI passes (lint, tests, secret-scan)

---

Thank you for contributing!
