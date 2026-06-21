# Contributing to RubricAI

## Getting Started

```bash
git clone --branch v1.6.0 --depth 1 git@github.com:incendiary/RubricAI.git
cd RubricAI

python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pre-commit install
```

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

For intentional test fixtures (e.g., placeholder values used in tests), add a `# pragma: allowlist secret` comment on the line above or inline. The detect-secrets tool will then allowlist this string so it doesn't get flagged as a new secret on the next scan.

See `tests/test_install_claude_config.py` for examples of the pragma pattern in use.

### Machine-specific paths

The baseline is regenerated on each developer's machine and should **not** contain machine-specific absolute paths (like `/Users/alice/...` or `/home/bob/...`). If you see such paths in a diff, regenerate the baseline on your machine and commit the result — the paths will normalize to your environment.

### CI verification

The CI pipeline runs `detect-secrets scan --baseline .secrets.baseline` to verify that no new unaudited secrets have been introduced. If the job fails:

1. Check the job logs for the flagged finding (usually a filename and line number)
2. If it's intentional (a test fixture), add `# pragma: allowlist secret` and regenerate: `detect-secrets scan > .secrets.baseline`
3. If it's accidental (a real credential), remove it and never commit it
4. Regenerate and commit: `git add .secrets.baseline && git commit -m "chore: regenerate secrets baseline"`

## Testing

```bash
# Run all tests
pytest

# Run linters
black .
ruff check .
isort .

# Run all pre-commit hooks
pre-commit run --all-files
```

## Development Guidelines

- Use `.venv` for all local development (never install system-wide)
- Follow PEP 8 (enforced by Black and Ruff)
- Add tests for new functionality
- Update documentation and ROADMAP.md when making changes
