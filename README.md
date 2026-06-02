# RubricAI

> **TODO:** Replace this line with a one-paragraph description of what this project does and why.

---

## Setup

```bash
# Clone and enter
git clone git@github.com:incendiary/RubricAI.git
cd RubricAI

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Requirements
- Python 3.11+
- [pre-commit](https://pre-commit.com/)
- [gitleaks](https://github.com/gitleaks/gitleaks) (installed via pre-commit)

---

## Usage

```bash
# TODO: add usage examples
python -m src.main --help
```

---

## Development

```bash
# Run linters
black .
ruff check .
isort .

# Run tests
pytest

# Run all pre-commit hooks manually
pre-commit run --all-files
```

---

## Roadmap

| # | Status | Description |
|---|--------|-------------|
| [#1](../../issues/1) | ✅ Done | Secret scan — gitleaks + TruffleHog + detect-secrets (pre-commit + CI) |
| [#2](../../issues/2) | ✅ Done | Dependency audit — Dependabot (pip + Actions, weekly) |
| [#3](../../issues/3) | ⬜ Todo | Code quality pass — dead code, duplication, control flow |
| [#4](../../issues/4) | ✅ Done | Tooling — Black, Ruff, isort, pre-commit, CI pipeline |
| [#5](../../issues/5) | ⬜ Todo | Tests — add unit/integration test coverage |
| [#6](../../issues/6) | ⬜ Todo | Documentation — fill in description + usage above |
| [#7](../../issues/7) | ✅ Done | Branch protection — force-push blocked, required CI checks on main |

Status key: ⬜ Todo · 🔄 In Progress · ✅ Done

---

## Releases

| Version | Description |
|---------|-------------|
| v1.0.0  | Public release — all roadmap items complete |

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
