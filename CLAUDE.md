# RubricAI agent guide

## What this is

RubricAI is a Python MCP server that prioritises CVEs for remediation. It fetches public intelligence (CISA KEV, EPSS, NVD, GitHub Advisory, OSV, public PoC signals) and applies deterministic scoring policies (CHML, EPSS v5, BOD 26-04) in pure Python. The AI client conducts the interview and calls the tools; the server does the scoring. It has no offensive capability. It runs over stdio for local clients, or over SSE or Streamable HTTP for Docker and remote use, where `RUBRICAI_API_KEY` is required.

## Layout

- `src/main.py`: entry point (`main()`), transport selection via `RUBRICAI_TRANSPORT`, startup security checks. Installed as the `rubricai` script.
- `src/rubricai/server.py`: FastMCP instance and the MCP tool definitions.
- `src/rubricai/auth.py`: API-key middleware for SSE; `/health` is public.
- `src/rubricai/fetchers/`: intel sources (KEV, EPSS, NVD, GitHub Advisory, OSV, PoC) and retry or timeout escalation.
- `src/rubricai/policy/`: policy definitions and the policy registry.
- `src/rubricai/schemas/`: Pydantic models for findings, assessments, environments, evidence and intel.
- `src/rubricai/scoring/`: priority scoring.
- `src/rubricai/tools/`: tool implementations behind the MCP tools.
- `src/rubricai/templates/`: Jinja2 report templates (Markdown and HTML card).
- `prompts/`: workflow prompt and per-client system prompt templates (`prompts/templates/*.j2`).
- `scripts/`: `install_claude_config.py` (Claude Desktop config) and `render_prompt.py`.
- `tests/`: pytest suite. `tests/conftest.py` isolates the home and state directories.
- `docs/examples.md`, `examples/`: worked scenarios and sample PDF reports.
- `ROADMAP.md`: delivered work, open items, review findings and decisions.

## Setup and commands

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-lock.txt   # runtime and dev tools, pinned as in CI
pip install -e . --no-deps
```

- `pytest`: runs the suite; coverage gate is set in `pyproject.toml`.
- `black --check . && ruff check . && isort --check-only .`: the CI Lint job. Fix locally with `black .` and `isort .`.
- `pre-commit run --all-files`: the local hook set.
- `detect-secrets scan --baseline .secrets.baseline`: the CI secret baseline check.
- `docker compose up --build`: SSE deployment; set `RUBRICAI_API_KEY` first.

Lint settings live in `pyproject.toml` (line length 88, Python 3.11 target).

## Workflow

- All changes go through a pull request to `main`. Never push to `main`. The pre-commit `no-commit-to-branch` hook blocks commits there as well.
- One logical change per PR. Use a topic branch.
- PR titles and commit subjects use conventional prefixes (`fix:`, `feat:`, `docs:`, `ci:`, `chore:`). Include the RA or OPEN item where one applies.
- Merge by squash.
- Never rebase a pushed branch. Bring it up to date with `git merge main`.
- Branch protection on `main` (read live with `gh api repos/incendiary/RubricAI/branches/main/protection`):
  - Required checks: `Lint`, `Test`, `Secret Scan`, with branches required to be up to date before merging.
  - Required approving reviews: 0. Stale reviews are dismissed on new pushes.
  - Admins are enforced. Force pushes and branch deletion are blocked.
  - `Audit` and `Test (Python 3.13)` report but are not required.
- Check names must match the workflow `name:` values exactly. A required context that never reports blocks every PR.

## Versioning

- Three values must agree: `VERSION`, `[project] version` in `pyproject.toml`, and the `git clone --branch vX.Y.Z` line in `README.md`. `tests/test_version.py` enforces this, and also that `pyproject.toml` is not behind the latest tag.
- Bump once per batch of related PRs, not per PR. Patch for fixes, minor for features, major for breaking changes.
- To release: merge the version bump, tag `vX.Y.Z` on `main`, and create a GitHub release for the tag.

## Testing

- Every bug fix adds a regression test that fails without the fix.
- Run `pytest` before pushing. CI runs it on Python 3.11 (required) and 3.13 (informational).
- Never lower `--cov-fail-under` in `pyproject.toml`. Raise it when coverage grows.
- Tests must not touch the real home directory or real state. `tests/conftest.py` points `HOME`, `RUBRICAI_ENV_DIR`, `RUBRICAI_REPORT_DIR` and `RUBRICAI_LOG_DIR` at a temporary directory. Do not bypass it.
- Async tests run in pytest-asyncio auto mode.

## Security

- No secrets, API keys, tokens, internal hostnames, IP addresses or personal data in code, tests, fixtures, docs or commits. Read credentials from environment variables (see `.env.example`). `.env` is gitignored.
- Pre-commit runs gitleaks, trufflehog, detect-secrets and the branch guard. CI's Secret Scan job runs gitleaks and trufflehog.
- Intentional test fixtures that look like secrets get a `# pragma: allowlist secret` comment. Regenerate `.secrets.baseline` deliberately, in its own commit, when that is needed. Never commit it as a side effect of running tests or detect-secrets.
- The network transports (`sse`, `http`) refuse to start without `RUBRICAI_API_KEY` unless `RUBRICAI_ALLOW_NO_AUTH=1` is set. `RUBRICAI_TLS_CERT` and `RUBRICAI_TLS_KEY` must be set together. Keep both behaviours.
- Add new dependencies to `requirements-lock.txt` with exact pins. CI's Audit job runs `pip-audit` against that file.
- Third-party GitHub Actions stay pinned to full commit SHAs, with the tag in a trailing comment.
- `black`, `ruff`, `isort` and TruffleHog are pinned in more than one place (lock file, `ci.yml`, `.pre-commit-config.yaml`). Dependabot ignores them; bump all copies together in one PR.

## Documentation

- Keep `README.md` accurate when behaviour, environment variables, tools or the clone tag change.
- Record completed work in `ROADMAP.md`.

## Where to look

- `ROADMAP.md`: open items (`OPEN-n`), review findings (`RA-n`) and decisions (`D-n`). Pick the highest-priority item whose "Depends on" is met. Do not start an item whose dependencies are unmet.
- `CONTRIBUTING.md`: contributor setup and the secrets baseline procedure.
