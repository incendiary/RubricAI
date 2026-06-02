# RubricAI

A vulnerability prioritisation MCP server. Engineers answer structured questions about a CVE finding; RubricAI fetches public intel (CISA KEV, EPSS, NVD, PoC signals), applies a deterministic CHML scoring policy, and produces a standardised report card (markdown + JSON) for central review.

---

## How it works

```
Engineer interview  →  intel_lookup  →  score_evaluate  →  report_generate
(structured Q&A)      (KEV/EPSS/NVD)   (CHML policy)      (report card to disk)
```

**CHML lanes:**

| Lane | Trigger | Target |
|------|---------|--------|
| Critical | KEV listed + internet-exposed + high utility | 72 hours |
| High | Internet-exposed + EPSS ≥ 0.5 or PoC + high utility | 7 days |
| Medium | Constrained/internal reachability or lower impact | 30 days |
| Low | Low utility + low reachability or strong mitigations | Patch train (120–240 days) |

Scoring is deterministic — rules live in server code, not AI prompts.

---

## Setup

```bash
git clone git@github.com:incendiary/RubricAI.git
cd RubricAI

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pre-commit install

cp .env.example .env
```

### Requirements
- Python 3.11+
- [pre-commit](https://pre-commit.com/)
- [gitleaks](https://github.com/gitleaks/gitleaks) (via pre-commit)

---

## Usage

### Local (stdio — Claude Desktop)

```bash
python -m src.main
```

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "rubricai": {
      "command": "python",
      "args": ["-m", "src.main"],
      "cwd": "/path/to/RubricAI",
      "env": { "RUBRICAI_TRANSPORT": "stdio" }
    }
  }
}
```

### Docker (SSE — team deployment)

```bash
docker compose up --build
```

Point your MCP client at `http://localhost:8000/sse`.

### Generate platform-specific system prompts

```bash
python scripts/render_prompt.py --target claude    # → prompts/out/claude_system_prompt.md
python scripts/render_prompt.py --target generic   # → prompts/out/generic_system_prompt.md
python scripts/render_prompt.py --target gemini    # → prompts/out/gemini_system_prompt.md
```

Paste the output into your AI client's system prompt field.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `intel_lookup` | Fetch KEV, EPSS, CVSS, PoC, and vendor signals for one or more CVEs |
| `score_evaluate` | Apply CHML policy and return lane, target, rationale, evidence gaps |
| `report_generate` | Produce markdown + JSON report card, persist to `RUBRICAI_REPORT_DIR` |
| `policy_get` | Return the current CHML policy definition for auditability |

---

## Development

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

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUBRICAI_TRANSPORT` | `stdio` | `stdio` or `sse` |
| `RUBRICAI_REPORT_DIR` | `./reports` | Directory for persisted report cards |
| `NVD_API_KEY` | *(empty)* | Optional — increases NVD rate limit |

---

## Roadmap

| # | Status | Description |
|---|--------|-------------|
| [#1](../../issues/1) | ✅ Done | Secret scan — gitleaks + TruffleHog + detect-secrets (pre-commit + CI) |
| [#2](../../issues/2) | ✅ Done | Dependency audit — Dependabot (pip + Actions, weekly) |
| [#3](../../issues/3) | ✅ Done | Core implementation — schemas, CHML policy, fetchers, MCP tools |
| [#4](../../issues/4) | ✅ Done | Tooling — Black, Ruff, isort, pre-commit, CI pipeline |
| [#5](../../issues/5) | ⬜ Todo | Tests — expand integration coverage, add fetcher mocks |
| [#6](../../issues/6) | ✅ Done | Documentation — README, system prompt templates |
| [#7](../../issues/7) | ✅ Done | Branch protection — force-push blocked, required CI checks on main |

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
