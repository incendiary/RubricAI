# RubricAI

A vulnerability prioritisation MCP server. Engineers answer structured questions about a CVE finding; RubricAI fetches public intel (CISA KEV, EPSS, NVD, PoC signals), applies a deterministic CHML scoring policy, and produces a standardised report card (markdown + JSON) for central review.

---

## Background

Vulnerability triage at scale is broken. Teams receive hundreds of CVE notifications per month; CVSS scores are context-free (a CVSS 9.8 in an air-gapped dev tool is not the same risk as a CVSS 7.0 in an internet-facing API); and remediation SLAs vary by team, tool, and mood. The result is inconsistent prioritisation, audit friction, and genuine risk buried under noise.

RubricAI addresses this with two components:

**1. A deterministic scoring engine (this repo)**
A Python MCP server that fetches live public intel signals — CISA's Known Exploited Vulnerabilities (KEV) catalog, FIRST EPSS exploitation probability scores, NVD CVSS data, and PoC availability heuristics — and runs them through a fixed rule set called CHML (Critical / High / Medium / Low). The rules are code, not prompts: given the same inputs, the same lane is always assigned. This makes decisions auditable, reproducible, and easy to review centrally.

**2. A structured interview workflow**
A platform-agnostic Markdown document (`prompts/workflow.md`) that defines a 9-section interview an AI client conducts with engineers. The interview collects the contextual signals that public databases cannot: Is this component internet-exposed? Are there compensating controls? What data is at risk? The workflow is rendered into platform-specific system prompts via a Jinja2 template renderer for Claude, generic MCP clients, and Gemini.

Together they replace ad-hoc severity gut-feel with a consistent, evidence-backed assessment that both engineers and security teams can reason about.

---

## How it works

```
Engineer interview  →  intel_lookup  →  score_evaluate  →  report_generate
(structured Q&A)      (KEV/EPSS/NVD)   (CHML policy)      (report card to disk)
```

The AI client runs the interview (collecting finding context), then calls the MCP tools in sequence. Scoring happens server-side in pure Python — the AI is the interface, not the judge.

**CHML lanes:**

| Lane | Trigger | Default target |
|------|---------|----------------|
| Critical | KEV listed + internet-exposed + high utility (RCE/auth bypass/priv-esc/data access) | 72 hours |
| High | Internet-exposed + EPSS ≥ 0.5 or PoC available + high utility | 7 days |
| Medium | Constrained/internal reachability, lower impact, or partial mitigations | Patch train |
| Low | Local-only + low utility, or strong causal mitigations blocking the exploit path | Patch train |

All four lane targets are configurable — see [Environment variables](#environment-variables).

**Guardrails:**
- External intel (KEV, high EPSS, PoC) can escalate urgency but cannot downgrade a finding.
- Mitigations must be exploit-relevant to shift a lane — "EDR deployed" does not mitigate an IDOR.
- Medium → Low requires a mitigation with a `causal_claim` of type `waf_rule`, `acl_segmentation`, `disable_feature`, `vendor_workaround`, or `virtual_patching`.

---

## Setup

Download the [latest release](https://github.com/incendiary/RubricAI/releases/latest) or clone a specific tag:

```bash
# Latest release (recommended)
git clone --branch v0.1.0 --depth 1 git@github.com:incendiary/RubricAI.git
cd RubricAI

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pre-commit install

cp .env.example .env
```

To track development (not recommended for production use):

```bash
git clone git@github.com:incendiary/RubricAI.git
cd RubricAI
```

### Requirements
- Python 3.11+
- [pre-commit](https://pre-commit.com/)

---

## Running

### Local — Claude Desktop (stdio transport)

Generate a system prompt and start the server:

```bash
# Generate the Claude-specific system prompt
python scripts/render_prompt.py --target claude
# → prompts/out/claude_system_prompt.md

# Start the MCP server
python -m src.main
```

Register the server in `claude_desktop_config.json` using the merge script (safe to run on an existing config — it adds only the `rubricai` key and leaves everything else intact):

```bash
# Preview what will change
python scripts/install_claude_config.py

# Apply
python scripts/install_claude_config.py --write
```

The script auto-detects the config path on macOS, Windows, and Linux. To override:

```bash
python scripts/install_claude_config.py --config ~/my-config.json --write
```

Restart Claude Desktop after writing. Open a new conversation, paste the contents of `prompts/out/claude_system_prompt.md` as the system prompt, and tell Claude you have a CVE to assess.

### Team deployment — Docker (SSE transport)

```bash
cp .env.example .env
# Edit .env: set NVD_API_KEY if you have one

docker compose up --build
```

Point your MCP client at `http://localhost:8000/sse`. Reports are persisted to `./reports/` on the host.

### Other MCP clients (generic / Gemini)

```bash
python scripts/render_prompt.py --target generic   # → prompts/out/generic_system_prompt.md
python scripts/render_prompt.py --target gemini    # → prompts/out/gemini_system_prompt.md
```

Paste the output into your client's system prompt field.

---

## Tool call flow

An AI client conducts a session like this:

```
1. Interview engineer — collect finding fields:
     component, version, entry_point, reachability, attacker_utility,
     mitigations, data_impact, environment

2. Call intel_lookup(cves=["CVE-XXXX-YYYY"])
   → returns KEV status, EPSS score, CVSS, PoC availability

3. Call score_evaluate(finding=..., intel=...)
   → returns lane (critical/high/medium/low), target days,
     rationale, evidence gaps, score breakdown

4. Call report_generate(finding=..., intel=..., assessment=...)
   → persists markdown + JSON report cards to RUBRICAI_REPORT_DIR
   → returns rendered markdown for display
```

Report files are written as `{finding_id}_{timestamp}.md` and `.json` under `RUBRICAI_REPORT_DIR` (default `./reports/`).

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
| `RUBRICAI_TRANSPORT` | `stdio` | `stdio` (Claude Desktop) or `sse` (Docker/remote) |
| `RUBRICAI_REPORT_DIR` | `./reports` | Directory for persisted report cards |
| `NVD_API_KEY` | *(empty)* | Optional — increases NVD API rate limit from 5 to 50 req/30s |
| `RUBRICAI_CRITICAL_DAYS` | `3` | Override Critical lane SLA (days, or `patch_train`) |
| `RUBRICAI_HIGH_DAYS` | `7` | Override High lane SLA (days, or `patch_train`) |
| `RUBRICAI_MEDIUM_DAYS` | `patch_train` | Override Medium lane SLA (days, or `patch_train`) |
| `RUBRICAI_LOW_DAYS` | `patch_train` | Override Low lane SLA (days, or `patch_train`) |

---

## Roadmap

| Issue | Status | Description |
|-------|--------|-------------|
| [#6](https://github.com/incendiary/RubricAI/issues/6) | ✅ Done | Secret scan — gitleaks + TruffleHog + detect-secrets (pre-commit + CI) |
| [#7](https://github.com/incendiary/RubricAI/issues/7) | ✅ Done | Dependency audit — Dependabot (pip + Actions, weekly) |
| [#8](https://github.com/incendiary/RubricAI/issues/8) | ✅ Done | Core implementation — schemas, CHML policy, fetchers, MCP tools |
| [#9](https://github.com/incendiary/RubricAI/issues/9) | ✅ Done | Tooling — Black, Ruff, isort, pre-commit, CI pipeline |
| [#10](https://github.com/incendiary/RubricAI/issues/10) | ⬜ Open | Tests — expand integration coverage, add fetcher mocks |
| [#11](https://github.com/incendiary/RubricAI/issues/11) | ✅ Done | Documentation — README, system prompt templates |
| [#12](https://github.com/incendiary/RubricAI/issues/12) | ⬜ Open | Branch protection — force-push blocked, required CI checks on main |

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
