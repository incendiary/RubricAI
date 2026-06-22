# RubricAI

A vulnerability prioritisation MCP server. Engineers answer structured questions about a CVE finding; RubricAI fetches public intel (CISA KEV, EPSS, NVD, PoC signals), applies a deterministic CHML scoring policy, and produces a standardised report card (markdown + JSON) for central review.

---

## Background

Vulnerability triage at scale is broken. Teams receive hundreds of CVE notifications per month; CVSS scores are context-free (a CVSS 9.8 in an air-gapped dev tool is not the same risk as a CVSS 7.0 in an internet-facing API); and remediation SLAs vary by team, tool, and mood. The result is inconsistent prioritisation, audit friction, and genuine risk buried under noise.

RubricAI addresses this with two components:

**1. A deterministic scoring engine (this repo)**
A Python MCP server that fetches live public intel signals — CISA's Known Exploited Vulnerabilities (KEV) catalog, FIRST EPSS exploitation probability scores, NVD CVSS data, and PoC availability heuristics — and runs them through a fixed rule set called CHML (Critical / High / Medium / Low). The rules are code, not prompts: given the same inputs, the same lane is always assigned. This makes decisions auditable, reproducible, and easy to review centrally.

**2. A structured interview workflow**
A platform-agnostic Markdown document (`prompts/workflow.md`) that defines a 10-section interview an AI client conducts with engineers. The interview collects the contextual signals that public databases cannot: Is this component internet-exposed? Are there compensating controls? What data is at risk? The workflow is rendered into platform-specific system prompts via a Jinja2 template renderer for Claude, generic MCP clients, and Gemini.

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
| High | Internet-exposed + high utility (RCE/auth bypass/priv-esc/data access); OR internet-exposed + EPSS ≥ 0.5 — no strong mitigations | 7 days |
| Medium | Constrained/internal reachability, lower impact, or strong evidenced mitigations | Patch train |
| Low | Local-only + low utility, or strong causal mitigations blocking the exploit path | Patch train |

All four lane targets are configurable — see [Environment variables](#environment-variables).

**Priority Score (0–10)**

Each assessment also produces a `priority_score` — a numeric 0–10 value for sorting within a lane (e.g. which of two Criticals to patch first). CVSS base is one input (max 40%); the remaining weight comes from reachability, KEV/EPSS intel, attacker utility, and mitigation strength.

| Scenario | CVSS | Reachability | KEV | EPSS | Utility | Mitigation | Score | Lane |
|---|---|---|---|---|---|---|---|---|
| KEV + internet + high EPSS + RCE | 9.8 | internet | ✅ | 0.90 | RCE | none | **9.4** | Critical |
| KEV + internet + low EPSS + auth bypass | 7.5 | internet | ✅ | 0.20 | auth bypass | none | **8.0** | Critical |
| Internet + RCE + EPSS 0.6 | 8.8 | internet | ❌ | 0.60 | RCE | none | **7.5** | High |
| Internet + RCE, no intel signals | 8.8 | internet | ❌ | 0.05 | RCE | none | **6.5** | High |
| Internet + RCE + partial mitigation | 8.8 | internet | ❌ | 0.10 | RCE | partial | **6.5** | High |
| Internal + RCE, no mitigation | 8.8 | internal | ❌ | 0.05 | RCE | none | **4.5** | Medium |
| Internal + RCE + **verified ACL** | 8.8 | internal | ❌ | 0.04 | RCE | **strong** | **3.0** | Medium |
| Constrained + DoS, no intel | 5.0 | constrained | ❌ | 0.05 | DoS | none | **3.5** | Medium |
| Local + DoS | 5.0 | local | ❌ | 0.05 | DoS | none | **2.0** | Low |
| No CVSS data, internet + KEV + RCE | — | internet | ✅ | — | RCE | none | **4.5** | Critical/High |

Score = `cvss × 0.4` + reachability (2.5/1.5/0.5/0) + intel (KEV +1.5, EPSS ≥0.5 +1.0, EPSS ≥0.1 +0.5) + utility bonus (high utility +0.5) − mitigation penalty (strong −1.5, partial −0.5), clamped 0–10.

**Guardrails:**

- External intel (KEV, high EPSS) can escalate urgency but cannot downgrade a finding. PoC availability is not used as a scoring signal — absence of public PoC does not reduce lane assignment.
- Mitigations must be exploit-relevant to shift a lane — "EDR deployed" does not mitigate an IDOR.
- Medium → Low requires a mitigation with a `causal_claim` of type `waf_rule`, `acl_segmentation`, `disable_feature`, `vendor_workaround`, or `virtual_patching`.

---

## Setup

Download the [latest release](https://github.com/incendiary/RubricAI/releases/latest) or clone a specific tag:

```bash
# Latest release (recommended)
git clone --branch v1.6.0 --depth 1 git@github.com:incendiary/RubricAI.git
cd RubricAI

python3 -m venv .venv
source .venv/bin/activate   # Windows: py -m venv .venv

pip install -e ".[dev]"
pre-commit install

cp .env.example .env
```

> **NVD API key — strongly recommended**
> Without a key the NVD rate limit is 5 requests per 30 seconds, which will throttle any session assessing more than a handful of CVEs. With a free key it rises to 50 req/30s.
> Register at **<https://nvd.nist.gov/developers/request-an-api-key>** (takes ~30 seconds), then set `NVD_API_KEY=<your-key>` in your `.env` file.

To track development (not recommended for production use):

```bash
git clone git@github.com:incendiary/RubricAI.git
cd RubricAI
```

### Requirements

- Python 3.11+
- [pre-commit](https://pre-commit.com/)

---

## Example scenarios

Full conversation transcripts with topical June 2026 CVEs are in [docs/examples.md](docs/examples.md). Select examples include PDF report cards with evidence appendices.

| # | Scenario | Policy | CVE | Report |
|---|---|---|---|---|
| 1 | [Quick start — triage a single CVE](docs/examples.md#1-quick-start--triage-a-single-cve) | CHML v0.2 | Check Point VPN RCE | [📄 PDF](examples/FIND-000012_20260621T145937Z.pdf) |
| 2 | [Policy comparison — same CVE, three policies](docs/examples.md#2-policy-comparison--same-cve-three-policies) | All three | Check Point VPN RCE | — |
| 3 | [BOM daily check — SaaS microservices stack](docs/examples.md#3-bom-daily-check--saas-microservices-stack) | CHML v0.2 | FastAPI request smuggling | — |
| 4 | [IaC assessment — PyCharm + Terraform](docs/examples.md#4-iac-environment-assessment--pycharm--terraform) | CHML v0.2 | EKS IMDSv2 gap | — |
| 5 | [KEV alone ≠ Critical — Linux kernel privesc](docs/examples.md#5-nuanced-case--kev-alone--critical) | All three | Linux kernel io_uring privesc | [📄 PDF](examples/FIND-build-infra-CVE-2024-1086_20260621T151612Z.pdf) |

---

## Running

### Local — Claude Desktop (stdio transport)

Generate the system prompt:

```bash
python3 scripts/render_prompt.py --target claude
# → prompts/out/claude_system_prompt.md
```

> **Note:** You do not need to manually start the server. Claude Desktop starts it automatically using the config written by `install_claude_config.py`. The `rubricai` command is only needed if you want to test the server directly from the terminal.

Register the server in `claude_desktop_config.json` using the merge script (safe to run on an existing config — it adds only the `rubricai` key and leaves everything else intact):

```bash
# Preview what will change
python scripts/install_claude_config.py

# Apply
python scripts/install_claude_config.py --write
```

The script writes the full path to the `rubricai` entry point script (e.g. `/Users/you/RubricAI/.venv/bin/rubricai`) as the `command` field. This is intentional — Claude Desktop spawns the server as a bare subprocess with no shell context, so bare commands like `python` or `python3` fail. The long path is expected and correct.

The script auto-detects the config path on macOS, Windows, and Linux. To override:

```bash
python3 scripts/install_claude_config.py --config ~/my-config.json --write
```

Restart Claude Desktop after writing.

### Starting a session

1. Generate the system prompt (once, or after workflow updates):

   ```bash
   python3 scripts/render_prompt.py --target claude
   # → prompts/out/claude_system_prompt.md
   ```

2. In Claude Desktop, create a **Project**, paste the contents of `prompts/out/claude_system_prompt.md` as the project instructions, and add RubricAI as an allowed MCP server for that project.

3. Start a conversation and say something like: *"I have a CVE to assess"* or *"Let's triage CVE-2024-1234"*. Claude will call `env_read()` automatically, surface any existing environment context, and begin the interview.

There is no slash command — the system prompt is the trigger. Every conversation in the project inherits the instructions and MCP tools automatically.

### Team deployment — Docker (SSE transport)

```bash
cp .env.example .env
# Edit .env: set NVD_API_KEY if you have one
# Optional: set RUBRICAI_API_KEY for Bearer token auth
# Optional: set RUBRICAI_TLS_CERT and RUBRICAI_TLS_KEY for HTTPS

docker compose up --build
```

Point your MCP client at `http://localhost:8000/sse`. Reports are persisted to `./reports/` on the host.

> **Security note:** The container runs as a non-root user (`rubricai`). Set
> `RUBRICAI_API_KEY` in production to require Bearer token authentication on all
> HTTP requests.

### OpenAI (GPT-4o, o3, Agents SDK)

```bash
python scripts/render_prompt.py --target openai
# → prompts/out/openai_system_prompt.md
```

**Option A — OpenAI Agents SDK (recommended):**

```python
from agents import Agent, MCPServerStdio

rubricai = MCPServerStdio(
    name="rubricai",
    params={
        "command": "/path/to/RubricAI/.venv/bin/rubricai",
        "env": {"RUBRICAI_TRANSPORT": "stdio"},
    },
)
agent = Agent(
    name="RubricAI",
    instructions=open("prompts/out/openai_system_prompt.md").read(),
    mcp_servers=[rubricai],
    model="gpt-4o",
)
```

**Option B — Responses API with remote MCP (SSE transport):**

```python
response = client.responses.create(
    model="gpt-4o",
    instructions=open("prompts/out/openai_system_prompt.md").read(),
    tools=[{"type": "mcp", "server_url": "http://localhost:8000/mcp", "require_approval": "never"}],
    input="I need to assess CVE-2024-21887",
)
```

See `prompts/out/openai_system_prompt.md` for full setup instructions including o1/o3 notes.

### Other MCP clients (generic / Gemini)

```bash
python scripts/render_prompt.py --target generic   # → prompts/out/generic_system_prompt.md
python scripts/render_prompt.py --target gemini    # → prompts/out/gemini_system_prompt.md
```

Paste the output into your client's system prompt field.

### PyCharm / JetBrains (Claude Code extension)

RubricAI works with the Claude Code JetBrains extension. The `project_scan` tool
auto-detects your project's manifest files and pre-fills the BOM before the interview
starts, so you don't have to list your dependencies manually.

```bash
python scripts/render_prompt.py --target pycharm
# → prompts/out/pycharm_system_prompt.md
```

**Setup:**

1. Install the **Claude Code** extension from the JetBrains Marketplace.
2. Configure the MCP server in Claude Code settings (same config as Claude Desktop):

   ```json
   {
     "mcpServers": {
       "rubricai": {
         "command": "/path/to/RubricAI/.venv/bin/rubricai",
         "env": {
           "RUBRICAI_TRANSPORT": "stdio",
           "RUBRICAI_REPORT_DIR": "/path/to/RubricAI/reports"
         }
       }
     }
   }
   ```

3. Paste `prompts/out/pycharm_system_prompt.md` into the System Prompt field
   (JetBrains → Settings → Tools → Claude Code → System Prompt).

4. Open any project in PyCharm and type in the Claude Code pane:
   > *"Scan this project for vulnerabilities."*

   Claude Code calls `project_scan(".")`, detects your stack (Python, Node, Go,
   Terraform, Docker, etc.), and begins the RubricAI interview pre-seeded with
   your actual components.

**IaC projects:** For Terraform projects, `project_scan` detects providers and module
sources and sets `project_type: iac` + `cloud_provider_hint` in the environment hints.
The interview shifts to infrastructure risk framing automatically.

---

## Tool call flow

An AI client conducts a session like this:

```
0. env_list()
   → list available named environments
   → ALWAYS ask "Which environment are we working on today?" before anything else

0b. env_read(environment_name=<answer>)
   → load that environment's state (components, network, BOM, standing mitigations)
   → offer BOM check if bom is non-empty: "Check for new CVEs in your stack?"

1. intel_lookup(cves=["CVE-XXXX-YYYY"])
   → call IMMEDIATELY after getting CVE ID — before asking the engineer most questions
   → returns KEV status, EPSS, CVSS, description, derived_finding_context
   → present derived context (utility, entry point, preconditions) for engineer confirmation

2. Ask only environment questions (not security questions the intel already answers):
   → Is [component] internet-exposed, internal, or local-only in your environment?
   → Any compensating controls in place?

3. score_evaluate(finding=..., intel=...)
   → returns lane (critical/high/medium/low), priority score, rationale, evidence gaps

4. report_generate(finding=..., intel=..., assessment=..., evidence=[...])
   → formats=["markdown","json"] by default; add "pdf" for shareable report card
   → persists to RUBRICAI_REPORT_DIR

5. env_write(state=..., environment_name=<active_environment>)
   → save updated environment state with session_log entry


   → save updated environment state with session_log entry
```

Report files are written as `{finding_id}_{timestamp}.md` and `.json` under `RUBRICAI_REPORT_DIR` (default `./reports/`).

---
## Environment state

RubricAI maintains a versioned environment state file so the AI accumulates context across sessions rather than starting cold each time.

### Bootstrap

```bash
cp environment/initial_state_template.json environment/state_v001.json
# Edit state_v001.json: fill in your components, network topology, standing mitigations
```

The AI will read this at the start of the next session and use it to skip questions it can already answer.

### Versioning

Every `env_write` call increments the version counter and writes a new `state_vNNN.json` — existing files are never overwritten. `state_latest.json` is always a copy of the most recent version.

```
environment/
  initial_state_template.json   ← checked in, copy to bootstrap
  state_v001.json               ← your initial description
  state_v002.json               ← updated after first session
  state_latest.json             ← always the most recent
```

Set `RUBRICAI_ENV_DIR` to change the directory.

### State file fields

| Field | Description |
|-------|-------------|
| `components` | Known components: name, version, type, environment, hosting |
| `network` | Topology: which services are internet-exposed, internal, etc. |
| `standing_mitigations` | Controls that apply across all findings (WAF, ACL, etc.) |
| `context_notes` | Free-form environment summary |
| `session_log` | Append-only history of what each session assessed and learned |

## Evidence

When an engineer claims a mitigation is in place (e.g. "we have a firewall blocking that port"), the AI can ask for supporting evidence and record it in the report.

**How it works:** The AI asks the engineer to paste the relevant policy, config, or describe a screenshot. It assesses whether the content is consistent with the claim and sets `verified: true/false`. Evidence is stored in the report JSON and rendered in the markdown report under an **Evidence** section.

**What to provide:**

- Firewall/ACL policy output (`iptables -L`, security group rules, NSG config)
- WAF rule excerpts
- Network config showing segmentation
- Log extracts confirming blocked traffic
- Screenshot descriptions

Evidence type values: `firewall_policy`, `network_config`, `acl_rule`, `waf_config`, `screenshot_description`, `log_extract`, `other`.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `intel_lookup` | Fetch KEV, EPSS, CVSS, PoC, and vendor signals for one or more CVEs |
| `score_evaluate` | Apply CHML policy and return lane, target, rationale, evidence gaps |
| `report_generate` | Produce markdown + JSON + optional PDF report card, persist to disk |
| `env_list` | List all named environments stored on disk (call at session start) |
| `env_read` | Read the current versioned state for a named environment |
| `env_write` | Write a versioned update to the environment state |
| `env_migrate_legacy` | Migrate pre-v0.8 flat state files into a named environment |
| `policy_get` | Return the current CHML policy definition for auditability |
| `bom_update` | Store or replace the Bill of Materials for a named environment |
| `bom_check` | Check all BOM components for CVEs published or modified recently |

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

### Troubleshooting

**Watch the server log in real time:**

```bash
tail -f ~/.local/share/rubricai/rubricai.log
```

Each `bom_check` call logs one line per component showing which fetcher was used (OSV or NVD), how many CVEs came back, and any rate-limit or HTTP errors. This is the fastest way to diagnose unexpected zero-result responses or slow queries.

Log verbosity is controlled by `RUBRICAI_LOG_LEVEL` (default `INFO`). Set to `DEBUG` for full request/response detail.

**Environment variables not reaching the MCP server:**

Claude Desktop spawns the MCP subprocess with only the vars listed in the `env` block of `claude_desktop_config.json` — shell dotfiles and system environment are not inherited. RubricAI calls `load_dotenv()` at startup, so any variable set in your `.env` file is loaded automatically. Variables explicitly set in `claude_desktop_config.json` take precedence over `.env`.

If a variable appears in `.env` but doesn't seem to be taking effect, check that `.env` is in the project root (same directory as `pyproject.toml`) and restart Claude Desktop after any changes.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUBRICAI_TRANSPORT` | `stdio` | `stdio` (Claude Desktop) or `sse` (Docker/remote) |
| `RUBRICAI_REPORT_DIR` | `~/.local/share/rubricai/reports` | Directory for persisted report cards |
| `RUBRICAI_ENV_DIR` | `~/.local/share/rubricai` | Directory for versioned environment state files |
| `RUBRICAI_HTTP_TIMEOUT` | `30` | HTTP timeout (seconds) baseline. Requests auto-escalate (5s → 10s → 30s) on timeout, so slow networks are handled gracefully without changing this value. Increase if all windows consistently exhaust. |
| `RUBRICAI_LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `RUBRICAI_LOG_FORMAT` | `text` | Log format (`text` for human-readable, `json` for structured) |
| `RUBRICAI_LOG_DIR` | `~/.local/share/rubricai` | Directory for log file (`rubricai.log`) |
| `NVD_API_KEY` | *(empty)* | Optional — increases NVD API rate limit from 5 to 50 req/30s |
| `RUBRICAI_API_KEY` | *(empty)* | Optional — require Bearer token auth on SSE/HTTP transport |
| `RUBRICAI_TLS_CERT` | *(empty)* | Path to PEM certificate file for HTTPS (SSE transport) |
| `RUBRICAI_TLS_KEY` | *(empty)* | Path to PEM private key file (required with TLS_CERT) |
| `RUBRICAI_CRITICAL_DAYS` | `3` | Override Critical lane SLA (days, or `patch_train`) |
| `RUBRICAI_HIGH_DAYS` | `7` | Override High lane SLA (days, or `patch_train`) |
| `RUBRICAI_MEDIUM_DAYS` | `patch_train` | Override Medium lane SLA (days, or `patch_train`) |
| `RUBRICAI_LOW_DAYS` | `patch_train` | Override Low lane SLA (days, or `patch_train`) |

---

## Roadmap

The roadmap has moved to a dedicated file: **[ROADMAP.md](ROADMAP.md)**.

It tracks delivered work (with version tags) and the open backlog. Each open item
names the file(s) to change, what to do, and how to verify — so it can be picked up
independently.

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
