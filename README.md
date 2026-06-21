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

## Example scenarios

Full conversation transcripts with topical June 2026 CVEs are in [docs/examples.md](docs/examples.md).

| # | Scenario | Policy | CVE |
|---|---|---|---|
| 1 | [Quick start — triage a single CVE](docs/examples.md#1-quick-start--triage-a-single-cve) | CHML v0.2 | Check Point VPN RCE |
| 2 | [Policy comparison — same CVE, three policies](docs/examples.md#2-policy-comparison--same-cve-three-policies) | All three | Check Point VPN RCE |
| 3 | [BOM daily check — SaaS microservices stack](docs/examples.md#3-bom-daily-check--saas-microservices-stack) | CHML v0.2 | FastAPI request smuggling |
| 4 | [IaC assessment — PyCharm + Terraform](docs/examples.md#4-iac-environment-assessment--pycharm--terraform) | CHML v0.2 | EKS IMDSv2 gap |
| 5 | [KEV alone ≠ Critical — Linux kernel privesc](docs/examples.md#5-nuanced-case--kev-alone--critical) | All three | Linux kernel io_uring privesc |

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

### Example: three-tier web application

The environment below illustrates how the state file captures topology that affects scoring. Notice that `UserDB` (PII) and `AnalyticsDB` (non-sensitive) sit in the same network tier, but the AI uses `context_notes` and component notes to distinguish risk — a CVE in `PaymentAPI` touching `UserDB` scores differently from the same CVE in `ReportingService` touching `AnalyticsDB`.

```
Internet
   │
   ▼
[ WAF / CDN ]
   │
   ▼
[ WebApp ]  ←── internet_exposed
   │
   ▼
[ PaymentAPI ]  ←── internal (called by WebApp only)
   │         \
   ▼           ▼
[ UserDB ]   [ AnalyticsDB ]
  (PII,         (aggregated
  payment        metrics,
  records)       no PII)
```

```json
{
  "schema_version": "1",
  "version": 1,
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T00:00:00Z",
  "components": [
    {
      "name": "WebApp",
      "version": "4.2.1",
      "type": "service",
      "environment": "production",
      "hosting": "cloud",
      "notes": "React SPA served via CloudFront. Calls PaymentAPI for transactions."
    },
    {
      "name": "PaymentAPI",
      "version": "2.0.3",
      "type": "service",
      "environment": "production",
      "hosting": "cloud",
      "notes": "Internal REST API. Handles payment processing. Has read/write access to UserDB."
    },
    {
      "name": "UserDB",
      "version": "PostgreSQL 15",
      "type": "service",
      "environment": "production",
      "hosting": "cloud",
      "notes": "Contains PII (name, email, address) and payment card tokens. Accessible only from PaymentAPI."
    },
    {
      "name": "AnalyticsDB",
      "version": "PostgreSQL 15",
      "type": "service",
      "environment": "production",
      "hosting": "cloud",
      "notes": "Aggregated metrics only — no PII, no payment data. Accessible from ReportingService."
    },
    {
      "name": "ReportingService",
      "version": "1.1.0",
      "type": "service",
      "environment": "production",
      "hosting": "cloud",
      "notes": "Internal dashboard backend. Reads from AnalyticsDB only."
    }
  ],
  "network": {
    "internet_exposed_services": ["WebApp"],
    "constrained_external": [],
    "internal_only": ["PaymentAPI", "ReportingService"],
    "local_only": ["UserDB", "AnalyticsDB"],
    "notes": "WebApp is the only internet-facing entry point. All internal services communicate over a private VPC subnet. Databases are not reachable from the application tier without going through their respective service."
  },
  "standing_mitigations": [
    {
      "type": "waf_rule",
      "description": "Cloudflare WAF in front of WebApp — OWASP Core Rule Set enabled",
      "applies_to": ["WebApp"],
      "verified": false,
      "notes": "Reduces surface for common web attack patterns but does not mitigate logic flaws or auth bypasses in PaymentAPI."
    },
    {
      "type": "acl_segmentation",
      "description": "VPC security groups restrict UserDB to inbound connections from PaymentAPI only (port 5432)",
      "applies_to": ["UserDB"],
      "verified": false,
      "notes": "ACL is causal for reachability claims about UserDB — a vulnerability in UserDB is only reachable via PaymentAPI."
    }
  ],
  "context_notes": "Three-tier e-commerce platform. WebApp is public-facing; PaymentAPI and both databases are internal. UserDB holds PII and payment tokens and is the highest-sensitivity component. AnalyticsDB holds only aggregated, non-personal metrics. Prioritise findings that affect PaymentAPI or UserDB — lateral movement from WebApp to PaymentAPI is the primary threat path.",
  "session_log": []
}
```

The key contrast: a finding in `PaymentAPI` with `data_access` utility scores higher because `context_notes` flags it as the path to PII. A finding in `ReportingService` with the same CVE scores lower — `AnalyticsDB` holds no sensitive data and the service is further from the internet entry point.

---

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
| `RUBRICAI_HTTP_TIMEOUT` | `30` | HTTP timeout (seconds) for CISA KEV, EPSS, and NVD fetches |
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

| Issue | Status | Description |
|-------|--------|-------------|
| [#6](https://github.com/incendiary/RubricAI/issues/6) | ✅ Done | Secret scan — gitleaks + TruffleHog + detect-secrets (pre-commit + CI) |
| [#7](https://github.com/incendiary/RubricAI/issues/7) | ✅ Done | Dependency audit — Dependabot (pip + Actions, weekly) |
| [#8](https://github.com/incendiary/RubricAI/issues/8) | ✅ Done | Core implementation — schemas, CHML policy, fetchers, MCP tools |
| [#9](https://github.com/incendiary/RubricAI/issues/9) | ✅ Done | Tooling — Black, Ruff, isort, pre-commit, CI pipeline |
| [#10](https://github.com/incendiary/RubricAI/issues/10) | ✅ Done | Tests — expand integration coverage, add fetcher mocks |
| [#11](https://github.com/incendiary/RubricAI/issues/11) | ✅ Done | Documentation — README, system prompt templates |
| [#31](https://github.com/incendiary/RubricAI/issues/31) | ✅ Done | MCP server fix — use rubricai entry point instead of python -m src.main |
| [#35](https://github.com/incendiary/RubricAI/issues/35) | ✅ Done | Priority Score — RubricAI-native 0–10 score for within-lane prioritisation |
| [#37](https://github.com/incendiary/RubricAI/issues/37) | ✅ Done | Signal transparency — Signal Analysis table showing how CVSS/EPSS/KEV were applied (v0.6.1) |
| [#38](https://github.com/incendiary/RubricAI/issues/38) | ✅ Done | Intel-first interview — derive technical fields from CVE data, ask engineers only what they know (v0.7.0) |
| [#39](https://github.com/incendiary/RubricAI/issues/39) | ✅ Done | BOM tracking — `bom_update` / `bom_check` MCP tools for daily CVE monitoring (v0.7.0) |
| [#40](https://github.com/incendiary/RubricAI/issues/40) | ✅ Done | PDF export — single-page A4 landscape report card via `formats=["pdf"]` (v0.7.0) |
| [#45](https://github.com/incendiary/RubricAI/issues/45) | ✅ Done | Multi-environment — named environments, always-first selection, legacy migration (v0.8.0) |
| [#46](https://github.com/incendiary/RubricAI/issues/46) | ✅ Done | Compact PDF report card — dense grid, no whitespace (v0.8.0) |
| [#47](https://github.com/incendiary/RubricAI/issues/47) | ✅ Done | OpenAI compatibility — Agents SDK + Responses API setup (v0.8.0) |
| [#54](https://github.com/incendiary/RubricAI/issues/54) | ✅ Done | Bug: score_evaluate schema mismatch — cvss_av in entry_point violates extra=forbid (v0.8.1) |
| [#55](https://github.com/incendiary/RubricAI/issues/55) | ✅ Done | Evidence file storage + PDF appendix — file_path on EvidenceItem, embedded screenshots (v0.8.1) |
| [#58](https://github.com/incendiary/RubricAI/issues/58) | ✅ Done | Bug: NVD search() raises on 404 — bom_check aborts for unresolvable keywords (v0.8.2) |
| [#59](https://github.com/incendiary/RubricAI/issues/59) | ✅ Done | Bug: bom_check uses name+version keyword — NVD AND logic returns zero results for known-vulnerable components (v0.8.3) |
| — | ✅ Done | BOM name resolution — OSV translation layer (PyPI/npm/Go/Maven) + NVD keyword normalisation fallback; users never need to know NVD naming conventions (v0.8.4) |
| [#73](https://github.com/incendiary/RubricAI/issues/73) | ✅ Done | Security: XSS — enable Jinja2 HTML autoescape, mark safe only constructed data URIs (v0.8.6) |
| [#74](https://github.com/incendiary/RubricAI/issues/74) | ✅ Done | Security: Arbitrary file read — path validation on evidence file_path (v0.8.7) |
| [#75](https://github.com/incendiary/RubricAI/issues/75) | ✅ Done | Security: Optional API key auth + TLS on SSE transport (v0.8.8) |
| [#76](https://github.com/incendiary/RubricAI/issues/76) | ✅ Done | Security: Path traversal — validate environment_name in BOM tools + cache namespace (v0.8.9) |
| [#77](https://github.com/incendiary/RubricAI/issues/77) | ✅ Done | Security: TOCTOU race — file locking on state versioning (v0.8.10) |
| [#78](https://github.com/incendiary/RubricAI/issues/78) | ✅ Done | Security: HTTP error handling — catch exceptions in fetchers, validate timeout env var (v0.8.11) |
| [#79](https://github.com/incendiary/RubricAI/issues/79) | ✅ Done | Security: Dockerfile hardening — non-root user, remove dev deps, no error suppression (v0.8.12) |
| [#80](https://github.com/incendiary/RubricAI/issues/80) | ✅ Done | Security: Schema + validation — remove extra=allow, CVE format + list-size limits (v0.8.13) |
| — | ✅ Done | Security: Log path validation + volume security docs (v0.8.14) |
| — | ✅ Done | **v0.9.0 — Security hardening complete** — all 17 findings remediated (PRs #73–#81), stale branches pruned |
| [#51](https://github.com/incendiary/RubricAI/issues/51) | ✅ Done | End-to-end workflow test — full interview cycle in a single test (v0.9.0) |
| [#52](https://github.com/incendiary/RubricAI/issues/52) | ✅ Done | server.py smoke test — import and tool registration count (v0.9.0) |
| [#82](https://github.com/incendiary/RubricAI/pull/82) | ✅ Done | HTTP retry with exponential backoff + cache lazy eviction (v0.9.1) |
| [#83](https://github.com/incendiary/RubricAI/pull/83) | ✅ Done | Health endpoint, structured JSON logging, --verbose CLI flag (v0.9.2) |
| [#84](https://github.com/incendiary/RubricAI/pull/84) | ✅ Done | Prompt templates updated with complete 10-tool reference (v0.9.3) |
| [#85](https://github.com/incendiary/RubricAI/pull/85) | ✅ Done | README refresh — 10-tool table, env vars, version sync test (v0.9.4) |
| [#86](https://github.com/incendiary/RubricAI/pull/86) | ✅ Done | Auth middleware test coverage (v0.9.5) |
| — | ✅ Done | **v1.0.0 — Production-ready release** — retry, observability, docs, full test coverage |
| [#88](https://github.com/incendiary/RubricAI/pull/88) | ✅ Done | Policy dispatcher — `epss-v5` and `bod-26-04` policies; registry; `policy_version` param live (v1.1.0) |
| [#92](https://github.com/incendiary/RubricAI/pull/92) | ✅ Done | BOD 26-04 policy — 4-signal scoring with Vulnrichment automatable (v1.2.0) |
| [#95](https://github.com/incendiary/RubricAI/pull/95) | ✅ Done | `project_scan` MCP tool — auto-discovers BOM from manifests; PyCharm/JetBrains integration (v1.3.0) |
| [#98](https://github.com/incendiary/RubricAI/pull/98) | ✅ Done | `docs/examples.md` — 5 end-to-end conversation examples with BOM headers (v1.4.0) |
| [#100](https://github.com/incendiary/RubricAI/pull/100) | ✅ Done | Bug: install_claude_config.py drops NVD_API_KEY on re-run — deep-merge env dict (v1.4.1) |
| [#102](https://github.com/incendiary/RubricAI/pull/102) | ✅ Done | Docs: replace fabricated CVEs with real NVD-verified entries + BOM headers (v1.5.0) |
| — | ✅ Done | **v1.6.0** — `vendor_patch` mitigation type; patched findings resolve to Low across all 3 policies; `score_compare` tool for side-by-side policy comparison; workflow prompt schema reference |

### Open work

All open and planned items are gathered here for implementation. Each task is written so it can be picked up independently: it names the **file(s)** to change, **what** to do, and **how to verify** the change. Pick the highest-priority unblocked item, make the change on a feature branch (the repo blocks direct commits to `main`), run the verify step, and open a PR. Note: this development machine has **no Docker** — any step that needs a container build/run must be verified on a system that does (the code change itself can still be made here).

| ID | Priority | Status | Task |
|----|----------|--------|------|
| OPEN-1 | High | ✅ Done | **Bug — `/health` returned 401 when API-key auth was enabled; auth tests didn't exercise the real code.** Fixed in PR [#106](https://github.com/incendiary/RubricAI/pull/106): `APIKeyAuthMiddleware` extracted from `src/main.py` into `src/rubricai/auth.py` (with a `PUBLIC_PATHS` exemption for `/health`); `src/main.py` now imports and wires the real middleware; `tests/test_auth.py` rewritten to import the real class and assert `/health` returns 200 with no token while protected routes still 401 on missing/wrong tokens and 200 on the correct Bearer key. **Remaining (handed to implementing agents, needs Docker):** add a `HEALTHCHECK` to `Dockerfile` and/or a `healthcheck:` to `docker-compose.yml` doing an HTTP GET on `/health`, and verify on a Docker-capable machine. |
| OPEN-2 | High | ✅ Done | **Bug — NVD search cache key omitted `vendor`, so results could be served for the wrong vendor.** Fixed in PR [#106](https://github.com/incendiary/RubricAI/pull/106): `search()` in `src/rubricai/fetchers/nvd.py` now includes a normalised vendor segment in the cache key (`f"{keyword.lower()}:{(vendor or '').lower()}:{days_back}:{max_results}"`), and `tests/test_fetchers.py` has a regression test proving two searches with the same keyword but different vendors do not reuse each other's cached results. |
| OPEN-3 | Medium | ⬜ Open | **Claude Desktop config preflight — don't write a broken path.** **Where:** `scripts/install_claude_config.py` writes the `.venv/bin/rubricai` path (Windows: `.venv\Scripts\rubricai.exe`) into `claude_desktop_config.json` even on a fresh clone where that executable doesn't exist yet, producing a config that silently fails. **Do:** before writing, check whether the entry-point file exists; if it doesn't, print clear setup steps (`python3 -m venv .venv`, activate it, `pip install -e ".[dev]"`) and refuse to write unless an explicit override flag (e.g. `--force`) is passed. Keep the existing dry-run/`--write` behaviour. **Verify:** add a test in `tests/test_install_claude_config.py`: with a non-existent executable and no override, the script exits non-zero (or warns) and does **not** modify the config; with the override flag, it writes as before. |
| OPEN-4 | Medium | ⬜ Open | **Portable secrets baseline (tooling cleanup, not a secret incident).** **Where:** `.secrets.baseline` records an absolute local filesystem path and can flag intentional test fixtures (e.g. the `secret-key` string in `tests/test_install_claude_config.py`), so it produces noisy, machine-specific diffs between developers. **Do:** pick one approach and document it: (a) add an inline allowlist / `# pragma: allowlist secret` marker to the intentional fixture lines, and/or (b) document the regenerate-and-review workflow in `README.md` (or a new `CONTRIBUTING.md`) so the baseline stays stable across machines and personal path churn doesn't create diffs. **Verify:** `python -m detect_secrets scan --baseline .secrets.baseline` reports no new unaudited secrets, and `pytest tests/test_secrets.py` passes. |
| OPEN-5 | Medium | ⬜ Open | **Feature — VS Code / Copilot Chat MCP client support.** **Where:** new docs in `README.md`, optionally a new template in `prompts/templates/` and a `--target vscode` branch in `scripts/render_prompt.py`. **Do:** add first-class setup instructions for using RubricAI as an MCP server from VS Code / Copilot Chat. Cover both `stdio` (local) and `sse` (local Docker/remote) transports; show the exact VS Code MCP server configuration shape (command, args, cwd, env); explain where to paste or load the rendered system prompt; and, only if VS Code needs client-specific wording, add a `vscode.md.j2` template plus a `--target vscode` option in `render_prompt.py` (add `"vscode"` to the `TARGETS` list). **Verify:** on a fresh VS Code workspace, the configured client starts RubricAI, can call `env_list`, run a simple `intel_lookup`, and write reports/state to predictable local folders. *(Docker/SSE path must be verified on a machine with Docker.)* |
| #104 | Low | ⬜ Open | **Feature — threat-intel enrichment.** **Where:** intel fetchers (`src/rubricai/fetchers/`) and the intel schema (`src/rubricai/schemas/intel.py`). **Do:** add optional `threat_regions` and `threat_industries` context sourced from free/open feeds, each annotated with a confidence level and a source/provenance reference so downstream reviewers can judge the signal. Keep it optional — absence of this data must not change existing scoring. **Verify:** unit tests for the new fetcher/parsing with mocked feed responses; confirm scoring output is unchanged when the enrichment is absent. Tracked as GitHub issue [#104](https://github.com/incendiary/RubricAI/issues/104). |
| #105 | Low | ⬜ Open | **Feature — environment lifecycle / reset tools.** **Where:** environment tools in `src/rubricai/tools/environment.py`. **Do:** add MCP tools to (a) clear a single named environment, (b) clear all environments, and (c) perform a full local reset of stored data, reports, and PDFs. These are destructive, so require an explicit `confirm=true` argument and support a dry-run mode that reports what *would* be deleted without deleting it. **Verify:** tests in `tests/test_environment.py` proving dry-run deletes nothing, `confirm=true` deletes the expected paths only, and the operations never escape the configured state/report directories (reuse the existing path-validation helpers). Tracked as GitHub issue [#105](https://github.com/incendiary/RubricAI/issues/105). |
| OPEN-6 | Medium | ⬜ Open | **Release / tag hygiene — the documented clone command points at stale code.** **Where:** the **Setup** section of `README.md` says `git clone --branch v1.6.0 …`, but `git describe --tags` reports HEAD as `v1.6.0-10-g…` — i.e. ~10 commits ahead of the `v1.6.0` tag. A user who follows the docs gets code missing the latest fixes. **Do:** once the open bug fixes above are merged, tag a new release (e.g. `v1.6.1`) and update the README clone command and the "latest release" reference to that tag; alternatively change the doc to clone the default branch. Keep the pinned-tag example and the newest tag in sync going forward. **Verify:** a fresh `git clone --branch <tag>` followed by `git describe --tags` returns exactly `<tag>` with no `-N-g…` suffix, and the README clone command names the newest tag. |
| OPEN-7 | Medium | ⬜ Open | **Linter version pin drift between pre-commit and CI** *(replaces an earlier note that wrongly claimed `.github/workflows/ci.yml` was missing — it exists).* **Where:** `.pre-commit-config.yaml` pins ruff at `v0.11.9`, while `.github/workflows/ci.yml` installs ruff `0.15.15` (the local venv here has `0.15.17`). `black` (`26.5.1`) and `isort` (`8.0.1`) already match across both; only ruff drifts. Different ruff versions can pass locally / in pre-commit but fail the CI lint job (or vice-versa). **Do:** align the ruff version in `.pre-commit-config.yaml` and `.github/workflows/ci.yml` to a single pinned version (ideally pin black/ruff/isort identically in both files). **Verify:** `pre-commit run --all-files` and the CI `lint` job run the same ruff version, and `ruff check .` passes under it. |
| OPEN-8 | Low | ⬜ Open | **Python version policy is inconsistent.** **Where:** `pyproject.toml` declares `requires-python = ">=3.11"`; `.github/workflows/ci.yml` tests only `3.11`; the `Dockerfile` uses `python:3.11-slim`; but the project is allowed on (and currently developed on) newer interpreters up to 3.14. So 3.12–3.14 are permitted yet untested. **Do:** choose one: (a) add a CI test matrix covering `3.11`, `3.12`, `3.13` (and `3.14` once green) via `strategy.matrix.python-version`; or (b) narrow `requires-python` to the range actually tested and state the supported version(s) in the README **Requirements** section. **Verify:** CI is green across every declared version, or `requires-python` and the README agree on the single supported version. |
| OPEN-9 | Low | ⬜ Open | **Document WeasyPrint native dependencies for local installs.** **Where:** README **Setup** section. **Why:** PDF export depends on WeasyPrint, which needs native libraries (pango, cairo, gdk-pixbuf). CI installs these via `apt-get` in `.github/workflows/ci.yml`, but the README does not mention them — so a fresh local `pip install` succeeds and only fails later, at runtime, when a PDF is generated. **Do:** add a short "PDF export prerequisites" note with install commands for macOS (`brew install pango gdk-pixbuf libffi`) and Debian/Ubuntu (reuse the apt package list already in `ci.yml`), and note that PDF export is optional — all other features work without these libs. **Verify:** on a clean machine, after following the README, `report_generate(..., formats=["pdf"])` produces a PDF with no `ImportError`/`OSError`. |
| [#12](https://github.com/incendiary/RubricAI/issues/12) | — | ⏸️ Blocked | **Branch protection on `main`.** Requires a public repo or GitHub Pro/Team (not available on a private repo on the free plan). Unblock by making the repo public (per the release checklist) or upgrading the plan, then enable required status checks (`ci`) and required PR review. Tracked as GitHub issue [#12](https://github.com/incendiary/RubricAI/issues/12). |

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
