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
git clone --branch v0.8.4 --depth 1 git@github.com:incendiary/RubricAI.git
cd RubricAI

python3 -m venv .venv
source .venv/bin/activate   # Windows: py -m venv .venv

pip install -e ".[dev]"
pre-commit install

cp .env.example .env
```

> **NVD API key — strongly recommended**
> Without a key the NVD rate limit is 5 requests per 30 seconds, which will throttle any session assessing more than a handful of CVEs. With a free key it rises to 50 req/30s.
> Register at **https://nvd.nist.gov/developers/request-an-api-key** (takes ~30 seconds), then set `NVD_API_KEY=<your-key>` in your `.env` file.

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

docker compose up --build
```

Point your MCP client at `http://localhost:8000/sse`. Reports are persisted to `./reports/` on the host.

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

## Example sessions

Two common workflows are shown below. Both use the same Claude Desktop setup — the difference is what you ask.

---

### Scenario 1 — Triage a specific CVE

An engineer receives a scanner alert and needs a priority decision before the next patch window.

---

**Claude:** *(calls `env_list`)* Which environment are we working on today? I have these on record: **production-dmz**, **staging-web**. Or give me a new name to create one.

**Engineer:** Production-dmz.

**Claude:** *(calls `env_read("production-dmz")`)* I have your environment on record: WebApp (internet-exposed), PaymentAPI (internal), UserDB and AnalyticsDB (local). Still current?

**Engineer:** Yes. I need to assess CVE-2024-21887 — it's showing up in my scanner for Ivanti Connect Secure v22.3. Our VPN gateway.

**Claude:** *(calls `intel_lookup` immediately)*

Got the CVE data. Here's what the public record says:

> **CVE-2024-21887** — A command injection vulnerability in the web component of Ivanti Connect Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.
>
> - **What an attacker can achieve:** Remote code execution (from CVE description)
> - **How the exploit is triggered:** Network-accessible (CVSS AV:N)
> - **Privileges required:** High (CVSS PR:H — administrator credentials)
> - **CVSS base:** 9.1 · **EPSS:** 0.94 (99th percentile) · **KEV listed:** Yes (due 2024-01-31)

Does this match your understanding of the vulnerability?

**Engineer:** Yes, that's right. Admin credentials, web interface on port 443.

**Claude:** Two environment questions:

1. Is the Ivanti management interface reachable from the internet, or only internally?
2. Any compensating controls in place? (ACL, vendor workaround, patching)

**Engineer:** It's internet-facing — port 443 is open externally. We pushed Ivanti's XML mitigation workaround on the 3rd. Here's the change ticket: *[pastes INC-20240103-0042: applied mitigation per Ivanti KB44093, verified by change manager]*

**Claude:** *(calls `score_evaluate`, `report_generate`)*

---

**🔴 CRITICAL — Remediate within 72 hours**

| Signal | Value | Applied | Effect |
|--------|-------|---------|--------|
| CVSS base | 9.1 (v3.1) | ✅ | +3.64 to priority score |
| CISA KEV | **Listed** (due 2024-01-31) | ✅ | Critical escalation +1.5 pts |
| EPSS | 0.9400 (99th pct) | ✅ high | +1.0 pts |
| Reachability | internet\_exposed | ✅ | +2.5 pts |
| Utility | HIGH (rce) | ✅ | +0.5 pts |
| Mitigation | partial (workaround, unverified) | ⚠️ | −0.5 pts |

**Priority score: 9.2 / 10**

**Verdict rationale:**
- CVE is on CISA KEV with an internet-exposed exploit path and high attacker utility.

**Required actions:**
- → Remediate within 72 hours or apply immediate compensating controls.
- → Strengthen mitigations with causal claims or escalate to patching.

**Evidence gaps:**
- [ ] Vendor workaround: confirm KB44093 is active and covers your specific build (Ivanti has noted bypasses exist on some versions)

**Reports saved to:** `reports/FIND-ICS-001_20240104T103000.md` and `.json`

*(If PDF requested: `.pdf` report card also saved — suitable for security team review)*

---

### Scenario 2 — BOM ingestion and daily CVE check

An engineer wants to monitor their entire stack for new vulnerabilities, not just respond to individual alerts.

---

**Claude:** *(calls `env_list`)* Which environment are we working on today? I have: **production-dmz**, **staging-web**. Or give me a new name.

**Engineer:** Production-dmz. I want to register our software stack so we can check for new CVEs.

**Claude:** *(calls `env_read("production-dmz")`)* No BOM on record yet for production-dmz. Paste your component list — name, version, and type if you know it.

**Engineer:**
```
nginx 1.24.0 (reverse proxy)
PostgreSQL 15.2 (database)
OpenSSL 3.1.4 (library)
Django 4.2.7 (web framework)
Redis 7.0.11 (cache)
```

**Claude:** *(calls `bom_update(environment_name="production-dmz", components=[...])`)* Stored 5 components. BOM saved to production-dmz — it'll be available in every future session.

---

*Next morning:*

**Engineer:** Any new CVEs for our stack this week?

**Claude:** *(calls `bom_check(environment_name="production-dmz", days_back=7)`)* Checked all 5 components against NVD. Here's what's new:

**nginx 1.24.0** — 1 CVE found
- `CVE-2024-7347` — CVSS 4.7 (Medium) — nginx HTTP/3 QUIC module: specially crafted QUIC packets may cause worker process crash. *Published 2024-08-14.*

**OpenSSL 3.1.4** — 2 CVEs found
- `CVE-2024-5535` — CVSS 9.1 (Critical) — SSL_select_next_proto buffer overread, potential remote code execution. *Published 2024-06-27.*
- `CVE-2024-4603` — CVSS 5.3 (Medium) — Excessive time checking DSA keys. *Published 2024-05-16.*

**PostgreSQL 15.2, Django 4.2.7, Redis 7.0.11** — no new CVEs this week.

---

CVE-2024-5535 (OpenSSL, CVSS 9.1) looks urgent. Want me to start a full triage for that one now? I already have OpenSSL 3.1.4 pre-filled from your BOM.

**Engineer:** Yes, let's triage it.

**Claude:** *(calls `intel_lookup("CVE-2024-5535")` — pre-fills component from BOM, presents derived context for confirmation, then asks only reachability and mitigation questions)*

---

The JSON report, markdown card, and optional PDF are written to disk for submission to your central security review queue.

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
| `env_read` | Read the current environment state (or empty template if none exists) |
| `env_write` | Write a versioned update to the environment state |
| `intel_lookup` | Fetch KEV, EPSS, CVSS, PoC, and vendor signals for one or more CVEs |
| `score_evaluate` | Apply CHML policy and return lane, target, rationale, evidence gaps |
| `report_generate` | Produce markdown + JSON report card with optional evidence, persist to disk |
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
| [#10](https://github.com/incendiary/RubricAI/issues/10) | ✅ Done | Tests — expand integration coverage, add fetcher mocks |
| [#11](https://github.com/incendiary/RubricAI/issues/11) | ✅ Done | Documentation — README, system prompt templates |
| [#12](https://github.com/incendiary/RubricAI/issues/12) | ⬜ Open | Branch protection — force-push blocked, required CI checks on main |
| [#31](https://github.com/incendiary/RubricAI/issues/31) | ✅ Done | MCP server fix — use rubricai entry point instead of python -m src.main |
| [#35](https://github.com/incendiary/RubricAI/issues/35) | ✅ Done | Priority Score — RubricAI-native 0–10 score for within-lane prioritisation |
| [#37](https://github.com/incendiary/RubricAI/issues/37) | ✅ Done | Signal transparency — Signal Analysis table showing how CVSS/EPSS/KEV were applied (v0.6.1) |
| [#38](https://github.com/incendiary/RubricAI/issues/38) | ✅ Done | Intel-first interview — derive technical fields from CVE data, ask engineers only what they know (v0.7.0) |
| [#39](https://github.com/incendiary/RubricAI/issues/39) | ✅ Done | BOM tracking — `bom_update` / `bom_check` MCP tools for daily CVE monitoring (v0.7.0) |
| [#40](https://github.com/incendiary/RubricAI/issues/40) | ✅ Done | PDF export — single-page A4 landscape report card via `formats=["pdf"]` (v0.7.0) |
| [#45](https://github.com/incendiary/RubricAI/issues/45) | ✅ Done | Multi-environment — named environments, always-first selection, legacy migration (v0.8.0) |
| [#46](https://github.com/incendiary/RubricAI/issues/46) | ✅ Done | Compact PDF report card — dense grid, no whitespace (v0.8.0) |
| [#47](https://github.com/incendiary/RubricAI/issues/47) | ✅ Done | OpenAI compatibility — Agents SDK + Responses API setup (v0.8.0) |
| [#51](https://github.com/incendiary/RubricAI/issues/51) | ⬜ Open | End-to-end workflow test — full interview cycle in a single test (v0.9.0) |
| [#52](https://github.com/incendiary/RubricAI/issues/52) | ⬜ Open | server.py smoke test — import and tool registration count (v0.9.0) |
| [#54](https://github.com/incendiary/RubricAI/issues/54) | ✅ Done | Bug: score_evaluate schema mismatch — cvss_av in entry_point violates extra=forbid (v0.8.1) |
| [#55](https://github.com/incendiary/RubricAI/issues/55) | ✅ Done | Evidence file storage + PDF appendix — file_path on EvidenceItem, embedded screenshots (v0.8.1) |
| [#58](https://github.com/incendiary/RubricAI/issues/58) | ✅ Done | Bug: NVD search() raises on 404 — bom_check aborts for unresolvable keywords (v0.8.2) |
| [#59](https://github.com/incendiary/RubricAI/issues/59) | ✅ Done | Bug: bom_check uses name+version keyword — NVD AND logic returns zero results for known-vulnerable components (v0.8.3) |
| — | ✅ Done | BOM name resolution — OSV translation layer (PyPI/npm/Go/Maven) + NVD keyword normalisation fallback; users never need to know NVD naming conventions (v0.8.4) |
| — | 🔧 In Progress | Security: XSS — enable Jinja2 HTML autoescape, mark safe only constructed data URIs (v0.8.6) |
| — | ⬜ Open | Security: Arbitrary file read — path validation on evidence file_path |
| — | ⬜ Open | Security: Optional API key auth + TLS on SSE transport |
| — | ⬜ Open | Security: Path traversal — validate environment_name in BOM tools + cache namespace |
| — | ⬜ Open | Security: TOCTOU race — file locking on state versioning |
| — | ⬜ Open | Security: HTTP error handling — catch exceptions in fetchers, validate timeout env var |
| — | ⬜ Open | Security: Dockerfile hardening — non-root user, remove dev deps, no error suppression |
| — | ⬜ Open | Security: Schema + validation — remove extra=allow, CVE format + list-size limits |
| — | ⬜ Open | Security: Log path validation + volume security docs |

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
