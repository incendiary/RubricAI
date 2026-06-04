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
git clone --branch v0.5.2 --depth 1 git@github.com:incendiary/RubricAI.git
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
0. env_read()
   → load existing environment state (components, network, standing mitigations)
   → pre-populate interview answers; skip questions already answered

1. Interview engineer — collect finding fields:
     component, version, entry_point, reachability, attacker_utility,
     mitigations, data_impact, environment
   → ask for supporting evidence for any mitigation or reachability claim

2. intel_lookup(cves=["CVE-XXXX-YYYY"])
   → returns KEV status, EPSS score, CVSS, PoC availability

3. score_evaluate(finding=..., intel=...)
   → returns lane (critical/high/medium/low), target, rationale, evidence gaps

4. report_generate(finding=..., intel=..., assessment=..., evidence=[...])
   → persists markdown + JSON report cards to RUBRICAI_REPORT_DIR
   → evidence items stored in JSON; Evidence section rendered in markdown

5. env_write(state=...)
   → save updated environment state with session_log entry
```

Report files are written as `{finding_id}_{timestamp}.md` and `.json` under `RUBRICAI_REPORT_DIR` (default `./reports/`).

---

## Example interview

The following is a condensed example of what a RubricAI session looks like in Claude Desktop. The engineer answers questions; Claude calls the MCP tools and returns the verdict.

---

**Engineer:** I need to assess CVE-2024-21887 — it's a command injection in Ivanti Connect Secure.

**Claude:** I can see your environment includes: WebApp (internet-exposed), PaymentAPI (internal), UserDB and AnalyticsDB (local). Is this still current?

**Engineer:** Yes, still current. The affected component is Ivanti Connect Secure v22.3, it's our VPN gateway — internet-facing.

**Claude:** Got it. What's the exploit entry point?

**Engineer:** It's an authenticated HTTP request to the web management interface, port 443.

**Claude:** What can an attacker achieve? (RCE, auth bypass, privilege escalation, data access, etc.)

**Engineer:** Remote code execution. An attacker with any valid user credentials can run OS commands as root.

**Claude:** Is there authentication required to reach the vulnerable function?

**Engineer:** Yes, but only low-privilege user credentials — easily obtained or brute-forced.

**Claude:** Any mitigations in place? WAF rules, ACL, vendor workaround?

**Engineer:** We pushed Ivanti's XML mitigation workaround on the 3rd. I can paste the change ticket.

**Claude:** Please do — I'll record it as evidence.

**Engineer:** *[pastes INC-20240103-0042: applied mitigation per Ivanti KB44093, verified by change manager]*

**Claude:** *(calling `intel_lookup`, `score_evaluate`, `report_generate`)*

---

**Verdict: 🔴 CRITICAL — Remediate within 72 hours**

| Signal | Value |
|--------|-------|
| KEV listed | ✅ Yes — due 2024-01-31 |
| EPSS | 0.94 (99th percentile) |
| Reachability | Internet-exposed |
| Utility | RCE as root |
| Mitigation | Vendor workaround applied (unverified) |

**Rationale:** KEV-listed + internet-exposed + RCE = Critical under CHML policy. The vendor workaround does not shift the lane because it has not been independently verified and Ivanti has noted bypasses exist.

**Evidence gaps:**
- [ ] Vendor workaround verification: confirm the mitigation is active and covers your specific build
- [ ] Confirm no authentication bypass for the management interface exists on your build

**Report saved to:** `reports/FIND-ICS-001_20240104T103000.md`

---

The JSON report, markdown card, and all evidence are written to disk for submission to your central security review queue.

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
| `RUBRICAI_ENV_DIR` | `./environment` | Directory for versioned environment state files |

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

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
