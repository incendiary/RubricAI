# RubricAI — Example Sessions

Full conversation transcripts showing how RubricAI works in practice. All CVEs are real
and verifiable on NVD. Each example uses different entry points, policies, or workflows
to illustrate different capabilities. EPSS values shown are point-in-time approximations —
they change daily as exploitation activity is observed.

---

## Contents

1. [Quick start — triage a single CVE (Palo Alto PAN-OS, CHML)](#1-quick-start--triage-a-single-cve)
2. [Policy comparison — same CVE, three policies](#2-policy-comparison--same-cve-three-policies)
3. [BOM daily check — SaaS microservices stack](#3-bom-daily-check--saas-microservices-stack)
4. [IaC environment assessment — PyCharm + Terraform](#4-iac-environment-assessment--pycharm--terraform)
5. [Nuanced case — KEV alone ≠ Critical (Linux kernel privesc)](#5-nuanced-case--kev-alone--critical)

---

## 1. Quick start — Triage a single CVE

**CVE:** CVE-2024-3400 — Palo Alto Networks PAN-OS GlobalProtect OS Command Injection
**Scenario:** An engineer receives a scanner alert for their internet-facing firewall/VPN gateway.
**Policy:** `chml-v0.2` (default)
**Entry point:** Claude Desktop
**[Live conversation](https://claude.ai/share/43c6095e-f82a-4f68-ba35-10882495e90e)** — Full transcript with evidence PDF appendix

### Environment: production-edge

| Component | Version | Type | Exposure |
|---|---|---|---|
| VPN-GW01 (Palo Alto PA-3200, PAN-OS) | 11.1.0 | network-appliance | internet-exposed (443/UDP-4500, GlobalProtect) |
| Internal-Jumphost | Ubuntu 22.04 LTS | server | internal |
| NetworkDB | PostgreSQL 14.11 | database | local-only |

*Registered via `env_write` in a prior session. Retrieved at session start via `env_read`.*

---

**Claude:** *(calls `env_list`)* Which environment are we working on today? I have these on record: **production-edge**, **staging**. Or give me a new name to create one.

**Engineer:** Production-edge.

**Claude:** *(calls `env_read("production-edge")`)* I have your environment on record:

- **VPN-GW01** — Palo Alto PA-3200, PAN-OS 11.1.0 (internet-exposed, GlobalProtect on 443/UDP-4500)
- **Internal-Jumphost** — Ubuntu 22.04 LTS, internal
- **NetworkDB** — PostgreSQL 14.11, local only

Still current?

**Engineer:** Yes. I need to look at CVE-2024-3400 — our scanner flagged the Palo Alto gateway.

**Claude:** *(calls `intel_lookup(["CVE-2024-3400"])` immediately)*

Got the data. Here's what the public record says:

> **CVE-2024-3400** — OS command injection in Palo Alto Networks PAN-OS via the GlobalProtect
> feature. An unauthenticated attacker can send a crafted HTTP request with a malformed SESSID
> cookie to `/ssl-vpn/hipreport.esp`, which causes arbitrary file creation that leads to OS
> command injection with root privileges. Device telemetry does not need to be enabled.
>
> - **What an attacker can achieve:** Remote code execution — pre-auth, runs as root
> - **Attack vector:** Network-accessible, no privileges or user interaction required (CVSS AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
> - **CVSS base:** 10.0 · **EPSS:** ~0.97 (actively exploited) · **KEV listed:** Yes *(added 2024-04-12)*
>
> Active exploitation observed in Operation MidnightEclipse. Affects PAN-OS 10.2, 11.0, 11.1
> with GlobalProtect gateway or portal configured.
>
> Vendor advisory: PAN-SA-2024-0006

Does that match your understanding?

**Engineer:** Yes — that's our gateway. GlobalProtect is enabled, port 443 is open from the internet.

**Claude:** Two questions:

1. Is the management interface (`HTTPS/4443`) separate from the GlobalProtect endpoint, or on the same IP?
2. Any mitigations in place? (Threat Prevention Content Update ID 95187/95189, version upgrade, network ACL blocking unknown sources)

**Engineer:** Management is on a separate internal IP — the internet-exposed interface is GlobalProtect only. We have no mitigations yet; we only found out this morning.

**Claude:** *(calls `score_evaluate`, `report_generate`)*

---

**🔴 CRITICAL — Remediate within 72 hours**

| Signal | Value | Effect |
|---|---|---|
| CVSS base | 10.0 | +4.0 pts |
| KEV listed | Yes — added 2024-04-12 | +1.5 pts (Critical escalation) |
| EPSS | ~0.97 (actively exploited) | +1.0 pts |
| Reachability | `internet_exposed` | +2.5 pts |
| Utility | `rce` (pre-auth, root) | +0.5 pts |
| Mitigations | None | — |

**Priority score: 9.5 / 10**

**Rationale:** CVE is on CISA KEV with an internet-exposed exploit path and maximum attacker utility (pre-auth RCE as root). EPSS reflects active exploitation in the wild. No compensating controls are in place.

**Required actions:**
- → Upgrade to PAN-OS 11.1.2-h3 or later (see PAN-SA-2024-0006) within 72 hours.
- → If upgrading is not possible within SLA: apply Threat Prevention Content Update IDs 95187/95189 with the relevant Threat Prevention profile enabled on GlobalProtect traffic as an immediate compensating control. Document as a `causal_claim`.

**Evidence gaps:**
- [ ] Confirm patched version number and change ticket after upgrading.

**Report saved:** `reports/FIND-VPN-001_20240413T083200.md` and `.json`

---

**Claude:** *(calls `env_write`)* Session saved. I've logged this assessment to your production-edge environment state.

---

## 2. Policy comparison — Same CVE, three policies

**CVE:** CVE-2024-3400 — Palo Alto Networks PAN-OS GlobalProtect OS Command Injection *(same as Example 1)*
**Scenario:** A security team evaluating whether to adopt BOD 26-04 or EPSS v5 wants to see how the same finding scores under all three policies.
**Entry point:** Claude Desktop or generic MCP client
**[Live conversation](https://claude.ai/share/3b80b1ee-0b96-45ad-9ea1-3dfa108b5ab1)** — Same CVE, three policy scores (no PDF)

*Environment: `production-edge` — same as Example 1. BOM unchanged.*

---

**Engineer:** Score CVE-2024-3400 under all three policies and give me a comparison. The environment is the same as the previous session — Palo Alto gateway, GlobalProtect internet-exposed, no mitigations, KEV listed.

**Claude:** *(calls `intel_lookup` → `score_evaluate` × 3: chml-v0.2, epss-v5, bod-26-04)*

Here's the same finding scored under all three policies:

| Signal | Value |
|---|---|
| KEV listed | Yes (2024-04-12) |
| EPSS | ~0.97 |
| CVSS base | 10.0 / AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| Reachability | `internet_exposed` |
| Automatable | Yes (AV:N + AC:L + PR:N + UI:N → derived from CVSS vector) |
| Technical impact | Total (Scope Changed + C:H + I:H) |

| | CHML v0.2 | EPSS v5 | BOD 26-04 |
|---|---|---|---|
| **Lane** | 🔴 Critical | 🔴 Critical | 🔴 Critical |
| **SLA** | 72 hours | 72 hours | 3 calendar days |
| **Primary driver** | KEV + internet + RCE | EPSS ≥ 0.7 + internet | All 4 signals |
| **Signals counted** | KEV ✅ · exposed ✅ · utility ✅ | EPSS ~0.97 ≥ 0.7 + exposed | 4 of 4 ✅ |
| **Additional action** | — | — | **Forensic triage required** |
| **Priority score** | 9.5 / 10 | — | — |

All three policies agree: Critical. The policies diverge on *why* — CHML emphasises the KEV + reachability combination; EPSS v5 is driven directly by the ~0.97 exploitation probability; BOD 26-04 counts the 4-signal combination and mandates forensic triage to determine if the gateway is already compromised.

**Which policy to use?**

- **CHML v0.2** — Best for general-purpose prioritisation where exploit utility context matters. Useful when you want to distinguish between a CVSS 10 DoS and a CVSS 10 pre-auth RCE.
- **EPSS v5** — Best for high-volume triage where you trust exploitation probability as the primary signal. Fewer judgment calls, faster triage.
- **BOD 26-04** — Required for US federal agencies. Useful for any team that wants a simple, defensible policy based on publicly available signals. The forensic triage requirement at Critical is distinctive.

---

## 3. BOM daily check — SaaS microservices stack

**Scenario:** A team registers their Python microservices stack and runs a weekly CVE check. Two CVEs surface the following week.
**Policy:** `chml-v0.2`
**Entry point:** Claude Desktop
**[Live conversation](https://claude.ai/share/d5297ad5-c145-4791-b81b-64120a1e7ede)** — Session A of multi-part BOM assessment

### Environment: production-api

| Component | Version | Type | Exposure |
|---|---|---|---|
| nginx | 1.25.3 | system | internet-exposed (reverse proxy, 443) |
| FastAPI | 0.108.0 | pypi | internet-exposed (public API, behind nginx) |
| python-multipart | 0.0.6 | pypi | internal (FastAPI dependency, form processing) |
| aiohttp | 3.9.1 | pypi | internal (async HTTP client, service-to-service) |
| PostgreSQL | 15.6 | system | internal |
| Redis | 7.2.4 | system | internal |
| Celery | 5.3.4 | pypi | internal (worker) |
| uvicorn | 0.27.0 | pypi | internal |

*Registered via `bom_update` in Session A below.*

---

### Session A — Initial BOM registration

**Engineer:** I want to register our production API stack so you can track CVEs against it. Here's what we're running:

```
nginx==1.25.3
fastapi==0.108.0
python-multipart==0.0.6
aiohttp==3.9.1
psycopg2==2.9.9
redis==5.0.1
celery==5.3.4
uvicorn==0.27.0
```

PostgreSQL 15.6 and Redis 7.2.4 are system packages, not pip-installed.

**Claude:** *(calls `env_write("production-api", ...)`, then `bom_update(environment_name="production-api", components=[...])`)*

Registered 8 components to `production-api`. I've noted:
- nginx, FastAPI, and the public API surface are internet-exposed
- aiohttp, PostgreSQL, Redis, and Celery are internal-only

Run a BOM check any time — or ask me "any new CVEs this week?" and I'll pull the last 7 days automatically. I'll compare your component list against NVD and flag anything new.

*(calls `env_write`)* Environment state saved.

---

*[ One week passes ]*

---

### Session B — Weekly check

**Engineer:** Morning check — any new CVEs for our stack this week?

**Claude:** *(calls `bom_check(environment_name="production-api", days_back=7)`)* Checked all 8 components against NVD. Here's what's new:

**aiohttp 3.9.1** — 1 CVE found

- `CVE-2024-23334` — CVSS 7.5 (High) — Directory traversal in `aiohttp.web.static()` when `follow_symlinks=True`. An attacker can request paths containing `..` sequences to read files outside the configured static root, including sensitive server-side files. *Published 2024-01-29. Fixed in aiohttp 3.9.2.*

**python-multipart 0.0.6** — 1 CVE found

- `CVE-2024-24762` — CVSS 7.5 (High) — ReDoS via malformed Content-Type header. When FastAPI parses form data, python-multipart uses a regex to parse the `Content-Type` header. A crafted header value can cause catastrophic backtracking, stalling the event loop for minutes or indefinitely. *Published 2024-02-05. Fixed in python-multipart 0.0.7 (FastAPI 0.109.0+).*

**nginx 1.25.3, PostgreSQL 15.6, Redis 7.2.4, Celery 5.3.4, uvicorn 0.27.0** — no new CVEs this week.

---

CVE-2024-23334 (aiohttp, CVSS 7.5) is worth looking at first — your stack uses aiohttp for internal HTTP calls, and the path traversal is directly exploitable if you serve any static assets via aiohttp. Want me to triage that one?

**Engineer:** Yes — but we don't use `follow_symlinks=True` anywhere in our aiohttp config.

**Claude:** *(calls `intel_lookup(["CVE-2024-23334"])`)*

> **CVE-2024-23334** — Directory traversal in aiohttp ≤ 3.9.1 via `aiohttp.web.static()` when
> `follow_symlinks=True`. When symlink following is enabled, there is no validation that the
> resolved path remains within the configured static root, allowing `../../` traversal to
> arbitrary files.
>
> - **What an attacker can achieve:** Arbitrary file read on the server — private keys, config files, `/etc/passwd`
> - **Attack vector:** Network (AV:N), low complexity (AC:L), no privileges (PR:N), no UI
> - **CVSS:** 7.5 · **EPSS:** ~0.08 · **KEV listed:** No

If `follow_symlinks=True` is not set anywhere in your codebase, you are **not affected by the default trigger path**. Do you use `aiohttp.web.static()` to serve any routes at all?

**Engineer:** We don't serve static files through aiohttp — it's purely used as an async HTTP client for calling internal services.

**Claude:** *(calls `score_evaluate`)*

---

**🟢 LOW — Not affected (confirm and close)**

You are using aiohttp as an HTTP *client*, not as a static file server. CVE-2024-23334 only affects `aiohttp.web.static()` server-side routes with `follow_symlinks=True`. Your usage pattern does not expose the vulnerable code path.

**Recommended action:** Upgrade to aiohttp 3.9.2 anyway as a belt-and-suspenders measure (the diff is minimal, no API changes). Confirm via change ticket and close the finding.

**CVE-2024-24762 (python-multipart ReDoS)** — still open. Do you want me to triage that next?

**Engineer:** Yes.

**Claude:** *(calls `score_evaluate`)*

---

**🟡 MEDIUM — Remediate within 30 days**

The ReDoS requires a malformed `Content-Type` header on a route that processes form data (`application/x-www-form-urlencoded` or `multipart/form-data`). Do any of your public API endpoints accept form data, or do they accept JSON only?

**Engineer:** Our public endpoints are all JSON. We have one internal admin endpoint at `/admin/upload` that accepts `multipart/form-data`, but it's behind our internal VPN — not reachable from the internet.

**Claude:** The `/admin/upload` endpoint is on the internal-only surface. The ReDoS is exploitable only by someone who can reach that endpoint. Given internal-only exposure, this drops from Medium to Low in effective risk.

**Recommended action:** Upgrade to FastAPI 0.109.0+ (which pulls in python-multipart 0.0.7) during your next release sprint. No emergency patch required.

*(calls `report_generate`, `env_write`)* Reports saved for both findings.

---

## 4. IaC environment assessment — PyCharm + Terraform

**Scenario:** A platform engineer opens a Terraform repository in PyCharm with the Claude Code extension. The `project_scan` tool auto-detects the AWS infrastructure and pre-seeds the session.
**Policy:** `chml-v0.2`
**Entry point:** PyCharm / JetBrains Claude Code extension
**[Live conversation](https://claude.ai/share/ee8ac65b-f46e-4e92-a068-7a7960d0a7cf)** — SaaS microservices BOM daily check continued

### Environment: platform-eks-prod

*BOM auto-discovered by `project_scan` — 15 Terraform components. See `project_scan` output in
the transcript below. Registered to `platform-eks-prod` via `bom_update` during Session A.*

---

**Engineer:** *(types in Claude Code pane)* Scan this project for vulnerabilities.

**Claude:** *(calls `project_scan(".")` — Step 0 of the PyCharm workflow)*

Scanned your Terraform project. Here's what I found:

```
project_type: ["terraform"]
cloud_provider_hint: "aws"
bom (15 entries):
  - hashicorp/aws                          v5.52.0    (terraform_provider)
  - hashicorp/kubernetes                   v2.30.0    (terraform_provider)
  - terraform-aws-modules/vpc/aws          v5.9.0     (terraform_module)
  - terraform-aws-modules/eks/aws          v20.11.0   (terraform_module)
  - terraform-aws-modules/rds/aws          v6.6.0     (terraform_module)
  - terraform-aws-modules/security-group   v5.1.0     (terraform_module)
  [... 9 more ...]
environment_hints: { project_type: "iac", cloud_provider_hint: "aws" }
```

This looks like an AWS environment with an EKS cluster and RDS database. Want me to:
1. Register these as your BOM and check for new CVEs?
2. Or do you have a specific CVE you'd like to assess against this infrastructure?

**Engineer:** Check for CVEs. Call the environment `platform-eks-prod`.

**Claude:** *(calls `env_write("platform-eks-prod", ...)`, then `bom_update`, then `bom_check`)*

New findings this week:

**terraform-aws-modules/eks/aws v20.11.0** — configuration advisory

The EKS module at v20.11.0 generates node group launch templates that do not enforce IMDSv2 (`http_tokens = "required"`). This is a well-documented AWS security baseline gap — exposed nodes are vulnerable to SSRF-based metadata credential theft (the technique used in the 2019 Capital One breach and documented in numerous post-incident reports).

This is not a CVE, but a misconfiguration with a clear exploit path: SSRF in any pod → IMDSv2 fallback to v1 → metadata endpoint → IAM credentials → lateral movement within the AWS account.

**hashicorp/aws v5.52.0, hashicorp/kubernetes v2.30.0** — no CVEs this week.

---

Would you like me to triage the IMDSv2 gap as a formal finding?

**Engineer:** Yes — treat it as a finding. The EKS worker nodes are in a private subnet but can reach the internet via NAT.

**Claude:** *(calls `score_evaluate`)*

---

**🟠 HIGH — Remediate within 7 days**

IMDSv2 not enforced on EKS node groups. Worker nodes are reachable from internal workloads (which may themselves have SSRF bugs). The exploit path is: SSRF in any workload → IMDSv2 v1 fallback → metadata endpoint → IAM credentials → privilege escalation within AWS account.

**Rationale:** Not KEV-listed, but the exploit technique is well-documented and widely tooled (Pacu, cloudgoat, IMDSv1 to credential theft is a known kill chain). Internal exposure is constrained but not isolated — a compromised pod in the cluster can reach the metadata endpoint.

**Fix:** Two-line Terraform change in your EKS node group module block:
```hcl
metadata_options = {
  http_tokens = "required"
}
```

---

## 5. Nuanced case — KEV alone ≠ Critical

**CVE:** CVE-2024-1086 — Linux kernel `nf_tables` use-after-free local privilege escalation
**Scenario:** An engineer triages a KEV-listed kernel CVE on an internal build server. The example shows how reachability gates scoring, and how BOD 26-04 and CHML diverge on local-access findings.
**Policy:** All three (comparison)
**Entry point:** Claude Desktop
**Live conversation** — Demonstrates KEV→Critical assumption limitations (local access scope)

### Environment: build-infra

| Component | Version | Type | Exposure |
|---|---|---|---|
| Build-Server-01 (Ubuntu 22.04 LTS) | kernel 5.15.140 | server | internal-only |
| GitHub Actions self-hosted runner | 2.315.0 | ci-runner | internal (CI jobs only) |

*`nftables` loaded (Ubuntu default); no explicit restrictions on kernel module access. Single CI pipeline user, no interactive logins from untrusted parties.*

---

**Engineer:** I need to look at CVE-2024-1086. It's KEV-listed but I think we're okay — it requires local access.

**Claude:** *(calls `intel_lookup(["CVE-2024-1086"])`)*

> **CVE-2024-1086** — Use-after-free in the Linux kernel's netfilter `nf_tables` component
> (`nft_verdict_init()`). A local unprivileged user can trigger a double-free condition to
> overwrite kernel memory and escalate to root. Public PoC published by Notselwyn.
>
> - **What an attacker can achieve:** Local privilege escalation to root
> - **Attack vector:** Local (AV:L) — requires an existing shell on the target
> - **CVSS:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) · **EPSS:** ~0.04 (low — exploitation requires pre-existing local access)
> - **KEV listed:** Yes *(added 2024-03-26)* — targeted exploitation observed; exploitation resurfaced in ransomware campaigns in late 2025
> - **Affected:** Linux kernel v5.14–6.6.14 · **Fixed:** v5.15.149+, v6.1.76+, v6.6.15+

Your kernel (5.15.140) is in the vulnerable range. The fix is available in 5.15.149+. This confirms your read: local access is required.

Two questions:

1. Is this server multi-tenant or shared-user (e.g., CI runners with code from untrusted contributors)?
2. Does the CI pipeline run untrusted code, or only your own repo's build jobs?

**Engineer:** It's a dedicated internal build server. Only our CI pipeline user runs jobs on it — all from our own private repos. No external contributors, no interactive logins from untrusted parties.

**Claude:** *(calls `score_evaluate` × 3)*

| | CHML v0.2 | EPSS v5 | BOD 26-04 |
|---|---|---|---|
| **Lane** | 🟡 Medium | 🟡 Medium | 🟡 Medium |
| **SLA** | Patch train | 30 days | 60 days |
| **Reasoning** | KEV escalates, but AV:L + internal → Medium | EPSS 0.04 < 0.1 threshold → Low/Medium boundary; KEV bumps to Medium | internet_exposed: No · automatable: No · KEV: Yes · total_impact: Yes → 2 of 4 signals → Medium (60-day band) |

**Why not Critical despite KEV listing?**

- **CHML:** KEV status alone cannot produce Critical. The rule requires KEV *plus* internet exposure *plus* high utility. A KEV-listed local privesc on a dedicated internal server with a single trusted CI user cannot reach Critical — an attacker would need to already be on the box.
- **EPSS v5:** EPSS is ~0.04. The probability of exploitation in the next 30 days is low for this specific asset because the attack surface is narrow (dedicated server, no interactive users, no untrusted code execution). EPSS correctly reflects the difference between "widely exploitable in the wild" and "technically KEV but constrained by access model".
- **BOD 26-04:** 2 signals active (KEV + total_impact). Not internet-exposed, not automatable (requires local shell first). 60-day remediation band is the correct outcome.

**Engineer:** That makes sense. So we can patch it in the next kernel update cycle?

**Claude:** Yes. Schedule it for your next planned kernel maintenance window — upgrade to 5.15.149 or later (Ubuntu 22.04 HWE kernel provides this). If you want to close the evidence gap now: confirm `nft_verdict_init` is not accessible to unprivileged users (non-default seccomp or AppArmor profiles may already restrict it).

*(calls `report_generate`, `env_write`)*

---

**What this example shows:** CISA KEV listing is a strong signal, but it is not automatically Critical in all scoring policies. Context — specifically who can reach the vulnerable surface — determines the lane. RubricAI makes that reasoning explicit and auditable rather than leaving it to gut feel.

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
