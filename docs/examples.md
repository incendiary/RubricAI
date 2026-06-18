# RubricAI — Example Sessions

Full conversation transcripts showing how RubricAI works in practice. All CVEs are real
and topical as of June 2026. Each example uses different entry points, policies, or
workflows to illustrate different capabilities.

---

## Contents

1. [Quick start — triage a single CVE (Check Point VPN, CHML)](#1-quick-start--triage-a-single-cve)
2. [Policy comparison — same CVE, three policies](#2-policy-comparison--same-cve-three-policies)
3. [BOM daily check — SaaS microservices stack](#3-bom-daily-check--saas-microservices-stack)
4. [IaC environment assessment — PyCharm + Terraform](#4-iac-environment-assessment--pycharm--terraform)
5. [Nuanced case — KEV alone ≠ Critical (Linux kernel privesc)](#5-nuanced-case--kev-alone--critical)

---

## 1. Quick start — Triage a single CVE

**CVE:** CVE-2026-24019 — Check Point Quantum VPN Gateway RCE
**Scenario:** An engineer receives a scanner alert for their internet-facing VPN gateway.
**Policy:** `chml-v0.2` (default)
**Entry point:** Claude Desktop

---

**Claude:** *(calls `env_list`)* Which environment are we working on today? I have these on record: **production-edge**, **staging**. Or give me a new name to create one.

**Engineer:** Production-edge.

**Claude:** *(calls `env_read("production-edge")`)* I have your environment on record:

- **VPN-GW01** — Check Point Quantum R81.20 (internet-exposed, 443/UDP-4500)
- **Internal-Jumphost** — internal, not exposed
- **NetworkDB** — local only

Still current?

**Engineer:** Yes. I need to look at CVE-2026-24019 — our scanner flagged the Check Point gateway.

**Claude:** *(calls `intel_lookup(["CVE-2026-24019"])` immediately)*

Got the data. Here's what the public record says:

> **CVE-2026-24019** — Unauthenticated remote code execution in Check Point Quantum VPN Gateway
> R81.20 and earlier. A specially crafted packet to the IKEv2 listener allows an attacker to
> execute arbitrary code as root before authentication completes.
>
> - **What an attacker can achieve:** Remote code execution — pre-auth, runs as root
> - **Attack vector:** Network-accessible, no privileges or user interaction required (CVSS AV:N/AC:L/PR:N/UI:N)
> - **CVSS base:** 10.0 · **EPSS:** 0.91 (94th percentile) · **KEV listed:** Yes *(added 2026-06-02)*
>
> CISA KEV due date: **2026-06-16**. Active exploitation observed by Qilin ransomware affiliate.

Does that match your understanding?

**Engineer:** Yes — that's our gateway. It's VPN, port 443 and UDP 4500 are open from the internet.

**Claude:** Two questions:

1. Is the management interface (`8443`) separate from the VPN endpoint, or on the same IP?
2. Any mitigations in place? (IPS signature, version patch, network ACL blocking unknown sources)

**Engineer:** Management is on a separate internal IP — the internet-exposed interface is the VPN endpoint only. We have no mitigations yet; we only found out this morning.

**Claude:** *(calls `score_evaluate`, `report_generate`)*

---

**🔴 CRITICAL — Remediate within 72 hours**

| Signal | Value | Effect |
|---|---|---|
| CVSS base | 10.0 | +4.0 pts |
| KEV listed | Yes — CISA due 2026-06-16 | +1.5 pts (Critical escalation) |
| EPSS | 0.91 (94th pct) | +1.0 pts |
| Reachability | `internet_exposed` | +2.5 pts |
| Utility | `rce` (pre-auth, root) | +0.5 pts |
| Mitigations | None | — |

**Priority score: 9.5 / 10**

**Rationale:** CVE is on CISA KEV with an internet-exposed exploit path and maximum attacker utility (pre-auth RCE as root). EPSS confirms active exploitation. No compensating controls are in place.

**Required actions:**
- → Patch to R81.20 Jumbo Hotfix Take 75 or later (Check Point advisory SK183781) within 72 hours.
- → If patching is not possible within SLA: block all inbound traffic to the VPN gateway except from known-good source IPs via upstream ACL. Document as a compensating control with a `causal_claim`.

**Evidence gaps:**
- [ ] Confirm patched version number and change ticket after patching.

**Report saved:** `reports/FIND-VPN-001_20260618T083200.md` and `.json`

---

**Claude:** *(calls `env_write`)* Session saved. I've logged this assessment to your production-edge environment state.

---

## 2. Policy comparison — Same CVE, three policies

**CVE:** CVE-2026-24019 — Check Point Quantum VPN Gateway RCE *(same as Example 1)*
**Scenario:** A security team evaluating whether to adopt BOD 26-04 or EPSS v5 wants to see how the same finding scores under all three policies.
**Entry point:** Claude Desktop or generic MCP client

---

**Engineer:** Score CVE-2026-24019 under all three policies and give me a comparison. The environment is the same as the previous session — VPN gateway, internet-exposed, no mitigations, KEV listed.

**Claude:** *(calls `intel_lookup` → `score_evaluate` × 3: chml-v0.2, epss-v5, bod-26-04)*

Here's the same finding scored under all three policies:

| Signal | Value |
|---|---|
| KEV listed | Yes (2026-06-02) |
| EPSS | 0.91 |
| CVSS base | 10.0 / AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| Reachability | `internet_exposed` |
| Automatable | Yes (AV:N + AC:L + PR:N + UI:N → derived) |
| Technical impact | Total (Scope Changed + C:H + I:H) |

| | CHML v0.2 | EPSS v5 | BOD 26-04 |
|---|---|---|---|
| **Lane** | 🔴 Critical | 🔴 Critical | 🔴 Critical |
| **SLA** | 72 hours | 72 hours | 3 calendar days |
| **Primary driver** | KEV + internet + RCE | EPSS ≥ 0.7 + internet | All 4 signals |
| **Signals counted** | KEV ✅ · exposed ✅ · utility ✅ | EPSS 0.91 ≥ 0.7 + exposed | 4 of 4 ✅ |
| **Additional action** | — | — | **Forensic triage required** |
| **Priority score** | 9.5 / 10 | — | — |

All three policies agree: Critical. The policies diverge on *why* — CHML emphasizes the KEV + reachability combination; EPSS v5 is driven directly by the 0.91 exploitation probability; BOD 26-04 counts the 4-signal combination and mandates forensic triage to determine if the gateway is already compromised.

**Which policy to use?**

- **CHML v0.2** — Best for general-purpose prioritisation where exploit utility context matters. Useful when you want to distinguish between a CVSS 10 DoS and a CVSS 10 pre-auth RCE.
- **EPSS v5** — Best for high-volume triage where you trust exploitation probability as the primary signal. Fewer judgment calls, faster triage.
- **BOD 26-04** — Required for US federal agencies. Useful for any team that wants a simple, defensible policy based on publicly available signals. The forensic triage requirement at Critical is distinctive.

---

## 3. BOM daily check — SaaS microservices stack

**Scenario:** A team registers their Python microservices stack and runs a weekly CVE check. A new critical CVE surfaced on June 10, 2026.
**Policy:** `chml-v0.2`
**Entry point:** Claude Desktop

---

**Engineer:** Morning check — any new CVEs for our stack this week?

**Claude:** *(calls `bom_check(environment_name="production-api", days_back=7)`)* Checked all 8 components against NVD. Here's what's new in the last 7 days:

**fastapi 0.109.0** — 1 CVE found

- `CVE-2026-31200` — CVSS 8.1 (High) — Request smuggling via malformed chunked transfer encoding. Affects FastAPI when deployed behind an nginx reverse proxy with `proxy_buffering off`. *Published 2026-06-10.*

**cryptography 42.0.3** — 1 CVE found

- `CVE-2026-28923` — CVSS 7.5 (High) — RSA key decryption timing oracle. Requires attacker to observe decryption timing. *Published 2026-06-08.*

**requests 2.31.0, postgresql-15, redis-7, celery 5.3.4, pydantic 2.5.0, uvicorn 0.27.0** — no new CVEs this week.

---

CVE-2026-31200 (FastAPI, CVSS 8.1) is the most urgent. Your stack has nginx in front of FastAPI — that's the exact combination the advisory calls out. Want me to triage that one now? I have FastAPI 0.109.0 pre-filled from your BOM.

**Engineer:** Yes, please triage it.

**Claude:** *(calls `intel_lookup(["CVE-2026-31200"])`)*

> **CVE-2026-31200** — Request smuggling in FastAPI/Starlette when deployed behind nginx with
> `proxy_buffering off`. An attacker can poison the request queue and inject crafted requests
> to other users' sessions.
>
> - **What an attacker can achieve:** Session hijacking / data access (cross-user request injection)
> - **Attack vector:** Network (AV:N), low complexity (AC:L), no privileges (PR:N), no UI
> - **CVSS:** 8.1 · **EPSS:** 0.62 (high) · **KEV listed:** No

Two questions:

1. Is your FastAPI service internet-exposed, or only internal?
2. Is `proxy_buffering off` set in your nginx config?

**Engineer:** It's internet-exposed — that's our public API. I just checked: `proxy_buffering off` is set in our nginx config for the `/stream` endpoints. Regular endpoints use default buffering.

**Claude:** *(calls `score_evaluate`, `report_generate`)*

---

**🟠 HIGH — Remediate within 7 days**

The `/stream` endpoints are the vulnerable path, and they're internet-exposed. However, the attack is limited to request smuggling — no code execution, no persistence. EPSS is high (0.62) but KEV is not listed. This is High rather than Critical because the exploit chain requires the specific `proxy_buffering off` configuration to be active on the request path.

**Recommended actions:**
- → Upgrade FastAPI to 0.112.0+ (fix is in Starlette 0.37.2, bundled in FastAPI 0.112.0).
- → If upgrading is blocked this sprint: remove `proxy_buffering off` from `/stream` endpoints temporarily (adds 5–10ms latency to streaming responses — acceptable for most use cases).
- → Confirm via change ticket.

---

## 4. IaC environment assessment — PyCharm + Terraform

**Scenario:** A platform engineer opens a Terraform repository in PyCharm with the Claude Code extension. The `project_scan` tool auto-detects the AWS infrastructure and pre-seeds the session.
**Policy:** `chml-v0.2`
**Entry point:** PyCharm / JetBrains Claude Code extension

---

**Engineer:** *(types in Claude Code pane)* Scan this project for vulnerabilities.

**Claude:** *(calls `project_scan(".")` — Step 0 of the PyCharm workflow)*

Scanned your Terraform project. Here's what I found:

```
project_type: ["terraform"]
cloud_provider_hint: "aws"
bom (15 entries):
  - hashicorp/aws          v5.52.0   (terraform_provider)
  - hashicorp/kubernetes   v2.30.0   (terraform_provider)
  - terraform-aws-modules/vpc/aws          v5.9.0    (terraform_module)
  - terraform-aws-modules/eks/aws          v20.11.0  (terraform_module)
  - terraform-aws-modules/rds/aws          v6.6.0    (terraform_module)
  - terraform-aws-modules/security-group   v5.1.0    (terraform_module)
  [... 9 more ...]
environment_hints: { project_type: "iac", cloud_provider_hint: "aws" }
```

This looks like an AWS environment with an EKS cluster and RDS database. Want me to:
1. Register these as your BOM and check for new CVEs?
2. Or do you have a specific CVE you'd like to assess against this infrastructure?

**Engineer:** Check for CVEs. Call the environment `platform-eks-prod`.

**Claude:** *(calls `env_read("platform-eks-prod")`, then `bom_update`, then `bom_check`)*

New CVEs this week:

**terraform-aws-modules/eks/aws v20.11.0** — advisory found

The EKS module at v20.11.0 generates node group launch templates that do not enforce IMDSv2 (`http_tokens = "required"`). This is not a CVE but a configuration drift from AWS security baseline — exposed nodes are vulnerable to SSRF-based metadata credential theft.

Relevant to: CVE-2021-25741 class of attacks still active in cloud environments.

Recommend pinning `http_tokens = "required"` in your node group configuration. This is a 2-line Terraform change.

**hashicorp/aws v5.52.0, hashicorp/kubernetes v2.30.0** — no CVEs this week.

---

Would you like me to triage the IMDSv2 gap as a formal finding? I can score it under CHML — it's not a traditional CVE but has a clear exploit path (SSRF → metadata → IAM credential theft → lateral movement).

**Engineer:** Yes — treat it as a finding. The EKS worker nodes are in a private subnet but can reach the internet via NAT.

**Claude:** *(calls `score_evaluate`)*

---

**🟠 HIGH — Remediate within 7 days**

IMDSv2 not enforced on EKS node groups. Worker nodes are reachable from internal services (which may themselves have SSRF bugs). The exploit path is: SSRF in any workload → metadata endpoint → IAM credentials → privilege escalation within AWS account.

**Rationale:** Not KEV-listed, but exploit technique is well-documented and tooled (Pacu, cloudgoat). Internal exposure is constrained but not isolated — a compromised pod in the cluster can reach the metadata endpoint.

**Fix:** Two-line Terraform change in your EKS node group module block:
```hcl
metadata_options = {
  http_tokens = "required"
}
```

---

## 5. Nuanced case — KEV alone ≠ Critical

**CVE:** CVE-2026-1038 — Linux kernel `copy_to_user` privilege escalation
**Scenario:** An engineer triages a KEV-listed kernel CVE on an internal server. The example shows how reachability gates scoring, and how BOD 26-04 and CHML diverge on local-access findings.
**Policy:** All three (comparison)
**Entry point:** Claude Desktop

---

**Engineer:** I need to look at CVE-2026-1038. It's KEV-listed but I think we're okay — it requires local access.

**Claude:** *(calls `intel_lookup(["CVE-2026-1038"])`)*

> **CVE-2026-1038** — Linux kernel 6.6.x–6.8.x: `copy_to_user` bounds check bypass via
> malformed `io_uring` request. Allows a local unprivileged user to overwrite kernel memory
> and escalate to root.
>
> - **What an attacker can achieve:** Local privilege escalation to root
> - **Attack vector:** Local (AV:L) — requires an existing shell on the target
> - **CVSS:** 7.8 · **EPSS:** 0.04 (low — exploitation requires pre-existing local access)
> - **KEV listed:** Yes *(added 2026-05-28)* — targeted exploitation observed on shared hosting environments

This confirms your read: local access is required. Two questions:

1. Is this server multi-tenant or shared-user (e.g., CI runners, shared build boxes, developer sandbox)?
2. Any `io_uring` disabled or users restricted to unprivileged containers?

**Engineer:** It's a dedicated internal build server. Only our CI pipeline user runs jobs on it — no external users, no interactive logins from untrusted parties. `io_uring` isn't explicitly disabled.

**Claude:** *(calls `score_evaluate` × 3)*

| | CHML v0.2 | EPSS v5 | BOD 26-04 |
|---|---|---|---|
| **Lane** | 🟡 Medium | 🟡 Medium | 🟡 Medium |
| **SLA** | Patch train | 30 days | 60 days |
| **Reasoning** | KEV escalates, but AV:L + internal → Medium | EPSS 0.04 < 0.1 threshold → Low/Medium | internet_exposed: No; automatable: No; KEV: Yes; total_impact: Yes → 2 of 4 signals → Medium |

**Why not Critical despite KEV listing?**

- **CHML:** KEV status alone cannot produce Critical. The rule requires KEV *plus* internet exposure *plus* high utility. A KEV-listed local privesc on a dedicated internal server with a single CI user cannot reach Critical because the attacker would already need internal access first.
- **EPSS v5:** EPSS is 0.04 — below the 0.1 Medium threshold. The probability of exploitation in the next 30 days is low because the attack surface is narrow (dedicated server, no interactive users). EPSS v5's better calibration picks this up correctly.
- **BOD 26-04:** 2 signals active (KEV + total_impact). Not internet-exposed, not automatable (requires local shell first). 60-day remediation band is appropriate.

**Engineer:** That makes sense. So we can patch it in the next kernel update cycle?

**Claude:** Yes. Schedule it for your next planned kernel maintenance window — 30–60 days is the right envelope given the access constraints. If you add a dedicated CI user with `--no-io_uring` restrictions or upgrade the kernel now, note it as a compensating control to close the evidence gap.

*(calls `report_generate`, `env_write`)*

---

**What this example shows:** CISA KEV listing is a strong signal, but it is not automatically Critical in all scoring policies. Context determines the lane — and RubricAI makes that reasoning explicit and auditable rather than leaving it to gut feel.

---

> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
