# RubricAI Roadmap

This file tracks delivered work and the open backlog. Completed items retain their
version tags for historical context. Open items are written so they can be picked up
independently — each names the **file(s)** to change, **what** to do, and **how to
verify** the change.

## Delivered

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
| — | ✅ Done | **v1.7.0** — GitHub Advisory Database as primary intel source with NVD fallback; auto-incrementing HTTP timeouts (5s, 10s, 30s); NVD auth fallback on 503; examples updated with sharing links and PDF evidence reports |

## Open work

All open and planned items are gathered here for implementation. Each task is written so it can be picked up independently: it names the **file(s)** to change, **what** to do, and **how to verify** the change. Pick the highest-priority unblocked item, make the change on a feature branch (the repo blocks direct commits to `main`), run the verify step, and open a PR. Note: some development machines have **no Docker** — any step that needs a container build/run must be verified on a system that does (the code change itself can still be made without Docker).

| ID | Priority | Status | Task |
|----|----------|--------|------|
| OPEN-1 | High | ✅ Done | **Bug — `/health` returned 401 when API-key auth was enabled; auth tests didn't exercise the real code.** Fixed in PR [#106](https://github.com/incendiary/RubricAI/pull/106): `APIKeyAuthMiddleware` extracted from `src/main.py` into `src/rubricai/auth.py` (with a `PUBLIC_PATHS` exemption for `/health`); `src/main.py` now imports and wires the real middleware; `tests/test_auth.py` rewritten to import the real class and assert `/health` returns 200 with no token while protected routes still 401 on missing/wrong tokens and 200 on the correct Bearer key. **Remaining (handed to implementing agents, needs Docker):** add a `HEALTHCHECK` to `Dockerfile` and/or a `healthcheck:` to `docker-compose.yml` doing an HTTP GET on `/health`, and verify on a Docker-capable machine. |
| OPEN-2 | High | ✅ Done | **Bug — NVD search cache key omitted `vendor`, so results could be served for the wrong vendor.** Fixed in PR [#106](https://github.com/incendiary/RubricAI/pull/106): `search()` in `src/rubricai/fetchers/nvd.py` now includes a normalised vendor segment in the cache key (`f"{keyword.lower()}:{(vendor or '').lower()}:{days_back}:{max_results}"`), and `tests/test_fetchers.py` has a regression test proving two searches with the same keyword but different vendors do not reuse each other's cached results. |
| OPEN-3 | Medium | ⬜ Open | **Claude Desktop config preflight — don't write a broken path.** **Where:** `scripts/install_claude_config.py` writes the `.venv/bin/rubricai` path (Windows: `.venv\Scripts\rubricai.exe`) into `claude_desktop_config.json` even on a fresh clone where that executable doesn't exist yet, producing a config that silently fails. **Do:** before writing, check whether the entry-point file exists; if it doesn't, print clear setup steps (`python3 -m venv .venv`, activate it, `pip install -e ".[dev]"`) and refuse to write unless an explicit override flag (e.g. `--force`) is passed. Keep the existing dry-run/`--write` behaviour. **Verify:** add a test in `tests/test_install_claude_config.py`: with a non-existent executable and no override, the script exits non-zero (or warns) and does **not** modify the config; with the override flag, it writes as before. |
| OPEN-4 | Medium | ⬜ Open | **Portable secrets baseline (tooling cleanup, not a secret incident).** **Where:** `.secrets.baseline` records an absolute local filesystem path and can flag intentional test fixtures (e.g. the `secret-key` string in `tests/test_install_claude_config.py`), so it produces noisy, machine-specific diffs between developers. **Do:** pick one approach and document it: (a) add an inline allowlist / `# pragma: allowlist secret` marker to the intentional fixture lines, and/or (b) document the regenerate-and-review workflow in `README.md` (or a new `CONTRIBUTING.md`) so the baseline stays stable across machines and personal path churn doesn't create diffs. **Verify:** `python -m detect_secrets scan --baseline .secrets.baseline` reports no new unaudited secrets, and `pytest tests/test_secrets.py` passes. |
| OPEN-5 | Medium | ⬜ Open | **Feature — VS Code / Copilot Chat MCP client support.** **Where:** new docs in `README.md`, optionally a new template in `prompts/templates/` and a `--target vscode` branch in `scripts/render_prompt.py`. **Do:** add first-class setup instructions for using RubricAI as an MCP server from VS Code / Copilot Chat. Cover both `stdio` (local) and `sse` (local Docker/remote) transports; show the exact VS Code MCP server configuration shape (command, args, cwd, env); explain where to paste or load the rendered system prompt; and, only if VS Code needs client-specific wording, add a `vscode.md.j2` template plus a `--target vscode` option in `render_prompt.py` (add `"vscode"` to the `TARGETS` list). **Verify:** on a fresh VS Code workspace, the configured client starts RubricAI, can call `env_list`, run a simple `intel_lookup`, and write reports/state to predictable local folders. *(Docker/SSE path must be verified on a machine with Docker.)* |
| #104 | Low | ⬜ Open | **Feature — threat-intel enrichment.** **Where:** intel fetchers (`src/rubricai/fetchers/`) and the intel schema (`src/rubricai/schemas/intel.py`). **Do:** add optional `threat_regions` and `threat_industries` context sourced from free/open feeds, each annotated with a confidence level and a source/provenance reference so downstream reviewers can judge the signal. Keep it optional — absence of this data must not change existing scoring. **Verify:** unit tests for the new fetcher/parsing with mocked feed responses; confirm scoring output is unchanged when the enrichment is absent. Tracked as GitHub issue [#104](https://github.com/incendiary/RubricAI/issues/104). |
| #105 | Low | ⬜ Open | **Feature — environment lifecycle / reset tools.** **Where:** environment tools in `src/rubricai/tools/environment.py`. **Do:** add MCP tools for independent and tandem operations: (a) clear state for a single named environment (leave reports), (b) clear state for all environments (leave reports), (c) clear all reports regardless of environment, (d) perform a full local reset of all stored data (state + reports + PDFs). All operations are destructive and require explicit `confirm=true` argument; support dry-run mode that previews what would be deleted. **Verify:** tests in `tests/test_environment.py` proving dry-run deletes nothing, `confirm=true` deletes only the specified paths, and operations never escape configured state/report directories (reuse existing path-validation helpers). Tracked as GitHub issue [#105](https://github.com/incendiary/RubricAI/issues/105). |
| OPEN-6 | Medium | ✅ Done | **Release / tag hygiene — the documented clone command points at stale code.** **Where:** the **Setup** section of `README.md` says `git clone --branch v1.6.0 …`, but `git describe --tags` reports HEAD as `v1.6.0-10-g…` — i.e. ~10 commits ahead of the `v1.6.0` tag. A user who follows the docs gets code missing the latest fixes. **Do:** once the open bug fixes above are merged, tag a new release (e.g. `v1.6.1`) and update the README clone command and the "latest release" reference to that tag; alternatively change the doc to clone the default branch. Keep the pinned-tag example and the newest tag in sync going forward. **Verify:** a fresh `git clone --branch <tag>` followed by `git describe --tags` returns exactly `<tag>` with no `-N-g…` suffix, and the README clone command names the newest tag. |
| OPEN-7 | Medium | ⬜ Open | **Linter version pin drift between pre-commit and CI** *(replaces an earlier note that wrongly claimed `.github/workflows/ci.yml` was missing — it exists).* **Where:** `.pre-commit-config.yaml` pins ruff at `v0.11.9`, while `.github/workflows/ci.yml` installs ruff `0.15.15` (the local venv here has `0.15.17`). `black` (`26.5.1`) and `isort` (`8.0.1`) already match across both; only ruff drifts. Different ruff versions can pass locally / in pre-commit but fail the CI lint job (or vice-versa). **Do:** align the ruff version in `.pre-commit-config.yaml` and `.github/workflows/ci.yml` to a single pinned version (ideally pin black/ruff/isort identically in both files). **Verify:** `pre-commit run --all-files` and the CI `lint` job run the same ruff version, and `ruff check .` passes under it. |
| OPEN-8 | Low | ⬜ Open | **Python version policy is inconsistent.** **Where:** `pyproject.toml` declares `requires-python = ">=3.11"`; `.github/workflows/ci.yml` tests only `3.11`; the `Dockerfile` uses `python:3.11-slim`; but the project is allowed on (and currently developed on) newer interpreters up to 3.14. So 3.12–3.14 are permitted yet untested. **Do:** choose one: (a) add a CI test matrix covering `3.11`, `3.12`, `3.13` (and `3.14` once green) via `strategy.matrix.python-version`; or (b) narrow `requires-python` to the range actually tested and state the supported version(s) in the README **Requirements** section. **Verify:** CI is green across every declared version, or `requires-python` and the README agree on the single supported version. |
| OPEN-9 | Low | ⬜ Open | **Document WeasyPrint native dependencies for local installs.** **Where:** README **Setup** section. **Why:** PDF export depends on WeasyPrint, which needs native libraries (pango, cairo, gdk-pixbuf). CI installs these via `apt-get` in `.github/workflows/ci.yml`, but the README does not mention them — so a fresh local `pip install` succeeds and only fails later, at runtime, when a PDF is generated. **Do:** add a short "PDF export prerequisites" note with install commands for macOS (`brew install pango gdk-pixbuf libffi`) and Debian/Ubuntu (reuse the apt package list already in `ci.yml`), and note that PDF export is optional — all other features work without these libs. **Verify:** on a clean machine, after following the README, `report_generate(..., formats=["pdf"])` produces a PDF with no `ImportError`/`OSError`. |
| OPEN-10 | Medium | ⬜ Open | **Proactively offer all three policy comparisons in scoring conversations.** **Where:** `prompts/templates/claude_system_prompt.md.j2` (system prompt for Claude Desktop / MCP clients). **Why:** `score_compare` tool exists and returns all three policies (CHML v0.2, EPSS v5, BOD 26-04) side-by-side, but is only called when user explicitly asks "compare policies" or "show all three". By default, Claude scores with a single policy. Users miss the opportunity to see policy differences (KEV vs. EPSS vs. BOD-26-04 rationale) unless they know to ask. **Do:** update the `score_evaluate` section of the system prompt to: after returning a score, proactively offer to run `score_compare` for policy comparison. Example phrasing: "Would you also like to see how this scores under EPSS v5 and BOD 26-04 for comparison?" Make the offer natural and contextual (not forced on every evaluation). **Verify:** in a Claude Desktop conversation, ask for a CVE score; Claude returns the score AND offers `score_compare`; user can accept the offer and see all three policies compared. |
| OPEN-11 | High | ⬜ Open | **Schema validation errors in `score_evaluate` — unclear error messages and field constraints.** **Where:** `src/rubricai/schemas/finding.py` and MCP tool error handling. **Issue:** When users call `score_evaluate` with findings, validation errors list "extra input" fields that seem valid (e.g. `component.vendor`, `entry_point.service`, `data_impact.affected_data_types`) without explaining what fields ARE allowed. Users must trial-and-error to discover the actual schema. Error messages unhelpful: "extra input (not in schema)" doesn't indicate which fields exist or their constraints. **Do:** (a) audit the Finding schema and document allowed fields per object (`component`, `entry_point`, `data_impact`, etc.) in a human-readable format; (b) improve validation error messages to show what fields ARE accepted (not just reject invalid ones); (c) provide example findings in docstrings or separate examples file showing valid structure. **Verify:** users can call `score_evaluate` with a well-formed finding on first try (without trial-and-error); error messages guide toward valid fields. |
| OPEN-12 | Medium | ⬜ Open | **CVE result caching for resilience during API outages.** **Where:** new `src/rubricai/cache/` module and `intel_lookup` tool. **Why:** NVD/EPSS APIs experience intermittent outages (e.g. 503 Service Unavailable). Currently, `intel_lookup` fails entirely when APIs are down. With caching, users can still score CVEs using cached intel while receiving a notification that data is stale. **Do:** (a) implement persistent CVE cache (JSON or simple MD file format) stored in `~/.local/share/rubricai/cache/cves/`; (b) structure cache as `{cve_id: {kev_status, epss, cvss, description, cached_at}}`; (c) modify `intel_lookup` to: check cache first (if data is < 7 days old), return cached result with banner `[CACHED - API unavailable]`; (d) on cache miss + API down, return empty/minimal result with warning; (e) keep cache indefinitely but flag age to user. **Verify:** simulate API outage (mock 503), call `intel_lookup` for previously-cached CVE, get cached result with warning banner; untouched CVE shows "no cache" warning. |
| OPEN-13 | Medium | ⬜ Open | **Independent API diagnostic tools — expose as MCP endpoints for agent-driven debugging.** **Where:** new `src/rubricai/tools/diagnostics.py` module and MCP tool definitions. **Why:** When APIs fail (like NVD 503 today), users manually run bash commands to diagnose. Agents (Claude, other LLMs) cannot independently investigate API issues. With MCP diagnostic tools, agents can troubleshoot and report health status automatically. **Do:** (a) create diagnostic functions in `src/rubricai/tools/diagnostics.py`: `check_nvd_api()`, `check_epss_api()`, `check_cisa_kev()`, `check_connectivity()`; (b) each returns: status (up/down/timeout), HTTP response code, latency (ms), error message, timestamp; (c) expose as MCP tools: `diagnose_apis` (runs all checks), `diagnose_nvd` (single API); (d) tools return structured JSON with health status, NOT raw bash output; (e) add caching (5-min TTL) so repeated calls don't hammer APIs. **Verify:** (1) call `diagnose_apis`, get structured {nvd: {status, code, latency}, epss: {...}, cisa: {...}}; (2) mock 503 response, tool correctly reports "down"; (3) agent can understand result without parsing logs. |
| OPEN-14 | Medium | ⬜ Open | **Report generation: offer to include evidence screenshots on supplementary PDF pages.** **Where:** `report_generate` MCP tool and PDF rendering pipeline (`src/rubricai/tools/report.py` + `src/rubricai/pdf/`). **Why:** Evidence items with file_path pointing to screenshot images are stored but not currently embedded in generated PDFs. Users must manually attach screenshots to reports or re-collect evidence. With screenshot embedding, PDF reports are self-contained and shareable without losing context (e.g., firewall rules, security group configs, WAF logs). **Do:** (a) before `report_generate` returns, inspect the evidence array for items with `file_path` pointing to images (PNG, JPG); (b) if images exist, ask the user: "I found X relevant evidence screenshots. Include them on supplementary pages in the PDF?" with a yes/no/review-list option; (c) if yes, embed images on separate pages at the end of the PDF with captions (evidence type + description); (d) if no or user opts to review, proceed without embedding; (e) PDF rendering should handle multi-page images gracefully (scale large images, add page breaks). **Verify:** (1) call `report_generate` with evidence items that have image file_paths; (2) verify Claude prompts user for inclusion before rendering; (3) generated PDF has supplementary pages with embedded screenshots; (4) PDF is still readable and properly formatted. |
| OPEN-15 | Medium | 🟡 Shipped in v1.7.0, defective (see RA-1, RA-7) | **GitHub Advisory Database as alternative intel source for resilience.** **Where:** new `src/rubricai/fetchers/gh_advisory.py` module, `intel_lookup` tool in `src/rubricai/tools/intel.py`, and intel schema `src/rubricai/schemas/intel.py`. **Why:** NVD API experiences intermittent outages (503 Service Unavailable); currently, when NVD is down, vulnerability assessment fails completely. GitHub Advisory Database is free, well-maintained, and covers software packages (npm, PyPI, RubyGems, Maven, Nuget, Go) that NVD sometimes misses. Adding it as a secondary source improves coverage and resilience — when NVD is flaky, GH Advisory provides fallback intel. **Do:** (a) create `src/rubricai/fetchers/gh_advisory.py` with `fetch(cve_id: str) -> dict | None` and `search(keyword: str, ecosystem: str) -> list[dict]` functions (use GitHub GraphQL API or REST API v4); (b) fetch: `{cve_id, description, severity, cvss_score, published, urls, ecosystems}`; (c) add GH Advisory data to `intel_lookup`: after NVD fetch, check GitHub Advisory if NVD returned no data or NVD is unreachable (503/timeout), merge both sources with provenance tags (`source: "nvd"` vs `source: "github"`) so users know which intel is stale; (d) document rate limits (60 req/hr unauthenticated, 5000 req/hr with GitHub token) and add optional `GITHUB_TOKEN` env var for higher limits; (e) add caching (same as NVD: 24-hour TTL by CVE, 4-hour TTL for searches). **Verify:** (1) call `intel_lookup` for a package-focused CVE (e.g., log4j) and confirm GH Advisory fills gaps when NVD doesn't; (2) mock NVD 503 outage, verify `intel_lookup` falls back to GH Advisory and returns data with `source: "github"` tag; (3) verify rate-limit warnings appear in logs when approaching API limits; (4) unit tests for GH Advisory parser, caching, and fallback logic with mocked responses. |
| [#12](https://github.com/incendiary/RubricAI/issues/12) | — | ✅ Done (enabled; see D-1 for open defects) | **Branch protection on `main`.** Requires a public repo or GitHub Pro/Team (not available on a private repo on the free plan). Unblock by making the repo public (per the release checklist) or upgrading the plan, then enable required status checks (`ci`) and required PR review. Tracked as GitHub issue [#12](https://github.com/incendiary/RubricAI/issues/12). |

## Review findings, 2026-10-08 (RA-*)

Output of a holistic codebase review and a ponytail (over-engineering) review of `main`
at v1.7.0 (`0d31fb3`). Items are written for an implementing agent with no prior context:
each names the files, the exact change, and a verify step. IDs are `RA-n`; decisions that
need the owner are `D-n`. Do not start an item whose **Depends on** is unmet.

### How this was checked

| Check | Result |
|-------|--------|
| `pytest` on Python 3.14.8 (CI runs 3.11 only) | 347 passed, 87% line coverage |
| Live GitHub Advisory payload for CVE-2021-44228 run through `_normalize_advisory` | Confirms RA-1 (CVSS and description lost) |
| `pip-audit -r requirements-lock.txt` | urllib3 2.7.0 (3 advisories, fixed in 2.8.0), setuptools 82.0.1 (fixed in 83.0.0), virtualenv 21.5.1 (4 advisories, dev-only, via pre-commit), weasyprint 69.0 (CVE-2026-106443, fixed in 70.0) |
| `gh api .../branches/main/protection` | Required contexts `lint`, `test`, `secret-scan` do not match the check-run names `Lint`, `Test`, `Secret Scan` (see D-1) |
| Worst-case latency (RA-2) | Derived from reading `retry.py`, not measured |
| Docker build, SSE bind address, multi-process cache races, PDF rendering on weasyprint 70 | **Not verified** (no Docker on this machine; no multi-process harness) |

### Decisions needed (owner)

| ID | Decision | Recommendation |
|----|----------|----------------|
| D-1 | **Branch protection is unmergeable as configured.** Required contexts are lower-case job ids; GitHub reports the `name:` values (`Lint`, `Test`, `Secret Scan`), so the gate waits for checks that never report. Separately, `required_approving_review_count: 1` with a single author cannot be satisfied (GitHub forbids self-approval) and `enforce_admins` is on. This blocks #106, #107 and 19 Dependabot PRs. | Set contexts to the three real names. For approvals, either set the count to 0 (PR plus green CI still required, admins enforced) or add a second reviewer or bot account. Owner to choose; do not change settings without confirmation. |
| D-2 | **Close #106 and #107 as superseded.** `main` already contains `src/rubricai/auth.py`, `ROADMAP.md` and the OPEN-1/OPEN-2 fixes. #106 now differs from `main` by 19 README lines; #107 is DIRTY. | Close both with a comment pointing at this section. |
| D-3 | **GitHub Advisory as primary: keep the label, change the merge rule.** `vendor` and `automatable` only exist in NVD, so NVD is called for every CVE regardless; GitHub adds a second request and a second failure mode. GitHub's `summary` is a title, not a description. | Keep GitHub first for ecosystem identity, but merge per field: NVD English description and CVSS vector when present, GitHub values only to fill gaps or when NVD fails. RA-1 implements this. |
| D-4 | `.serena/project.yml` is tracked but Serena rewrites it on every version change, so the tree is permanently dirty. | `git rm --cached .serena/project.yml`, add `.serena/` to `.gitignore`. |
| D-5 | `env_migrate_legacy` tool and `needs_migration` flag exist for a pre-v0.8 layout. | Delete if no installs older than v0.8 remain (about 50 lines, see RA-12). |
| D-6 | Housekeeping of 7 stashes and about 17 stale local branches (several already merged or marked `gone` on origin). | List and delete merged branches after owner review. Destructive, so not automated. |
| D-7 | CI tests Python 3.11 only; local venv is 3.14.8 and passes. | Add 3.13 (and 3.14 if wanted) to the matrix in RA-8. Extends OPEN-8. |

### Work packages

Model guide: **Opus 5.5** for concurrency or security reasoning where a subtle mistake is
costly; **Sonnet 5.5** for ordinary scoped changes with tests; **Haiku 5.5** for mechanical,
fully specified edits. Every item is its own branch and PR (squash merge, conventional
title). Bump the patch version once per batch, not per PR: batch A is RA-1 to RA-4 (1.7.1),
batch B is RA-5 to RA-8 (1.7.2). Bump `VERSION`, `pyproject.toml` and the README clone tag together.
Run `source .venv/bin/activate && pytest` before pushing. Do not run `detect-secrets` or
pytest and then commit `.secrets.baseline` (see RA-6).

#### RA-1: Fix GitHub Advisory field mapping and merge per field

| | |
|-|-|
| Priority | High (affects every CVE that has a GHSA, including all of the log4j-class examples) |
| Model / effort | Sonnet 5.5 / S |
| Depends on | none |
| Files | `src/rubricai/fetchers/gh_advisory.py`, `src/rubricai/tools/intel.py`, `tests/test_fetchers.py`, `tests/test_intel.py`, new `tests/fixtures/ghsa_log4shell.json` |

**Context.** `_normalize_advisory` reads `advisory["cvss_score"]` and `advisory["package"]`,
which the GitHub API does not return. The real shape is `cvss: {score, vector_string}`,
`cvss_severities`, and `vulnerabilities[].package`. Result for CVE-2021-44228: `cvss_base`
is `None`, no vector is stored, and `description` is the title "Remote code injection in
Log4j". In `intel.py`, because the GitHub record is truthy, the NVD CVSS fetch is skipped
(`elif nvd_record`), so `cvss` is `None`; the description replaces NVD's, and
`derive_finding_context` then classifies utility as `other` because "code injection" does
not match its `remote code exec` pattern. `score_evaluate` loses the CVSS weight (up to 4.0
points) and the AV/PR/AC derivations. Reproduce:
`gh api -H "Accept: application/vnd.github+json" "advisories?cve_id=CVE-2021-44228"`.

**Do.**
1. In `_normalize_advisory`: `cvss = advisory.get("cvss") or {}`; set `cvss_base = cvss.get("score") or None`, `cvss_vector = cvss.get("vector_string")`, and `cvss_version` from the vector prefix (`CVSS:3.1/` gives `3.1`, `CVSS:4.0/` gives `4.0`, otherwise `unknown`). Take package and ecosystem from `advisory["vulnerabilities"][0]["package"]` when present. Treat a score of 0 with no vector as unscored.
2. In `intel.py` `_lookup_one`: build `cvss` from the GitHub record only when both `cvss_base` and `cvss_vector` are present; otherwise fall through to `nvd_fetcher.fetch_cvss`. Replace the `"N/A"` vector default with `None`.
3. Description: use the NVD English description when `nvd_record` has one; use the GitHub `summary` only when NVD has none. Keep the `GITHUB_ADVISORY` entry in `sources`.
4. Delete the unused `_HTTP_TIMEOUT` constant in `gh_advisory.py`.

**Verify.** Save a trimmed copy of the live payload to `tests/fixtures/ghsa_log4shell.json`.
Tests: (a) normaliser returns `cvss_base == 10`, a vector starting `CVSS:3.1/AV:N`, version `3.1`;
(b) with GitHub returning no score and NVD returning one, `intel_lookup` returns the NVD CVSS;
(c) with both present, `derived_finding_context.attacker_utility` for log4shell contains `rce`
(NVD wording) rather than `other`. `pytest` green.

#### RA-2: Bound worst-case request latency and remove dead timeout code

| | |
|-|-|
| Priority | High |
| Model / effort | Sonnet 5.5 / S |
| Depends on | none |
| Files | `src/rubricai/fetchers/retry.py`, `src/rubricai/fetchers/{kev,epss,nvd,osv}.py`, `README.md` (env var row), new `tests/test_retry.py` |

**Context.** `fetch_with_retry` catches `httpx.HTTPError`, which includes timeouts, so each
timeout window makes 4 attempts with 1s, 2s, 4s backoff before the outer loop escalates.
Worst case per call: (4x5+7) + (4x10+7) + (4x30+7) = about 201s, and about 400s on NVD
because the 503 auth fallback repeats the whole escalation. That is well above typical MCP
client request timeouts (client dependent), so the user sees a tool failure even though a
later window might have succeeded. Also, `RUBRICAI_HTTP_TIMEOUT` is documented in the
README but nothing reads it any more: `_timeout()` in `kev.py`, `epss.py`, `nvd.py` and
`_HTTP_TIMEOUT` in `osv.py` are dead since the escalation change.

**Do.**
1. Timeouts must not be retried inside a window (escalation is the retry). In `fetch_with_retry` re-raise `httpx.TimeoutException` immediately; keep backoff for 429, 5xx and non-timeout network errors.
2. Make the largest window configurable: `windows = (5, 10, min(30, cap))` where `cap` comes from `RUBRICAI_HTTP_TIMEOUT` (default 30, invalid values fall back to 30). Worst case becomes about 45s plus backoff.
3. Delete the dead `_timeout()` and `_HTTP_TIMEOUT` definitions listed above and the `import os` lines they orphan.
4. Update the README env var row to say what it now does.

**Verify.** `tests/test_retry.py` using `httpx.MockTransport`: a handler that always raises
`ReadTimeout` is called exactly 3 times (once per window); a 503-then-200 sequence returns the 200;
a 404 returns immediately. `grep -rn "_timeout()\|_HTTP_TIMEOUT" src` returns nothing.

#### RA-3: Make state writes safe (BOM lost update, unlocked versioning)

| | |
|-|-|
| Priority | Medium-High |
| Model / effort | Opus 5.5 / M |
| Depends on | none |
| Files | `src/rubricai/tools/bom.py`, `src/rubricai/tools/environment.py`, `tests/test_bom.py`, `tests/test_environment.py` |

**Context.** `env_write` takes an exclusive `flock` around version allocation (fix for #77).
`bom._save_state` re-implements the same versioning with a private `_current_version` and no
lock. `bom_check` loads state, then performs network calls for every component (minutes),
then saves the whole object, so any `env_write` or `bom_update` made in between is silently
overwritten, and two writers can both claim the same `state_vNNN.json`.

**Do.**
1. Extract the locked "allocate next version and write `state_vNNN.json` plus `state_latest.json`" block of `env_write` into one helper in `environment.py` and call it from both `env_write` and `bom._save_state`. Delete `bom._save_state`'s private version logic.
2. In `bom_check`, after the network phase, re-load the latest state under the lock and apply only the `last_checked` timestamps by component `(name, version)`; never write back the stale BOM.
3. Run the per-component lookups concurrently with `asyncio.Semaphore(3)` (NVD allows 5 requests per 30s unauthenticated, so do not go higher without a key). Keep result ordering deterministic.

**Verify.** Tests: (a) call `bom_update` while a mocked slow `bom_check` is in flight; the new BOM survives; (b) two threads calling the shared writer 20 times each produce versions 1..40 with no duplicates; (c) existing bom and environment tests pass.

#### RA-4: `env_read` must not create environments

| | |
|-|-|
| Priority | Medium |
| Model / effort | Haiku 5.5 / XS |
| Depends on | RA-3 (same file) |
| Files | `src/rubricai/tools/environment.py`, `tests/test_environment.py` |

**Context.** `env_read` calls `_env_dir`, which does `mkdir`. A mistyped name in a read
creates a permanent empty environment that then appears in `env_list`.

**Do.** Give `_env_dir` a `create: bool = True` parameter; `env_read` passes `create=False` and returns the empty template without touching disk. Writers keep creating.

**Verify.** Test: `env_read("typo-env")` then `env_list()["environments"]` does not contain `typo-env`.

#### RA-5: SSE transport hardening

| | |
|-|-|
| Priority | Medium-High (only when exposed beyond localhost) |
| Model / effort | Sonnet 5.5 / S |
| Depends on | none |
| Files | `src/main.py`, `src/rubricai/auth.py`, `docker-compose.yml`, `.env.example`, `README.md`, `tests/test_auth.py`, new `tests/test_main.py` |

**Context.** (1) `auth.py` compares the header with `!=`, which is not constant time.
(2) `main.py` enables TLS only if both `RUBRICAI_TLS_CERT` and `RUBRICAI_TLS_KEY` are set; with only one set it silently serves plain HTTP. (3) `docker-compose.yml` defaults `RUBRICAI_API_KEY` to empty, so `docker compose up` publishes port 8000 with `env_write`, `report_generate` and `project_scan` unauthenticated. (4) `main.py` has 0% test coverage.

**Do.**
1. Use `hmac.compare_digest` on the encoded header and expected value.
2. In `main.py`, raise `SystemExit` with a clear message if exactly one of cert/key is set.
3. For `sse` transport, refuse to start when `RUBRICAI_API_KEY` is unset unless `RUBRICAI_ALLOW_NO_AUTH=1` is set explicitly. Document in README and `.env.example`.
4. Extract the argument and transport wiring into a function that returns the `mcp.run` kwargs so it can be unit tested without starting a server.
5. Bind address: confirm what FastMCP binds to by default under `sse` and document it. **Needs Docker to verify end to end; do not claim it is verified without it.**

**Verify.** Tests for: wrong key of equal length returns 401; one-of-cert/key exits non-zero; sse without key exits non-zero; sse with key returns kwargs containing the middleware.

#### RA-6: Cache robustness and test isolation

| | |
|-|-|
| Priority | Medium |
| Model / effort | Sonnet 5.5 / M |
| Depends on | none |
| Files | `src/rubricai/cache.py`, `src/rubricai/fetchers/*.py` (module-level `_cache = FileCache()`), `src/rubricai/server.py` (import-time logging), `tests/conftest.py` (new), `tests/test_secrets.py`, `tests/test_cache.py` (new) |

**Context.**
- `FileCache._save` is a plain `write_text`; a crash mid-write leaves invalid JSON, and `_load` then returns `{}`, discarding the whole namespace. Use write to temp file in the same directory plus `os.replace`.
- Importing any fetcher creates `~/.cache/rubricai`, and importing `rubricai.server` creates the log directory and file under `~/.local/share/rubricai`. The test suite therefore writes into the developer's real home.
- `tests/test_secrets.py` runs `detect-secrets scan --baseline .secrets.baseline` against the tracked file, which rewrites it in place with an absolute local path and a new timestamp. Every `pytest` run dirties the tree (observed during this review).
- Not-found and error results are never cached, so a CVE with no GHSA costs one GitHub request per lookup, against a 60 requests per hour unauthenticated limit.

**Do.**
1. Atomic write in `_save`.
2. Create the cache directory lazily on first `set`, not in `__init__`.
3. `tests/conftest.py` autouse fixture: set `RUBRICAI_ENV_DIR`, `RUBRICAI_REPORT_DIR`, `RUBRICAI_LOG_DIR` to `tmp_path`, and `HOME` to a temp directory so default paths cannot reach the real home.
4. `test_secrets.py`: copy the baseline to `tmp_path` and scan against the copy.
5. Add a negative-cache entry (TTL 1 hour) for confirmed 404 or empty results in `gh_advisory.fetch` only; never cache transport errors. Relates to OPEN-12 (stale-if-error), which stays separate.

**Verify.** After `pytest`, `git status --short` is empty and `ls ~/.cache/rubricai` is unchanged. A test that kills a write halfway (patch `os.replace` to raise) leaves the previous cache file readable.

#### RA-7: GitHub Advisory hygiene: rate limit, token docs, unused code

| | |
|-|-|
| Priority | Medium |
| Model / effort | Sonnet 5.5 / S |
| Depends on | RA-1, RA-6 |
| Files | `src/rubricai/fetchers/gh_advisory.py`, `README.md`, `.env.example`, `docker-compose.yml`, `tests/test_fetchers.py` |

**Context.** `GITHUB_TOKEN` is read by the code but appears in no doc, `.env.example` or compose file, so everyone runs at 60 requests per hour. `intel_lookup` accepts 50 CVEs per call and fires one GitHub request each; after the first 403 every remaining CVE repeats the request and logs the same warning. `gh_advisory.search()` (lines 100 to 184) has no caller (BOM checks use OSV and NVD) and no tests.

**Do.**
1. Document `GITHUB_TOKEN` (no scopes needed for public advisories) in the README env table, `.env.example` and compose.
2. Module-level `_blocked_until` timestamp: on a 403 with `x-ratelimit-remaining: 0`, skip GitHub until the `x-ratelimit-reset` time and log once.
3. Delete `search()` and the `data.get("advisories", [])` dict branch in `fetch` (the API returns a list). Trim `_normalize_advisory` to the keys `intel.py` reads.

**Verify.** Test: after one mocked 403 with remaining 0, a second `fetch` makes no HTTP call. `grep -rn "gh_advisory.search" src tests` returns nothing.

#### RA-8: CI hardening and Dependabot grouping

| | |
|-|-|
| Priority | Medium |
| Model / effort | Sonnet 5.5 / S |
| Depends on | D-1 (so the PR can merge) |
| Files | `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.pre-commit-config.yaml`, `pyproject.toml` |

**Do.**
1. Add top-level `permissions: contents: read` to `ci.yml`.
2. Add `schedule: - cron: "0 6 * * 1"` (weekly) so drift is caught without a push.
3. Add a `pip-audit -r requirements-lock.txt` step (new job `audit`, not required initially). Install with `pip install pip-audit==<current>`.
4. Python matrix `["3.11", "3.13"]` on the test job (plus 3.14 per D-7).
5. Coverage gate: `--cov-fail-under=85` (current 87%). Never lower it.
6. Pin third-party actions to commit SHAs with the tag as a trailing comment; Dependabot keeps them current.
7. Align versions (extends OPEN-7): pre-commit `isort` is 6.0.1 and CI is 8.0.1; pre-commit `trufflehog` is v3.95.2 and CI is v3.95.5; lock file has ruff 0.15.17 and CI pins 0.15.15.
8. `dependabot.yml`: add `groups:` so minor and patch updates arrive as one weekly PR per ecosystem; leave majors ungrouped.

**Verify.** Open the PR and confirm all jobs run and report as `Lint`, `Test`, `Secret Scan`, `Audit`. `git diff` shows no `uses:` without a 40-character SHA.

#### RA-9: Dependency remediation and Dependabot backlog

| | |
|-|-|
| Priority | High (weasyprint and urllib3 advisories) |
| Model / effort | Sonnet 5.5 for majors, Haiku 5.5 for patch bumps / M |
| Depends on | D-1 |
| Files | `requirements-lock.txt`, `pyproject.toml`, workflow files |

**Do.** Use the `github-morning-run` skill. Merge patch and minor Dependabot PRs one at a time (CI must be green on the rebased branch). Handle individually, never batched: `weasyprint` 69 to 70 (#149; run `pytest tests/test_report.py` and regenerate one PDF to eyeball), `cryptography` 49 to 50 (#145), `actions/checkout` 6 to 7 (#125), `actions/setup-python` 6 to 7 (#142), `trufflehog` (#148). The lock also needs `urllib3>=2.8.0`; if no PR exists, bump it by hand. Re-run `pip-audit` and record the result in the PR.

**Verify.** `pip-audit -r requirements-lock.txt` reports only dev-only transitive items (virtualenv), or nothing.

#### RA-10: Close test gaps on resilience paths

| | |
|-|-|
| Priority | Medium |
| Model / effort | Sonnet 5.5 / M |
| Depends on | RA-2, RA-5, RA-7 |
| Files | `tests/test_retry.py`, `tests/test_fetchers.py`, `tests/test_main.py`, `tests/test_project_scan.py` |

Coverage today: `main.py` 0%, `gh_advisory.py` 52%, `retry.py` 73% (the escalation loop, lines 151 to 175, is untested), `epss.py` and `kev.py` 72% (error branches), `project_scan.py` 69%, `server.py` 81%. Add tests for: each fetcher returns its documented empty value on timeout, 429, 5xx and malformed JSON; NVD 503 auth fallback sends the second request without `apiKey`; `project_scan` on a malformed `pom.xml`, `package.json` and `go.mod`. Assert specific values, not just status codes. **Verify:** total coverage at least 90%, and no module under 80% except `server.py`.

#### RA-11: `project_scan` input hardening

| | |
|-|-|
| Priority | Low-Medium |
| Model / effort | Haiku 5.5 / XS |
| Depends on | none |
| Files | `src/rubricai/tools/project_scan.py`, `pyproject.toml`, `tests/test_project_scan.py` |

**Context.** `pom.xml` is parsed with `xml.etree.ElementTree`, and the file-wide ruff ignore `S314` hides that. ElementTree does not fetch external entities but does expand internal ones, so a hostile manifest can cause entity-expansion blow-up. Manifests are read without a size limit, and the scan path is chosen by the model.

**Do.** Skip any manifest larger than 1 MB. Reject XML containing `<!DOCTYPE` or `<!ENTITY` before parsing (stdlib only, no new dependency). Replace the file-level `S314` ignore with a per-line `# noqa: S314` plus the reason. **Verify:** test with a billion-laughs `pom.xml` returns no entries quickly; test with a 2 MB `requirements.txt` is skipped.

#### RA-12: Simplification pass (ponytail findings)

| | |
|-|-|
| Priority | Low |
| Model / effort | Sonnet 5.5 / S |
| Depends on | RA-1, RA-2, RA-3, RA-7 (avoids merge conflicts in the same files) |

Apply the cuts listed under "Ponytail review" below that earlier items did not already remove. Behaviour must not change: the suite stays green and coverage does not drop.

#### RA-13: Documentation and repo hygiene

| | |
|-|-|
| Priority | Low |
| Model / effort | Haiku 5.5 / XS |
| Depends on | D-2, D-4 |

Rewrite the repo `CLAUDE.md`: it is still the publication-readiness template ("Fill in the four fields above", branch protection example with context `"ci"`, which is wrong). Keep it generic, no personal or employer context. Add the OPEN-1 remaining item (Docker `HEALTHCHECK`) to the first Docker-capable session. Note in the README that `RUBRICAI_HTTP_TIMEOUT` semantics changed (RA-2).

### Ponytail review (over-engineering only)

Whole-repo scan, not a PR diff. One line per finding; `RA-n` marks the item that already covers it.

- `fetchers/kev.py:L21-26`, `epss.py:L17-22`, `nvd.py:L21-26`: delete: `_timeout()` is never called. Nothing replaces it. (RA-2)
- `fetchers/gh_advisory.py:L33`, `osv.py:L32`: delete: `_HTTP_TIMEOUT` is never read. (RA-1, RA-2)
- `fetchers/gh_advisory.py:L100-184`: delete: `search()` has no caller and no tests, about 85 lines. (RA-7)
- `fetchers/gh_advisory.py:L86-87` and the same pattern in `search`: delete: `data.get("advisories", [])` branch; the endpoint returns a list. (RA-7)
- `fetchers/gh_advisory.py:L187-225`: yagni: `_normalize_advisory` emits `ecosystem`, `package`, `severity`, `source`, `url`, `published`, `last_modified` that `intel.py` never reads. Keep id, description, cvss fields. (RA-7)
- `fetchers/retry.py:L96-99` and `L173-176`: delete: unreachable "should not reach here" tails; both loops either return or raise. Use `for ... else` or drop them.
- `fetchers/retry.py:L58-59`: delete: the `400 <= status < 500` early return is identical to the final `return resp`.
- `fetchers/retry.py:L24-100` vs `L102-177`: yagni: two functions where the inner one takes a client it is always handed by the outer. One function creating `httpx.AsyncClient(timeout=t)` per window is enough. About 25 lines.
- `fetchers/nvd.py:L38-64`: shrink: `_fetch_with_auth_fallback` has a third branch repeating the unauthenticated call. `resp = await f(headers=headers); if headers and resp.status_code == 503: resp = await f(headers={})`. About 12 lines.
- `fetchers/nvd.py:L8`: delete: `# noqa: F401` is stale; `httpx` is used by the `-> httpx.Response` annotation at L40.
- `tools/bom.py:L40-57`: reuse: `_save_state` duplicates versioning from `tools/environment.py:L51-57` (`_current_version`) and `env_write`. Call the shared helper. (RA-3)
- `tools/intel.py:L72-90`: shrink: `primary_record = gh_advisory_record or nvd_record` is used only as a truthiness test, and the `"N/A"` vector default is never valid. Fold into the RA-1 rewrite.
- `server.py:L41-42`: delete: `".." in _log_dir.parts` after `.resolve()` can never be true, because `resolve()` already collapses `..`.
- `tools/environment.py:L60-62,L167-206` plus `needs_migration` in `env_list`: yagni: migration tool for a layout from before v0.8. Delete with its two tests if D-5 agrees. About 50 lines.
- `tests/*`: tests import `src.rubricai...` while the server imports `rubricai...`, so patches in `test_fetchers.py` target different module objects from the ones the server uses. Not over-engineering, but make tests import `rubricai` (editable install) to remove the second import root. (Add to RA-10.)

net: -190 lines possible (about 25 dead timeout code, 85 `search()`, 30 retry collapse, 12 NVD fallback, 15 BOM save, 10 normaliser, 4 misc, 50 legacy migration if D-5 agrees, less the code RA-1 to RA-3 add).

### Execution plan

1. **Owner, now:** D-1, D-2, D-4. Nothing merges until D-1 is fixed.
2. **Wave 1 (parallel, disjoint files):** RA-1 (Sonnet), RA-2 (Sonnet), RA-3 (Opus), RA-5 (Sonnet), RA-6 (Sonnet), RA-11 (Haiku). Merge as they go green; tag **1.7.1** after RA-1 to RA-3 land.
3. **Wave 2:** RA-4 (Haiku, after RA-3), RA-7 (Sonnet, after RA-1 and RA-6), RA-8 and RA-9 (after D-1).
4. **Wave 3:** RA-10, then RA-12, then RA-13. Tag **1.7.2**.

Agents working in parallel must each use their own branch from current `main`, keep PRs to one logical change, and catch up with `git merge main` (never rebase a pushed branch). README conflicts between RA-2, RA-5 and RA-7 are expected and trivial.
