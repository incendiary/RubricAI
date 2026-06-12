# Project Publication Readiness — Python

## Context
- **Type:** Vulnerability prioritisation MCP server + AI interview workflow
- **Authorization:** No offensive capability — fetches public intel only (CISA KEV, EPSS, NVD)
- **Public release intent:** Portfolio / professional reference for security engineering workflows
- **Audience:** Security engineers, AppSec teams, vulnerability management practitioners

Fill in the four fields above before starting the audit.

---

## Ordered Steps — Work top to bottom. One PR per logical unit. Stop before any destructive action.

### Priority Zero — Secret Scanning
Audit every file and the full git history for hardcoded credentials, API keys,
tokens, internal IPs, hostnames, email addresses, and proprietary config.

```bash
# Working tree
grep -rniE "(key|secret|token|password|auth|bearer|sk-|akia|api_key)" . \
  --include="*.py" --include="*.toml" --include="*.cfg" --include="*.env" \
  --include="*.yaml" --include="*.yml" --include="*.json"

# Git history
git log -p | grep -iE "(key|secret|token|password|bearer|sk-|akia)" | head -100
```

If secrets found in history: recommend destroying `.git` and reinitialising.
**Do not proceed until working tree and history are confirmed clean.**

---

### Step 1 — Dependency Audit
- Check `requirements*.txt` / `pyproject.toml` for severely outdated or CVE-affected packages.
- Flag anything high-severity. Check Dependabot alerts if repo is already on GitHub.

---

### Step 2 — Code Quality Review (Karpathy pass)
Review every `.py` file:
- **Dead code** — unreachable branches, unused imports, unused variables
- **Duplication** — repeated logic that should be extracted
- **Confusing control flow** — catch-and-re-raise, dead else branches, unreachable returns
- **Comment noise** — comments that describe *what*, not *why*

Present findings grouped as (A) dead code, (B) duplication, (C) control flow, (D) comment noise.
**Ask for confirmation before implementing each group. Make distinct commits per group.**

Principles:
- Surgical changes only — every changed line traces to a finding
- No speculative abstractions, no wrapper functions that add no logic
- Match existing style unless step 3 tooling enforces otherwise

---

### Step 3 — Tooling
Set up if not already present:

```bash
# Install tooling
python -m pip install --upgrade pip
pip install black ruff isort pre-commit detect-secrets

# Initialise pre-commit
pre-commit install
pre-commit run --all-files

# Generate secrets baseline (commit this file — it tracks known findings)
detect-secrets scan > .secrets.baseline
```

Required config files (templates already in this repo):
- `pyproject.toml` — Black, Ruff, isort config
- `.pre-commit-config.yaml` — gitleaks, trufflehog, black, ruff, isort, detect-secrets hooks
- `.github/workflows/ci.yml` — lint + test + secret-scan on push/PR
- `.gitleaks.toml` — gitleaks config with `.secrets.baseline` allowlist
- `.secrets.baseline` — detect-secrets known-findings baseline (committed, not ignored)

Add a GitHub issue and roadmap entry for any missing tests.

---

### Step 4 — Documentation
- Update `README.md`: project description, setup instructions, roadmap table
- Add roadmap `## Roadmap` section with columns: Issue #, Status, Description
- Create a GitHub issue for each step above that required work
- Add this footer to README:

```markdown
> This project was uplifted for public release with the assistance of Claude (Anthropic).
> Things should work, but some paths may not have been fully re-tested. PRs and fixes welcome.
```

---

### Step 5 — Branch Protection
```bash
# Make repo public
gh repo edit --visibility public

# Enable branch protection on main
gh api repos/incendiary/RubricAI/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["ci"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field restrictions=null
```

---

### Versioning
Tag a release at each milestone:
```bash
gh release create v0.1.0 --title "Secret scan + dependency audit clean" --notes "Priority Zero and Step 1 complete"
gh release create v0.2.0 --title "Code quality pass" --notes "Step 2 complete"
gh release create v0.3.0 --title "Tooling configured" --notes "Step 3 complete"
gh release create v0.9.0 --title "Security hardening complete" --notes "All 17 findings remediated (PRs #73-#81)"
gh release create v1.0.0 --title "Public release" --notes "All steps complete, branch protection enabled"
```

---

## Security Remediation Way of Working

When performing security fixes:
1. **Spec first** — use karpathy-spec to break into agile specs with testable "done when"
2. **One PR per logical group** — related findings can share a PR, but each PR is independently reviewable
3. **Point releases per PR** — each merged fix bumps Major.Minor.Point (e.g. 0.8.6, 0.8.7...)
4. **Minor release on completion** — all security work done = minor bump (e.g. 0.9.0)
5. **Test before commit** — run affected tests, verify no regressions
6. **README roadmap tracking** — every PR gets a row in the Roadmap table with status
7. **Verify after** — invoke karpathy-verify: run full suite, check coverage, confirm no new findings
8. **PR format** — title: `fix: <description> (vX.Y.Z)`, body: Summary + Findings table + Test plan

---

## Engineering Philosophy
- Think before coding — state assumptions, ask before implementing
- Simplicity first — minimum code that solves the problem
- Surgical changes — touch only what you must
- Use `.venv` — never install packages system-wide

```bash
python -m venv .venv && source .venv/bin/activate
```
