---
name: osv-dependency-scan
description: On-the-fly software composition analysis (SCA) against the OSV.dev vulnerability database for every new or upgraded third-party dependency before it enters the codebase. Use this skill whenever a coding task would add, bump, pin, vendor, or import a package (npm/pip/Go/Maven/Cargo/NuGet/RubyGems/Composer/etc.), even for "quick" installs — run it right after guardrail selection and PWNISMS threat modelling and before writing the dependency. It does not block the developer's flow: instead of stopping on a HIGH/CRITICAL-vulnerable version, it automatically substitutes the nearest safe (fixed) version, keeps building, and flags the avoided vuln in the response summary and in VibeReview telemetry (threats mitigated).
---

# OSV.dev Dependency Scan (IDE-side SCA)

Configured VibeReview project: `Security TooL`
Project slug: `security-tool`
Project id: `e00ccc4a-3cb0-4288-a2fa-57703efa93e8`

This skill is VibeReview's **on-the-fly software composition analysis**. It runs inside the IDE, in the same turn the agent is choosing dependencies, so a known-vulnerable package version is caught *before* it lands in `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`, or an install command — not in a CI scan days later.

It complements, but does not replace, server-side VibeReview profiling. Profiling reasons about the *existing* repo; this skill guards the *incoming* supply-chain delta for the current task.

## Where this fits in the VibeReview workflow

This is an **auto-remediation step**, not a stop sign. It runs before the dependency is written so it can pick a safe version up front, but it never halts the developer's flow to ask permission. Ordered like this:

1. `.cursor/skills/guardrails-selection/SKILL.md` — shortlist the project guardrails.
2. `.cursor/skills/threat-modelling/SKILL.md` — PWNISMS threat modelling (the final **S — Supply Chain** category is what this skill operationalizes).
3. **This skill** — scan every dependency the task will introduce or upgrade, and substitute a safe version where needed.
4. Implementation — write code with the safe versions this skill selected, then keep going.
5. `.cursor/skills/vibereview-sync/SKILL.md` — record what was scanned, what vuln was avoided, and the version chosen.

Run this scan for every new/changed package and use its result to pick the version you write — but do not pause and wait. The default behavior is silent auto-remediation plus a transparent note in the reply. If guardrail selection separately flagged a supply-chain rule with `requires_approval`, that approval gate still applies (it is a project policy choice); this scan is in addition to it, not a substitute.

## When to trigger

Run the scan when the current prompt will, directly or as part of a fix/feature/refactor:

- add a new dependency, or import a package not already in the manifest;
- upgrade, downgrade, or change the pinned version of an existing dependency;
- replace one library with another;
- vendor or copy a third-party module;
- generate code that assumes a specific package version (AI-suggested deps are untrusted until scanned).

Re-run for follow-up prompts in the same IDE chat whenever they touch dependencies again — a previous scan does not cover a newly introduced package. Scan **direct** dependencies you are adding; if a lockfile resolves a specific transitive version that this change pins, scan that too.

You may skip only when the task introduces no new or changed dependency (pure logic edits, docs, formatting). If you skip, be ready to say why.

## How to run the scan

A zero-dependency Node scanner is bundled with this skill at:

```
.cursor/skills/osv-dependency-scan/scripts/osv-scan.mjs
```

It calls the public, unauthenticated OSV.dev API (`https://api.osv.dev`), so no API key or network credentials are needed. Requires Node >= 18 (for global `fetch`), which is already present in any environment running this kit.

Pass the exact ecosystem and the `name@version` you intend to add:

```bash
node .cursor/skills/osv-dependency-scan/scripts/osv-scan.mjs --ecosystem npm express@4.17.1 jsonwebtoken@8.5.1
node .cursor/skills/osv-dependency-scan/scripts/osv-scan.mjs --ecosystem PyPI requests@2.19.1
node .cursor/skills/osv-dependency-scan/scripts/osv-scan.mjs --ecosystem Go github.com/gin-gonic/gin@v1.6.0
```

Useful flags:

- `--ecosystem <eco>` — friendly aliases are normalized (`pip`→`PyPI`, `cargo`→`crates.io`, `composer`→`Packagist`, `gem`→`RubyGems`, `node`/`yarn`/`pnpm`→`npm`, …).
- `--severity-threshold HIGH` — default; remediates `HIGH` and `CRITICAL`. Use `CRITICAL` only if the project explicitly tolerates HIGH.
- `--json` — machine-readable output (includes a `recommended` safe version per package) to fold into the VibeReview scan artifact.
- `--stdin` — pass a JSON array `[{"ecosystem","name","version"}]` for mixed-ecosystem batches.

The scanner also prints a best-effort `recommended:` safe version (the highest published `fixed` version) for each flagged package, so you can substitute without guessing. Treat it as a strong default; still confirm it satisfies the task's compatibility needs and re-scan it.

**Exit codes are a signal, not a halt — they tell you whether to remediate:**

| Exit | Meaning | Action |
|---|---|---|
| `0` | No findings at/above the threshold | Use the scanned version as-is. |
| `1` | At least one package has a `HIGH`/`CRITICAL` vuln | **Auto-remediate:** swap in the `recommended` safe version and keep going. Do not stop to ask. |
| `2` | Unknown severity, or OSV was unreachable / errored | Proceed with the requested version but flag it as unverified residual risk in the summary + telemetry. Do not halt. |
| `3` | Bad usage | Fix the invocation and re-run. |

### If the script cannot run

If Node is unavailable or the script is missing, query OSV.dev directly and apply the same policy:

```bash
curl -s -X POST "https://api.osv.dev/v1/query" -H "Content-Type: application/json" \
  -d '{"package":{"name":"<name>","ecosystem":"<eco>"},"version":"<version>"}'
```

Inspect each returned `vulns[]` entry: use `database_specific.severity` (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`) and/or the CVSS vector in `severity[]`. Read fixed versions from `affected[].ranges[].events[].fixed`. Ignore entries with a `withdrawn` timestamp.

## Decision policy: remediate, don't block

The goal is to keep the vulnerable version out of the codebase **without interrupting the developer's flow**. Do not stop and ask for approval, and do not refuse the task. Instead, quietly land on a safe version and tell the user what you did.

For every scanned package version:

- **`HIGH` or `CRITICAL` (exit 1): auto-substitute a safe version and continue.**
  1. **Use the `recommended` fixed version** from the scanner output (the highest published `fixed` version). Write that version instead of the vulnerable one. Re-scan it once — newer advisories can still affect a "fixed" release; if the recommended version is itself flagged, move to the next-highest fixed version.
  2. If you need a lower major/minor for compatibility, pick the lowest `fixed` version that satisfies the constraint and re-scan it.
  3. **If the package has no published fix at all**, prefer a maintained, non-vulnerable alternative that meets the requirement; if there is no reasonable alternative, proceed with the requested package but record it as **residual (unmitigated) risk** in the summary and telemetry rather than halting. Never silently ship the vulnerable version as if it were clean.
  - Do this even under allow-all / auto-edit / YOLO modes — auto-remediation *is* the non-blocking behavior, so there is nothing to waive.

- **Unknown severity / OSV error (exit 2):** do not treat as clean and do not halt. Proceed with the requested version, attempt a re-scan, and record it as unverified residual risk in the summary + telemetry so it is visible later.

- **Clean (exit 0):** use that exact version. Prefer pinning the scanned version so the resolved artifact matches what was scanned.

The only time you should surface a decision to the user instead of auto-fixing is when remediation would change behavior in a way they must know about (e.g. a major-version bump with breaking changes). Even then, proceed with the safe version by default and call out the upgrade — don't stall waiting for a reply.

## What every response that touches dependencies must include

Add a short **Dependency security (OSV.dev)** section to your reply so the developer can see what the SCA did inline. Keep it brief — this is a transparency note, not an approval request:

```
Dependency security (OSV.dev)
- express 4.17.1 → 4.21.2 [npm]   auto-fixed: avoided GHSA-... (HIGH), re-scanned clean
- jsonwebtoken 9.0.2 [npm]        clear
- <pkg> <ver> [<eco>]             residual risk: no published fix / OSV unreachable — flagged
```

Never describe a package as added/safe if a vuln was avoided — say which safe version you landed on. When you auto-substitute, mention it but keep moving; don't frame it as a blocker.

## Recording in VibeReview telemetry

Fold the results into the structured JSON the final sync writes (`.cursor/skills/vibereview-sync/SKILL.md`), so every avoided vuln is auditable in VibeReview even though the developer was never interrupted:

- For each auto-remediated package, add a `threats_mitigated` row: `threat_name` like `Vulnerable dependency avoided: express@4.17.1`, `severity` from the finding, `mitigation_applied` describing the substitution (`bumped to 4.21.2`, cite the GHSA/CVE id), and `satisfied: true`.
- For a residual-risk case (no fix available, or OSV unreachable), still add a `threats_mitigated` row but with `satisfied: false` and a note explaining why it could not be remediated — this is the signal that surfaces it for later follow-up.
- Add a `best_practices_achieved` entry noting that incoming dependencies were OSV-scanned and vulnerable versions were auto-replaced with safe ones.
- Add an `ide_generated` guardrail (e.g. `Scan new dependencies against OSV.dev and auto-substitute a safe version for HIGH/CRITICAL findings`) with `rule_type: must`, `category: supply_chain`, recording `satisfied` honestly.
- Add an `owasp_mappings` row for `A06:2021 — Vulnerable and Outdated Components` whenever a vulnerable dependency was caught or remediated.

Keep the rows grounded in this session's actual scan output — copy real vuln IDs and versions, do not invent.

## Quality bar

A good run of this skill:

- scanned every package the task introduced or changed, with the correct ecosystem;
- replaced every `HIGH`/`CRITICAL` version with a re-scanned safe version (or recorded honest residual risk when no fix exists) — **without halting the developer's flow**;
- never let an `exit 2` (unknown/unreachable) masquerade as clean;
- surfaced a short transparency note in the response and mirrored every avoided vuln into VibeReview telemetry as a mitigated (or residual) threat.
