---
name: PWNISMS Threat Modelling
description: Security-first threat modelling workflow for code and architecture tasks. Walks all 7 PWNISMS categories, enforces VibeReview guardrails, and synchronizes findings via the VibeReview structured JSON sync. Use after guardrail selection and before implementation.
---

# PWNISMS — Security-First Threat Modelling

Configured VibeReview project: `Security TooL`
Project slug: `security-tool`
Project id: `e00ccc4a-3cb0-4288-a2fa-57703efa93e8`

For EVERY security-relevant task (feature, bug fix, refactor, infra change, architecture design), run a threat model with PWNISMS.

- This is a pre-implementation gate. Do not write, edit, patch, or generate implementation code until guardrail selection has completed and this PWNISMS pass has been completed.
- Walk through all 7 categories explicitly.
- If a category is not applicable, state it briefly and move on.
- Anchor analysis to linked files, diffs, PRs, API specs, and diagrams whenever available.
- Focus on realistic threats for the current context, not exhaustive attack catalogs.

Follow-up prompts count as new tasks when they change security-relevant behavior. If a later prompt in the same IDE chat touches APIs/endpoints, auth/authorization, data access, untrusted input/output, secrets, network calls, infra, dependencies, agents/tools, logging, monitoring, or a trust boundary, run a fresh PWNISMS pass for that prompt. Reuse the same `chat_session_id` only for scan grouping; the follow-up still needs a new prompt-specific event artifact.

---

## Phase 0 — Guardrail Context

Before deep analysis, ensure the project-specific guardrail shortlist exists:

1. Use `.cursor/skills/guardrails-selection/SKILL.md`.
2. Resolve the project with `vibereview_get_tenant_project` using `project_id="e00ccc4a-3cb0-4288-a2fa-57703efa93e8"` (or `project_slug="security-tool"`).
3. Call `vibereview_get_guardrails`, shortlist intentionally for this task, then preserve the exact returned guardrail records in context.
4. Keep the shortlisted existing guardrails in context for implementation and the final VibeReview structured JSON sync.

Do not perform local codebase profiling as part of PWNISMS. Profiling happens server-side at project creation; the IDE only consumes the resulting guardrails.

If VibeReview is not reachable, proceed with the user-provided context and repository evidence, then clearly note that project guardrails could not be fetched.

---

## Phase 1 — Inputs to Gather

Collect these quickly before deep analysis:

- **Scope**: What is changing (feature, component, service, migration, PR)?
- **Assets**: What must be protected (PII, credentials, tokens, configs, accounts, workflows)?
- **Entry points**: How data enters/leaves (HTTP, queues, schedulers, CLI, webhooks, integrations)?
- **Trust boundaries**: Where data crosses users/services/networks/privilege levels?
- **Existing guardrails**: What shortlisted project-specific dos and don'ts apply (from Phase 0)?

If the user provided specific code, diffs, or architecture artifacts, prioritize those as primary evidence.

---

## Phase 2 — Lightweight Workflow (PWNISMS)

1. **Clarify scope and assumptions** — define the unit of analysis; state assumptions about auth model, deployment boundary, tenant model, etc.
2. **Map assets and flows** — list high-value assets, entry points, and which assets are covered by existing guardrails.
3. **Walk all 7 PWNISMS categories** — identify plausible threats for each category and check if an existing guardrail already addresses each.
4. **Prioritize** — select the top 3-7 risks by impact and likelihood.
5. **Mitigate** — propose concrete, implementable controls and map them to specific guardrails.
6. **Summarize residual risk** — call out remaining risk, trade-offs, and follow-up actions, and note guardrail gaps.

---

## The 7 Categories (What to Check)

### P — Product

- Input validation, injection, insecure deserialization.
- Authorization gaps, privilege escalation, IDOR/BOLA.
- Business logic abuse, replay/race conditions, unsafe redirects.
- Error handling that leaks internals.
- **Guardrail check:** Are there `must` / `must_not` rules for input validation, authorization patterns, error handling?

### W — Workload

- Insecure container/runtime posture, over-privileged workload identity.
- Weak host/orchestrator controls and segmentation.
- Insecure data storage/backups and DB configuration.
- Queue/broker abuse and poison-message handling gaps.
- **Guardrail check:** Are there rules for container security, data-at-rest encryption, workload identity?

### N — Network

- Missing/weak TLS, insecure service-to-service communication.
- Exposed ports/endpoints and permissive ingress/egress.
- Weak segmentation or lateral movement paths.
- API-layer abuse controls missing (rate limits, request limits, CORS hardening).
- **Guardrail check:** Are there rules for TLS enforcement, CORS policy, rate limiting?

### I — IAM (Identity & Access Management)

- Broken authentication controls and token validation.
- Missing least-privilege RBAC/ABAC.
- Service-to-service auth gaps.
- Escalation paths across users, roles, or services.
- **Guardrail check:** Are there rules for auth mechanisms, session management, privilege boundaries?

### S — Secrets

- Secrets in code, images, logs, CI output, or defaults.
- Weak rotation, revocation, or token lifetime policies.
- Over-shared secrets across components.
- Missing secret manager/KMS controls.
- **Guardrail check:** Are there `must_not` rules against hardcoded secrets, `must` rules for secret manager usage?

### M — Monitoring (Logging & Observability)

- Missing logs for auth, authorization, admin/data access events.
- Sensitive data leakage in logs.
- Missing alerts for abuse indicators.
- Incomplete audit trails or weak log integrity.
- **Guardrail check:** Are there rules for what must be logged and what must not appear in logs?

### S — Supply Chain

- Unpinned/unverified dependencies and vulnerable packages.
- Third-party integration trust and scope overreach.
- CI/CD pipeline leakage or unreviewed build scripts.
- Unsigned/unprovenanced artifacts, missing SBOM.
- Treat AI-generated code as untrusted until validated.
- **Guardrail check:** Are there rules for dependency pinning, SBOM generation, artifact signing?
- **On-the-fly SCA:** If this task adds, upgrades, or imports any package, hand off to `.cursor/skills/osv-dependency-scan/SKILL.md` to scan the exact `name@version` against OSV.dev before the dependency is introduced. For HIGH/CRITICAL findings it auto-substitutes a re-scanned safe (fixed) version rather than blocking the flow, and records the avoided vuln in telemetry.

---

## Phase 3 — Guardrail Enforcement

After completing the PWNISMS analysis and before writing code:

1. Review the exact shortlisted guardrails produced by `.cursor/skills/guardrails-selection/SKILL.md`.
2. Classify applicability for the current task.
3. Apply during code generation:
   - `must` rules → mandatory implementation requirements.
   - `must_not` rules → hard prohibitions.
4. Flag conflicts — if a guardrail conflicts with an explicit user instruction, surface it.
5. Create `ide_generated` guardrails on the fly when PWNISMS reveals recurring patterns not captured by existing guardrails. Include `title`, `rule_type`, `category`, `instruction`, and rationale in the notes.

---

## Phase 4 — Security-First Code Generation Rules

When implementing code, enforce these baseline controls alongside project guardrails:

1. Validate and constrain all untrusted input.
2. Parameterize all queries and command-like invocations.
3. Enforce least privilege for users, services, and workloads.
4. Never hardcode secrets; use managed secret stores.
5. Encrypt sensitive data in transit and at rest.
6. Log security-relevant actions without leaking secrets/PII.
7. Pin and verify dependencies and build artifacts.
8. Return safe user errors; keep sensitive diagnostics internal.
9. Add abuse protections (rate limits, lockouts, throttling) on exposed interfaces.

---

## Phase 5 — VibeReview Sync (Post Threat Modelling)

After every threat-modelling step that produces or modifies threat content, the main agent must write a new `.vibereview/scans/*.json` structured scan artifact for the current prompt event and upload only that artifact (CLI `vibereview sync --file <path-to-this-json>` or MCP segmented tools per the vibereview-sync SKILL).

Triggers:

- New threat model generated (any form: scenarios, data flows, attack trees, PWNISMS analysis)
- Existing threat model updated or extended
- Guardrails applied during a code-generation task
- Security-relevant follow-up prompt in the same IDE chat

Do not call sync before implementation is complete unless the user explicitly asked only for threat modelling/design output.

Required content in the JSON artifact:

- Threat model findings (PWNISMS categories, severities, mitigations applied)
- Best practices achieved
- Secure code snippets (real code with paths where applicable)
- Guardrails applied — both `existing` (shortlisted from `vibereview_get_guardrails`) and `ide_generated`
- Session metadata (`chat_session_id`, stable `workflow_name`, prompt-specific `title` / `summary`)

How to sync:

1. Read and follow `.cursor/skills/vibereview-sync/SKILL.md`.
2. Write `.vibereview/scans/<chat_session_id>-<slugified-title-or-event-name>.json` for this prompt event.
3. Use the same `chat_session_id` for follow-up prompts in the same IDE chat, and generate a new `chat_session_id` for a new chat or unrelated workflow.
4. Prefer `vibereview sync --file <path-to-this-json>` from the project root, or call MCP tools in order (`vibereview_ctm_structured_start` … `vibereview_ctm_structured_finalize`).
4. If sync fails, leave the artifact on disk and report the failure clearly.

---

## Post-Generation Checklist

- [ ] Scope, assumptions, and trust boundaries were explicit.
- [ ] All 7 PWNISMS categories were checked (or marked N/A explicitly).
- [ ] Top risks were prioritized by impact and likelihood.
- [ ] Mitigations are concrete and actionable.
- [ ] Residual risk and follow-up actions are stated.
- [ ] Guardrails were fetched and enforced (all applicable `must`/`must_not` rules satisfied).
- [ ] Guardrail compliance summary is included in the response (existing + IDE-generated).
- [ ] The VibeReview JSON scan artifact was written under `.vibereview/scans/` and synced successfully (`vibereview sync --file <path-to-this-json>` or MCP segmented tools).

If ANY box cannot be checked, flag the gap to the user with a specific remediation recommendation before finalizing the code.
