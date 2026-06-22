---
name: guardrails-selection
description: Analyze the developer request, infer the security categories and likely threats involved, shortlist the most relevant project guardrails, then preserve the exact returned guardrail records before implementation. Use for every security-relevant code task before code is written and preserve the shortlist for the final VibeReview sync.
---

# Guardrails Selection

Configured VibeReview project: `Security TooL`
Project slug: `security-tool`
Project id: `e00ccc4a-3cb0-4288-a2fa-57703efa93e8`

Use this skill whenever code will be created or modified and the task has any security surface.

This skill is a hard pre-write gate. Do not write, edit, patch, or generate implementation code until this skill has produced the active guardrail shortlist and the PWNISMS skill has used that shortlist for threat modelling.

## Follow-Up Prompt Rule

Run this skill for each security-relevant prompt, even when the prompt is a continuation of an existing IDE chat that already produced a VibeReview scan event.

Previous guardrail work can inform your thinking, but it does not exempt the new prompt. If the follow-up changes or adds APIs, endpoints, auth/authorization, data access, untrusted input/output, secrets, network calls, infrastructure, dependencies, agent/MCP tools, logging, monitoring, or any trust boundary, create a fresh shortlist for this prompt before coding.

For the final sync, the event should reuse the existing `chat_session_id` only for grouping. It still needs a new prompt-specific `title` and a new artifact describing this prompt's guardrails and implementation.

The workflow:

1. Understand the request deeply.
2. Infer which security categories are in play.
3. Predict the threats that might occur for this exact task.
4. Shortlist only the guardrails that mitigate those threats.
5. Preserve the exact shortlisted guardrails returned by `vibereview_get_guardrails`.
6. Carry that same shortlist forward into implementation and the final VibeReview structured JSON sync.

Do not skip the analysis step. Do not rely on title-matching alone. Do not dump every guardrail into the final answer.

## Inputs You Must Analyze First

Before calling `vibereview_get_guardrails`, extract the actual development intent from the prompt and surrounding code:

- What is being built, changed, fixed, or refactored?
- Which components are affected: API, UI, background jobs, auth flow, webhook, file upload, admin tooling, AI agent flow, infra code, data pipeline?
- Which trust boundaries are crossed?
- Which sensitive assets are touched: tokens, credentials, sessions, PII, tenancy boundaries, audit logs, secrets, internal APIs, signed URLs, payment state, workflow approvals?
- Which technologies and patterns are involved in the existing code?
- What abuse cases are plausible if this change is implemented poorly?

You are not only selecting guardrails for the obvious functionality. You are selecting guardrails for the threats that might materialize around that functionality.

## Category Inference Workflow

Derive a category set for the task before shortlisting guardrails. Common categories include `authentication`, `authorization`, `session_management`, `input_validation`, `output_encoding`, `secrets`, `cryptography`, `logging`, `monitoring`, `file_uploads`, `deserialization`, `data_access`, `rate_limiting`, `network`, `client_side`, `business_logic`, `tenant_isolation`, `admin_workflows`.

Use both the user request and the codebase patterns to infer the category set. A task can involve multiple categories even if the prompt mentions only one feature.

## Threat Mapping Requirement

After identifying categories, infer the threat families that might occur. The shortlist should be threat-led, not catalog-led. At minimum, consider whether the task can create:

- authentication bypass
- authorization bypass
- privilege escalation
- information disclosure
- repudiation gaps
- denial of service
- unsafe client-side trust
- insecure logging or audit gaps
- injection-triggered security failures
- serialization-triggered security failures
- business-logic-triggered bypasses

## Guardrail Selection Procedure

### Step 1: Resolve the project and load the catalog

1. Call `vibereview_get_tenant_project` with `project_id="e00ccc4a-3cb0-4288-a2fa-57703efa93e8"` (or `project_slug="security-tool"`) to confirm the tenant-visible project.
2. Call `vibereview_get_guardrails` against that project.

Treat `vibereview_get_guardrails` as the authoritative project catalog. The returned entries already are the canonical guardrail records; shortlist from those exact records and preserve their ids, titles, rule types, categories, and instructions.

### Step 2: Build a shortlist

Shortlist guardrails using all of the following:

- direct category match with the task
- mitigation value against the likely threats you inferred
- relevance to the technologies and code paths being touched
- support for adjacent controls that prevent bypass chains
- duplication removal

Do not select a guardrail only because it sounds generally useful. Select it because it materially constrains the risky part of the current task.

### Step 3: Preserve exact shortlisted guardrails

For every shortlisted existing guardrail, preserve the exact guardrail record returned by `vibereview_get_guardrails`. Implementation must be driven by that exact shortlist, not by vague memory from the broad catalog listing. Do not re-query guardrails after implementation starts unless the shortlist is missing or the task scope materially changes.

### Step 4: Track the active shortlist in context

Maintain an explicit in-context list of the shortlisted existing guardrails that will govern the task. For each shortlisted existing guardrail, keep:

- `id`
- `title`
- `rule_type`
- `category`
- `instruction`
- `requires_approval` (from the tool response)
- `why_selected`

Also track any new guardrails created during the task as `ide_generated`.

This shortlist is the source of truth for the rest of the session.

### Step 5: Human-in-the-loop approval gate (MANDATORY)

Before writing any implementation code, scan your shortlist for entries where `requires_approval: true`. This flag comes from the server based on the project's `approval_mode` ('critical' or 'always') combined with the guardrail's category. **You cannot opt out of this gate, even under allow-all / auto-edit / YOLO modes** — those modes govern file editing, not security policy decisions.

If your shortlist contains zero entries with `requires_approval: true`, skip this section and proceed to Implementation Rules.

Otherwise, **STOP** and present the flagged guardrails to the user in exactly this shape, then wait for an explicit response before writing any code:

```
The following N guardrail(s) require your approval before I proceed:
 1. <title> [<category>, <rule_type>] — <one-line instruction>
 2. <title> [<category>, <rule_type>] — <one-line instruction>
 ...
Reply 'approve all' to proceed with every one, or list which to approve / reject (e.g. 'approve 1, 3; reject 2').
```

Wait rules:

- Treat silence, ambiguous replies, or anything other than `approve` / `yes` / `go ahead` / `approve all` (or an explicit per-item list) as NOT approved.
- Apply only the guardrails the user explicitly approves.
- If the user rejects a `must` or `must_not` guardrail that protects against a real risk in this task, tell them you cannot safely proceed and stop. Do not silently implement the insecure path.
- Record the user's decision (approved / rejected per guardrail) in the in-context shortlist so the final VibeReview sync can faithfully report which guardrails were applied and which were skipped at the user's instruction.

Do not skip Step 5. It is not optional in `critical` / `always` modes, and the `instructions` field in the `vibereview_get_guardrails` response repeats this same protocol.

## Implementation Rules

Once the exact shortlist is preserved:

- Every applicable `must` guardrail is mandatory.
- Every applicable `must_not` guardrail is a hard prohibition.
- If two shortlisted guardrails appear to conflict, explain the conflict and resolve it before coding.
- If the task reveals a real gap not covered by the shortlisted existing guardrails, create an `ide_generated` guardrail and apply it immediately.

When deciding whether a guardrail applies, prefer security-preserving inclusion over risky omission. If it plausibly mitigates a realistic path to abuse for the current task, keep it in scope.

## VibeReview Sync Contract

The final sync step must reuse the shortlist from this skill. It must not call `vibereview_get_guardrails` again unless the task scope materially changed.

Before structured scan sync, ensure the main agent context clearly contains:

- the exact existing guardrails shortlisted earlier
- which of them were applied
- whether each one was satisfied
- any notes about partial compliance, conflicts, or rationale
- every `ide_generated` guardrail created during the task

If a guardrail was shortlisted but not fully satisfied, still include it in the handoff with `satisfied: false` and a note. Do not silently drop it.

For every shortlisted **existing** guardrail in `guardrails_applied`, set `source: "existing"` and copy **`guardrail_id`** (or `id`) verbatim from the `vibereview_get_guardrails` response. The server rejects `source: existing` rows without a project guardrail UUID. Use `source: "ide_generated"` only for net-new rules created during the task (no `guardrail_id`).

## Selection Quality Bar

A good selection does all of the following:

- covers the feature's real threat surface, not just its visible functionality
- captures adjacent controls that stop bypass chains
- avoids irrelevant noise
- produces a small, defensible set of guardrails that can actually guide implementation
- leaves the final VibeReview scan artifact with an exact list of what the IDE selected and enforced
