---
name: vibereview-sync
description: Write and synchronize a structured VibeReview JSON scan artifact under .vibereview/scans/ for the current security-relevant session. Use only after guardrail selection, PWNISMS threat modelling, and guardrail-enforced implementation are complete.
---

# VibeReview structured scan sync (JSON)

Configured VibeReview project: `Security TooL`
Project slug: `security-tool`
Project id: `e00ccc4a-3cb0-4288-a2fa-57703efa93e8`

Use this skill when threat modelling output exists or security guardrail compliance must be synchronized to VibeReview.

Author a **single JSON object per prompt event** (not markdown). The ingest path is permissive: unknown top-level keys may be preserved under server metadata. Prefer matching field names from `schemas/scan-artifact-v1.json` in `@securityreviewai/vibereview`.

For coding tasks, do not use this skill until: guardrail selection → PWNISMS threat modelling → implementation → structured scan sync.

## Core rules

1. Write the artifact under `.vibereview/scans/` as `*.json`.
2. Author JSON from the **current task context only**.
3. Do not read other artifacts in `.vibereview/scans/` to infer structure or merge state from other sessions.
4. Stable file name: `.vibereview/scans/<chat_session_id>-<slugified-title-or-event-name>.json`.
5. Include `chat_session_id`, `workflow_name`, and a prompt-specific `title` in every artifact.
6. For follow-up prompts with security impact, write a new artifact for the new prompt. Reuse the same `chat_session_id` only for grouping; do not update or overwrite the previous event artifact.

## Scan grouping contract

- `chat_session_id` is the stable grouping key for the IDE chat. Reuse the exact same value for follow-up prompts in the same chat so VibeReview stores them as new events under the same scan.
- Generate a new `chat_session_id` for a new IDE chat or unrelated workflow so VibeReview creates a new scan.
- `workflow_name` is the scan-level title. Keep it short and stable for the whole chat, such as `Checkout authorization` or `Webhook hardening`.
- `title` is the event-level title for the current prompt/feature. It must describe this specific change, such as `Add ticket ownership check` or `Harden webhook signature validation`; do not reuse the same generic title for every event.
- Each security-relevant follow-up prompt needs its own event artifact and sync, even if the implementation seems small.

## MCP completeness contract (read this carefully)

The server stores **only** what MCP tool calls send. A perfect `*.json` on disk is **ignored** until it is mirrored in those calls.

Rules:

- **Canonical source:** The file you authored is authoritative. Never paraphrase, summarize, or drop fields because of “token pressure”—if a tool body would be huge, split work across multiple `vibereview_ctm_structured_patch_event` calls or multiple `vibereview_ctm_structured_add_snippets` / `vibereview_ctm_structured_add_guardrails` / `vibereview_ctm_structured_add_owasp` batches (each PATCH **appends** list rows server-side).
- **Threat rows:** Copy `threat_name`, `description`, `severity`, `mitigation_applied` verbatim for every threat in the artifact. All threats must arrive via `vibereview_ctm_structured_patch_event` (possibly several calls).
- **Best practices:** Send every row (strings become objects server-side only if emitted as primitives; prefer objects from the schema when possible). Prefer `vibereview_ctm_structured_patch_event` for bulk practice rows when they are concise.
- **Snippets:** If `secure_code_snippets` is non‑empty in the file, ensure **every** snippet object reaches the server via `vibereview_ctm_structured_patch_event` and/or **`vibereview_ctm_structured_add_snippets` with `items`**. Omitting snippets because they were “shown in chat” is a failure condition.
- **Guardrails:** Same—for every artifact row use `vibereview_ctm_structured_add_guardrails` (chunked `items`) and/or `vibereview_ctm_structured_patch_event` with **full** `title`, `rule_type`, `instruction` (when present), `source`, `satisfied`, `notes`, `guardrail_id` / `id` as authored.
- **OWASP mappings:** If `owasp_mappings` is non‑empty, call `vibereview_ctm_structured_add_owasp` (chunked `items`) and/or `vibereview_ctm_structured_patch_event` with the **full** list of mappings.
- **Pre-finalize checklist (mandatory):** Before `vibereview_ctm_structured_finalize`, confirm **cumulative rows** from all PATCH and append calls matches the artifact: same count (and same substantive content) for `threats_mitigated`, `best_practices_achieved`, `secure_code_snippets`, `guardrails_applied`, and `owasp_mappings`. If counts do not match, send another PATCH or append call—**never** finalize while telling the user the sync succeeded if any non-empty artifact array was not fully mirrored.
- **`vibereview_ctm_structured_finalize` last:** Run only after the checklist passes.

## Recommended JSON shape

At minimum, include: `schema_version` (e.g. `1`), `chat_session_id`, `workflow_name`, `title`, `summary`, `metadata` (optional object), plus arrays as applicable:

- `threats_mitigated` — list of objects (`threat_name`, `description`, `severity`, `mitigation_applied`, …)
- `best_practices_achieved`
- `secure_code_snippets` — `language`, `code`, `explanation`, optional `file_path`
- `guardrails_applied` — for `source: "existing"`: **`guardrail_id`** (UUID from `get_guardrails`), plus `title`, `rule_type`, `instruction`, `satisfied`, `notes`; for `ide_generated` omit `guardrail_id`
- `owasp_mappings` — `category_id`, `category_name`

Extra properties on row objects are allowed; non-object array elements may be handled specially for practices only—prefer object-shaped rows when possible.

## How to upload — read this carefully

**Option A — CLI (recommended for the current whole file):** run `vibereview sync --file <path-to-this-json>` from the repo root (manifest + gzip upload for only this artifact). If the `vibereview` binary is not installed in the current environment, run `npx -y @securityreviewai/vibereview sync --file <path-to-this-json>` instead.

Do **not** run plain `vibereview sync` for this workflow unless the user explicitly asks to drain the whole local queue; plain sync walks every JSON file in `.vibereview/scans/`. If retrying this event after a failed, empty, or partial ingest, run `vibereview sync --file <path-to-this-json> --force` (or `npx -y @securityreviewai/vibereview sync --file <path-to-this-json> --force`) so the server re-uploads only this artifact body even when the same artifact hash was seen before.

**Option B — MCP (segmented, small payloads):** call tools in order so each request stays bounded; completeness over brevity.

**The JSON file you write to disk is NOT what the server stores on the MCP path.** The server only stores what you push through the segmented MCP tools below. If you write 4 threats into the JSON but never call `vibereview_ctm_structured_patch_event` with `threats_mitigated`, the server's record will show 0 threats.

You MUST call every tool that corresponds to a non-empty array in your JSON. The mapping is fixed:

| JSON field on disk | Tool that pushes it | Notes |
|---|---|---|
| `title`, `summary`, `description`, `severity`, `developer_name`, `developer_email` | `vibereview_ctm_structured_patch_event` | Scalar fields. Send in one patch_event call. |
| `threats_mitigated` (array) | `vibereview_ctm_structured_patch_event` | Pass as the `threats_mitigated` parameter on the patch_event call. **Do not skip this if your JSON has threats.** |
| `best_practices_achieved` (array) | `vibereview_ctm_structured_patch_event` | Pass as the `best_practices_achieved` parameter on the same patch_event call. |
| `secure_code_snippets` (array) | `vibereview_ctm_structured_add_snippets` | One call per chunk. `items` = the array. |
| `guardrails_applied` (array) — and any other guardrail-shaped array you authored (e.g. `ide_generated_guardrails`, `guardrails_existing_shortlist_snapshot`) | `vibereview_ctm_structured_add_guardrails` | **Combine all guardrail-shaped arrays into one `items` list** before pushing. Server stores one `guardrails_applied` set per event. |
| `owasp_mappings` (array) | `vibereview_ctm_structured_add_owasp` | One call. **Do not skip this if your JSON has any OWASP entries.** |

1. `vibereview_ctm_structured_start`: begin segmented upload (`artifact_hash` required).
2. `vibereview_ctm_structured_patch_event`: (`event_id`) scalars (`title`, `summary`, …) plus **verbatim** rows for `threats_mitigated`, `best_practices_achieved` from the authored JSON (**no summaries**). Optionally **full** `secure_code_snippets`, `guardrails_applied`, `owasp_mappings`; else use step 3. Multiple PATCH calls **append**—use repeated PATCH/`items` calls for large payloads instead of shortening text.
3. `vibereview_ctm_structured_add_snippets` / `vibereview_ctm_structured_add_guardrails` / `vibereview_ctm_structured_add_owasp`: **required whenever** step 2 did not already send **every** row from the artifact arrays (chunk `items` per call); call each endpoint at least once with a non-empty `items` array **or** omit only if step 2 already included the full arrays.
4. `vibereview_ctm_structured_finalize`: **only after** cardinality matches the artifact (same counts/threat/snippet/guardrail/OWASP rows as file); then pass `scan_id`.

See **MCP completeness contract** above: the artifact is not synced until tools carry **every** row.

## Required call sequence

1. `vibereview_ctm_structured_start` — pass `artifact_hash` (SHA-256 of the JSON file bytes), `chat_session_id`, and `workflow_name`. Capture the returned `scan_id` and `event_id`.
2. `vibereview_ctm_structured_patch_event` — **always call this once**, even if you only have the scalar fields. Include `threats_mitigated` and `best_practices_achieved` here if your JSON has them.
3. `vibereview_ctm_structured_add_snippets` — call **only if** your JSON has `secure_code_snippets`. Pass the array as `items`. Chunk if > 25 items.
4. `vibereview_ctm_structured_add_guardrails` — call **once with the combined guardrails array** (shortlist + ide_generated, both go here). Chunk if > 25 items.
5. `vibereview_ctm_structured_add_owasp` — call **only if** your JSON has `owasp_mappings`. Pass the array as `items`.
6. `vibereview_ctm_structured_finalize` — pass the `scan_id` from start.

## Pre-finalize mandatory checklist

Before calling `vibereview_ctm_structured_finalize`, mentally walk this list. **Do not finalize until every applicable item is confirmed:**

- [ ] I called `vibereview_ctm_structured_start` and have the server-issued `scan_id` and `event_id`.
- [ ] I called `vibereview_ctm_structured_patch_event` with the scalar fields.
- [ ] If `threats_mitigated` exists in my JSON, I included it in the `vibereview_ctm_structured_patch_event` call.
- [ ] If `best_practices_achieved` exists in my JSON, I included it in the `vibereview_ctm_structured_patch_event` call.
- [ ] If `secure_code_snippets` exists in my JSON, I called `vibereview_ctm_structured_add_snippets` with the full array (chunked if needed).
- [ ] If any guardrail-shaped array exists in my JSON, I called `vibereview_ctm_structured_add_guardrails` with the combined array.
- [ ] If `owasp_mappings` exists in my JSON, I called `vibereview_ctm_structured_add_owasp` with the full array.

If any checkbox is unchecked because the corresponding tool errored, report the error to the user and **do not call finalize** — the JSON on disk will be batch-uploaded by the SessionStart hook on the next IDE session.

## Validation checklist (content)

- File is under `.vibereview/scans/`, valid JSON, root is an object.
- You did not read sibling scan files in `.vibereview/scans/`.
- Threats, snippets, guardrails, and OWASP sections reflect **this** session's work only (grounded, not invented).
- Guardrails handoff includes every shortlisted existing rule and every `ide_generated` rule, with honest `satisfied` / `notes`.
- MCP path: pre-finalize **cardinality** checklist passed (arrays in file ≡ rows delivered to API).
- If upload fails, leave the JSON on disk and report the error.

## Final step

After validation, sync via **CLI** or **MCP** as above. Prefer **`vibereview sync --file <path-to-this-json>`** when the payload is large; use segmented MCP only when you will honor the completeness contract. If you use MCP, call `vibereview_ctm_structured_finalize` with the `scan_id` from start, do not claim success until `finalize` returns OK **and** the checklist passed, and report back the counts you pushed: `threats: N, snippets: M, guardrails: K, owasp: L`. If finalize errors, leave the JSON on disk under `.vibereview/scans/` and report the error.
