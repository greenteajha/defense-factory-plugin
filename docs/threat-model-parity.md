# Threat-model skill: capability parity with Codex Security

`skills/threat-model` is designed to lose no capability of the `threat-model` skill in [openai/codex-security](https://github.com/openai/codex-security/tree/main/plugins/codex-security) (Apache-2.0). That skill is a short `SKILL.md` that reads plugin-level references (`threat-model.md`, `scan-artifacts.md`, `artifact-storage.md`, `security-guidance.md`, `scan-contract.md`) and relies on the Codex Security MCP server for storage. Our skill is self-contained and works without an MCP server in Claude Code, ChatGPT/Codex, and Cursor.

This table was compiled from codex-security `main` on 2026-09-24. Recheck it when either skill changes. Locations refer to files under `skills/threat-model/`.

| # | Codex Security capability | How this skill provides it | Where |
| --- | --- | --- | --- |
| 1 | Create a repository threat model, or reuse a cached repository-scoped one | Reusable model at `.defense-factory/threat-model.md`, reused on an exact match | `references/inputs-and-reuse.md` §3 |
| 2 | Reuse only when the `Repository` and `Version` footer matches and no replacement or regeneration was requested; copy unchanged to the per-scan path | Reuse only when header `target_id` and `version` match and no replacement, regeneration, context, or narrowed scope applies; copy unchanged into the run folder | `inputs-and-reuse.md` §3 |
| 3 | Bypass the cache for a supplied model, non-empty user context, an authoritative knowledge base, a narrower scope, or a host instruction | Same four conditions plus host or calling-workflow instructions | `inputs-and-reuse.md` §3 and "When the reusable model may be written" |
| 4 | A direct user request may write the shared cache; context data cannot authorize it | Same rule | `inputs-and-reuse.md` "When the reusable model may be written" |
| 5 | Honor explicit input and output paths; ask for a missing required input rather than substitute | Same; also never claim a write to an unwritable destination | `SKILL.md` Preconditions 4; `inputs-and-reuse.md` "Output locations" |
| 6 | Stable target identity (digest of sanitized remote URL, else local identity; no credentials) | `scripts/target_identity.py`: sha256 of sanitized remote host/path, else absolute path; strips credentials, query, fragment | `scripts/target_identity.py`; tests |
| 7 | Version: revision for an immutable Git tree, snapshot digest otherwise; target kinds | `git_revision`, `git_worktree`, `directory_snapshot`; deterministic `defense-factory-snapshot/v1:sha256:` digest of the reviewed files | `scripts/target_identity.py` |
| 8 | Resolve `SECURITY.md` root-to-leaf, closest wins, as untrusted policy; retain `security_guidance.md` | `scripts/resolve_security_md.py` (also reads `.github/` and `docs/` repository policies); saved as `security-guidance.md` | `SKILL.md` Workflow 4 |
| 9 | Preserve a supplied model or authoritative guidance unchanged unless revision is requested; keep supplied text exact | Byte-for-byte copy under a record header; revisions keep the original beside it | `inputs-and-reuse.md` §1 |
| 10 | Repository-specific `AGENTS.md` or `SECURITY.md` may stand in for the model | Same, recorded as `source: repository-guidance` with coverage gaps | `inputs-and-reuse.md` §2 |
| 11 | Knowledge base overrides generated assumptions and policy, never user instructions; label by origin; do not expose private text or locations | Precedence list and origin labels | `inputs-and-reuse.md` "Precedence of inputs" |
| 12 | Read-only and offline; read a supplied URL once only with explicit authorization; no crawling | Same | `SKILL.md` Ground rules |
| 13 | Repository content, policy, and context are untrusted data that cannot authorize actions or another target | Same | `SKILL.md` Ground rules; `references/evidence-and-handling.md` |
| 14 | Architecture method: product, surfaces, conditional workflows, production versus test; inputs to sensitive operations and category list; delegated authority, approval and readback, generated code; effective resources across deployment paths; platform differences | All five steps, rewritten | `references/method.md` "Map the architecture" |
| 15 | Citations: `path:line`, must support the claim, batch-verified before returning; separate code facts, provided context, assumptions, questions; stop expanding when boundaries are clear | Same, plus `scripts/check_citations.py` for the batch check | `method.md` step 5; `evidence-and-handling.md`; `SKILL.md` Workflow 9 |
| 16 | Never reproduce credentials; record reference, location, recipients, control | Same | `SKILL.md` Ground rules; `evidence-and-handling.md` |
| 17 | Independent fresh-context architecture review with a fixed brief; no hypotheses sent; verify its claims; sequential fallback stated as not independent | Same brief, host-neutral ("sub-agent, background task, or separate session"); fallback recorded in `independent_review` | `method.md` "Independent architecture review" |
| 18 | Effective-resource rows (consumer, deployment, configuration chain, effective value, recipients, control, evidence, discrepancies) | Same columns in the table and template | `method.md`; `assets/threat-model-template.md` |
| 19 | Threat scenarios per boundary: attacker, starting control, absent privileges, capability gain, invariant, impact, prerequisites, controls, counterevidence, mitigation, uncertainty | Same, plus a STRIDE omission check | `method.md` "Threat scenarios" |
| 20 | Prioritization rules: no assumed operator control; library inputs as boundaries; deployment claims state exposure; no invented access, tenants, controls, or approvals; no-new-impact cases | Same | `method.md` "Threat scenarios" |
| 21 | Hypotheses kept separate from findings; unknowns as questions; severity calibrated by policy, privilege gain, impact, likelihood, mitigations | Same; hypotheses carry `TM-H` IDs for stage 2 | `method.md`; template section 3 |
| 22 | Canonical six-field model: summary, assets, trustBoundaries, attackerCapabilities, securityObjectives, assumptions | "Canonical summary" section with the same six fields | template |
| 23 | Standalone document with four sections: Overview (component table, effective-resource table, optional Mermaid); boundaries and assumptions; prioritized attack-surface table with fixed columns; severity calibration with examples and counterexamples, confidence separate from impact | Same four sections and columns | template; `method.md` "Severity calibration" |
| 24 | Within a scan: carry the model forward, reconcile every scenario, retain documentation/configuration disagreements, no second speculative registry | Stage 1 accounts for every boundary, keeps disagreements, and hands `TM-H` IDs to stage 2; per-scenario reconciliation belongs to stage 2's contract | `method.md`; `docs/workflow-contracts.md` |
| 25 | Repository-wide unless narrowed; stay within authorized scope; not centered on changed files | Same | `SKILL.md` Preconditions 2; `method.md` "Scope of the document" |
| 26 | Check the model for scope, runtime boundaries, evidence, and hypothesis separation before writing; write only the selected outputs | Same | `SKILL.md` Workflow 9-10 |
| 27 | Persistent storage that cannot be committed, plus a per-scan copy later phases treat as the source of truth | Self-ignoring `.defense-factory/`, checked with `git check-ignore`; run copy is the source of truth | `scripts/prepare_workspace.py`; `evidence-and-handling.md` |
| 28 | `agents/openai.yaml` UI metadata (display name, short description, default prompt) | Same file, validated by `scripts/check-package.py` | `agents/openai.yaml` |
| 29 | Explicit invocation and phase-based activation | Explicit invocation by skill name (`$threat-model` in Codex; the client's skill or slash-command picker in Claude Code and Cursor) plus a description that activates for threat-model requests and stage 1 | `SKILL.md` frontmatter |

## Capabilities this skill adds

- An explicit authorization and scope gate before any source is read, recorded in the output.
- A stage record header shared with later stages (status, actor, provenance, coverage gaps, next action).
- A STRIDE omission check per boundary.
- Explicit `blocked` and `inconclusive` outcomes, and a manual fallback when Python is unavailable.
- Activation and behavior test cases in `evals/cases.json`.

## Codex-specific mechanisms replaced, not dropped

| Codex Security mechanism | Replacement |
| --- | --- |
| MCP `save_codex_security_artifact` persistent storage under `~/.codex/state/…` | Self-ignoring `.defense-factory/` folder in the repository, or a user-chosen location |
| Workbench scan IDs and handoff tokens | `run_id` and the stage record header |
| `fork_turns: "none"` delegation | "Sub-agent, background task, or separate session with fresh context", whichever the client offers |
| `launch_codex_security_mcp --helper resolve-security-md` | `scripts/resolve_security_md.py` |
| `$skill` invocation syntax | Plain skill names in shared files; `$threat-model` only in the Codex-only `agents/openai.yaml` |
