# Patch preparation: capability parity with Codex Security

`skills/patch-preparation` (design: [patch-preparation-design.md](patch-preparation-design.md)) is designed to keep the capabilities of the fix phase in [openai/codex-security](https://github.com/openai/codex-security/tree/main/plugins/codex-security) (Apache-2.0): the `fix-finding` skill and the parts of `references/scan-contract.md` and `references/scan-artifacts.md` that govern preparing and verifying a fix. Codex Security calls its output a fix with outcome `fixed` / `no_change` / `blocked`; this plugin calls it a patch record (`patches.json`) with a per-patch outcome, and works without an MCP server in Claude Code, ChatGPT/Codex, and Cursor. Codex Security's separate `assess-patch-risk` skill (merge eligibility) maps to this workflow's **stage 5** (human review and change proposal), not stage 4; it is not adopted here.

Compiled from codex-security `main` on 2026-09-27. Recheck when either side changes. "Where" refers to files under `skills/patch-preparation/`.

| # | Codex Security capability (`fix-finding`) | How this skill provides it | Where |
| --- | --- | --- | --- |
| 1 | Activates only on an explicit request to fix and verify a validated or plausible security finding; not for ordinary bug fixes, general validation, or full scans | Same triggers and exclusions in the description; stage 4 of the workflow | `SKILL.md` frontmatter |
| 2 | Judgment order: correct classification, then a complete fix of the boundary, then preserved legitimate behaviour, then repository checks, then conventions, then minimal scope — never traded in reverse | The same six-point judgment order | `references/method.md` "Judgment order" |
| 3 | Key inputs: the affected implementation and callers, existing tests, evidence of attacker-controlled input, the source-to-sink path, the invariant, and legitimate behaviour | Consumed from the stage 3b analysis (`root_control` locations, severity), the stage 3 reproduction, and the stage 1/2 records, by reference | `references/inputs.md`; `scripts/start_patches.py` |
| 4 | Pre-patch investigation with a fresh read-only agent (or an independent pass) to establish the path, boundary, entry points, legitimate workflows, and conventions | Same, host-neutral ("a sub-agent when the client offers one; otherwise a stated second pass") | `references/method.md` "Investigate before patching" |
| 5 | Implementation: trace the path; `no_change` if already safe; run the reproduction plus a legitimate control; implement a minimal repository-native fix at the shared boundary; challenge it against all callers and both condition outcomes | The same steps, in order | `references/method.md` "Prepare the fix" |
| 6 | Verify in an ordered sequence: syntax/build/type; the security trigger and alternate malicious inputs; the legitimate control, existing tests, and package checks | The five ordered verification gates, every one must pass for `fixed` | `references/method.md` "The verification gates"; `scripts/check_patches.py` (`check_outcome`) |
| 7 | Patch-candidate review with a fresh read-only agent: surviving routes, equivalent representations, broken legitimate input, public-contract or state changes | Recorded in each patch's `candidate_review` | `references/method.md` "Review the patch candidate"; schema `candidate_review` |
| 8 | Require focused tests; code inspection alone is insufficient for a fix | `fixed` requires a non-empty `tests_added`; enforced | `check_patches.py` (`check_outcome`) |
| 9 | Do not report `fixed` until every ordered gate passes | `fixed` requires every gate `result` to be `pass`; enforced | `check_patches.py` |
| 10 | Outputs: outcome, the vulnerable path and invariant, patch strategy, files changed, tests added, commands run grouped by gate, proof the issue no longer reproduces, proof legitimate behaviour is intact, remaining uncertainty | The `patches[]` entry fields: `outcome`, `vulnerable_path`, `security_invariant`, `patch_strategy`, `files_changed`, `tests_added`, `gates`, `reproduction_before`/`reproduction_after`, `legitimate_behavior`, `remaining_risk`, `confidence` | `assets/patches.schema.json`; `references/patch-format.md` |
| 11 | Do not broaden into cleanup or sibling findings; do not remove user changes; never weaken a control to pass tests; expose proof gaps | The same rules, plus: the diff is recorded and never applied to the working tree | `SKILL.md` Ground rules; `references/method.md` "Never" |
| 12 | Isolated worktree for developing and verifying the fix (the workbench remediation stages) | One disposable Docker container per run: the reviewed revision is copied in (never mounted), the fix is developed on the copy, and the diff is exported to `patches/`; label-only clean-up | `references/container-workbench.md`; shared `export_target.py`, `run_container.py`, `cleanup_run.py` |
| 13 | Every finding that enters the fix phase leaves a recorded outcome; no implicit coverage | Every reportable finding has a `patches[]` entry or is named in `coverage_gaps`; enforced for `complete` | `check_patches.py` |
| 14 | `agents/openai.yaml` UI metadata (display name, short description, default prompt) | Same file, validated by `scripts/check-package.py` | `agents/openai.yaml` |
| 15 | Explicit invocation and phase-based activation | Explicit invocation by skill name (`$patch-preparation` in Codex, `/defense-factory-plugin:patch-preparation` in Claude Code, the skill picker in Cursor) plus a description that activates for fix requests and stage 4 | `SKILL.md` frontmatter |

## Capabilities this skill adds

- **A dedicated disposable container per run** on the user's own computer, shared with stage 3 — Codex Security develops the fix in whatever environment Codex is already in.
- **A fourth outcome, `inconclusive`**, for a fix whose gates could not run (Codex folds this into `blocked`); a setup failure is never counterevidence and never `fixed`.
- **A stage 3b record gate**: the consumed `attack-paths.json` must be valid and still match the code, and only `reportable` findings are patched, in priority order (P0 first).
- **The diff is the deliverable and is never applied** to the user's working tree; applying it is stage 5.
- **Recorded run provenance** with every patch: host OS, architecture, engine and version, base-image digest, code source, limits, and the clean-up receipt.
- **Auto-run in `defense-factory-review`** (a deliberate divergence from Codex, whose `fix-finding` is opt-in): the review runs stage 4 after stage 3b when there is a reportable finding, because stage 4 only records diffs and never changes the tree. The skill is still invokable on its own.

## Not adopted

| Codex Security mechanism | Reason |
| --- | --- |
| `assess-patch-risk` (merge eligibility: `merge`/`revise`/`no_op`/`block`/`hold_for_evidence`, `auto_merge_candidate`/`human_review_required`) | Maps to stage 5 (human review and change proposal), not stage 4; deferred until stage 5 is built. |
| Workbench remediation-stage MCP tokens (`generate`/`apply`/`verify` via a scan ID and remediation token) | Replaced by files in the run folder and the disposable container, so the skill needs no MCP server across all three clients. |
| Applying or committing the fix to the repository | Out of scope for stage 4: the diff is prepared and recorded; applying it is stage 5, after human review. |
| Compact diff-mode fixing and deep-scan worker pools | Diff and PR scans are deferred plugin-wide; stage 4 fixes whole-record findings. |
| SARIF or other export | Deferred. |
