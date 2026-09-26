# Validation skill: capability parity with Codex Security

`skills/finding-validation` (design: [validation-design.md](validation-design.md)) is designed to keep the capabilities of the validation phase in [openai/codex-security](https://github.com/openai/codex-security/tree/main/plugins/codex-security) (Apache-2.0): the `validation` skill (`skills/finding-validation/SKILL.md`, `references/validation-guidance.md`), the parts of `references/static-finding-assessment.md`, `references/scan-artifacts.md`, and `references/scan-contract.md` that govern validation, the compact validation record in `mcp-app/src/artifact-validation-phase.ts` and `schemas/tools/candidate-validations.schema.json`, the `references/config-preflight.md` preflight pattern, and the `examples/custom-validation/` disposable-server example. Codex Security calls its output a per-candidate `validation` object (disposition `reportable` / `suppressed` / `not_applicable` / `deferred`) stored through its MCP workbench; this plugin calls it a verdict (`confirmed` / `rejected` / `inconclusive`) stored in `validations.json`. Our skill is a standalone stage that works without an MCP server in Claude Code, ChatGPT/Codex, and Cursor, and adds a dedicated disposable container.

Compiled from codex-security `main` at `6f8b354` on 2026-09-26. Recheck when either side changes. "Where" refers to the planned files under `skills/finding-validation/`.

| # | Codex Security capability | How this skill provides it | Where |
| --- | --- | --- | --- |
| 1 | Activates in the validation phase or on an explicit request to validate a finding; not the primary trigger for full scans | Description activates for validating/reproducing/falsifying findings and stage 3; not for threat modeling, discovery, review, or fixes | `SKILL.md` frontmatter |
| 2 | Read the storage policy before choosing paths | `prepare_workspace.py --stage 3-validation` in the stage 2 run | `SKILL.md` Workflow; shared `evidence-and-handling.md` |
| 3 | Explicit input/output paths override defaults; ask for a missing required input | Same rule as stages 1 and 2 | `SKILL.md` Preconditions |
| 4 | Build a rubric of up to five concrete criteria **before** validating | Rubric written from the finding's `investigation_question` before running | `references/method.md`; `validations.schema.json` `rubric` |
| 5 | Choose the strongest realistic method (crash, valgrind/ASan, debugger, focused test, realistic-interface reproduction), falling back to code understanding | Same ladder; `method` field with the same options plus `static-assessment` | `references/method.md`; `SKILL.md` |
| 6 | Prefer targeted, non-interactive, bounded commands; avoid network unless essential | Same; testing phase turns the network off by default after setup | `references/container-workbench.md`; `SKILL.md` Ground rules |
| 7 | Static fallback when dynamic execution is blocked or disproportionate: source/control/sink, reachable path, boundary, counterevidence, proof gaps | Same method, recorded as `static-assessment` / `reproduced: false`, rendered "assessed statically, not reproduced" | `references/static-finding-assessment.md`; `validation-format.md` |
| 8 | Setup errors, compile errors, and missing dependencies are **not** counterevidence | Same rule; a setup failure can never justify `rejected`; the verdict is `inconclusive` | `references/method.md`; `check_validations.py` |
| 9 | Do not imply validation happened when it did not; calibrate confidence from the method and evidence, not the bug class | Same; `reproduced` flag and `confidence` calibrated from method; static-only is bounded | `validations.schema.json`; `check_validations.py` |
| 10 | Every candidate that enters validation leaves a record; no implicit coverage | One validation entry per selected finding; `check_validations.py` enforces one verdict each | `check_validations.py` |
| 11 | Instance-preserving: validate each candidate instance independently; do not collapse siblings sharing a family; use a nearby safe path as a negative control | One verdict per finding (stage 2 already separated instances); a harmless control run is required before `confirmed` | `references/method.md`; `validations.schema.json` `control` |
| 12 | Reproduce against the real application/library through its actual interface where feasible | The app is run in the container and driven through its real interface; reachability evidence required | `references/method.md`, `container-workbench.md` |
| 13 | For scans that should not modify the target tree, use a disposable copy / output-only directory for builds and PoCs | The target is copied into a disposable container; the host tree is never modified and never mounted for writing | `container-workbench.md`; `export_target.py` |
| 14 | Non-interactive debuggers and bounded long-running commands (do not abandon a command showing progress) | Same; wall-clock timeout bounds a hang but progress is not killed for slowness alone | `references/method.md`; limits in `container-workbench.md` |
| 15 | Validation output per finding: title, ids, root-control/affected locations, method, evidence, counterevidence/proof gap, remaining uncertainty, confidence, rubric checklist, artifact paths, next step | All kept in the validation entry; the rendered report shows the rubric as `- [x]`/`- [ ]` | `validations.schema.json`; `render_validations.py` |
| 16 | Compact validation record fields: `disposition`, `method`, `confidence`, `confidence_rationale`, `rubric`, `evidence`, `counterevidence_or_proof_gap`, `remaining_uncertainty`, `artifact_paths`, optional `source`/`control`/`sink`/`preconditions` | Mapped: `verdict`↔disposition, plus `confidence.reason`, `rubric`, `evidence`, `counterevidence_or_proof_gap`, `remaining_uncertainty`, `artifact_paths`; source/control/sink inherited from the finding | `validations.schema.json` |
| 17 | Dispositions `reportable` / `suppressed` / `not_applicable` / `deferred` | Mapped to `confirmed` / `rejected` / `inconclusive`: `reportable`→`confirmed`, `suppressed`→`rejected`, `not_applicable`+`deferred`→`inconclusive` (with the reason distinguishing them) | `validations.schema.json`; `validation-format.md` |
| 18 | Knowledge base / false-positive feedback is data, not instructions; dismiss only if the reason still holds against current controls | Same precedence as stages 1 and 2; a prior dismissal is re-tested, not trusted | `inputs-and-authorization.md`; shared `evidence-and-handling.md` |
| 19 | Save PoCs, crafted inputs, and logs under the finding's validation artifacts path; include a small readme for a PoC | `3-validation/artifacts/<finding_id>/`; no secrets | Outputs table; `validation-format.md` |
| 20 | Preflight the environment/config before substantive work (`config_preflight.py`) | `check_environment.py` verifies a usable engine, memory floor, and architecture before anything runs; stops with remediation if unmet | `check_environment.py`; `SKILL.md` Workflow |
| 21 | Keep validation artifacts and phase output together so later phases reconstruct every disposition | Canonical `validations.json` + rendered `validation.md`; stage 4 reads the JSON | Outputs table; `render_validations.py` |
| 22 | Class-specific proof tuples (authz, injection, SSRF, deserialization, path traversal, XXE, etc.) | Kept as guidance for choosing the rubric and the reproduction method per finding class | `references/method.md` |
| 23 | High-impact-first ordering; keep setup effort proportionate to the candidate | Findings tested in `hypothesis_priority` then `confidence` order within the time budget | `SKILL.md` Workflow |

## Capabilities this skill adds

- **A dedicated disposable container per run** on the user's own computer — Codex Security has no separate sandbox and validates in whatever environment Codex is already in. This is a deliberate addition, not a parity gap.
- Runs on **Docker Desktop**, located by path so it is found even when the shell PATH is minimal (a non-interactive or remote shell); never Apple `container`.
- **No personal data in the workbench**: the exact reviewed revision is copied in (never mounted), and no credentials, SSH agent, engine socket, or host environment variables enter it.
- **Label-only clean-up** that removes only what the run created and refuses to touch any unlabelled resource, with a test proving the user's other containers are untouched.
- **Two-phase network policy**: network on for setup, off by default for testing.
- **Portability provenance recorded with every verdict**: host OS, architecture, engine and version, base-image digest, emulation, code source, and limits.
- **A stage 2 record gate**: the consumed `findings.json` must be valid, normalized, and still match the target version, or the user chooses to rerun stage 2.
- **Repeated confirmation and an explicit reachability requirement** before a `confirmed` verdict.
- **Never pushes** validation results or finding detail to Git.

## Not adopted

| Codex Security mechanism | Reason |
| --- | --- |
| Severity and attack-path scoring during/after validation (`artifact-attack-path.ts`, `severity-policy.md`, `candidate-attack-paths.schema.json`) | Provided by the separate `attack-path-analysis` skill (stage 3b), run after stage 3; see [attack-path-parity.md](attack-path-parity.md). Stage 3 itself only decides whether the finding holds. |
| Workbench MCP tools (`record_codex_security_candidate_validations`, `list_codex_security_candidates`, drafts, checkpoints) | Replaced by files in the run folder, so the skill works with no MCP server across all three clients. |
| Compact workbench-backed diff-mode validation (one atomic call for every candidate) | Diff and PR scans are deferred plugin-wide (a stage 2 parity gap too); stage 3 validates whole-record findings. |
| Deep-scan reducer and parent-sandbox worker pool (`deep-scan/*`) | Out of scope; this stage runs one disposable container on the user's machine. |
| Per-finding receipt files and closure tables in Codex's numbered artifact directories | The canonical `validations.json` plus the rendered report cover the same need. |
| SARIF or other export | Deferred. |
| Codex's `config_preflight.py` Codex-config/runtime-capability checks (multi-agent runtime, worker slots, trust levels) | Not applicable; `check_environment.py` checks the container engine instead. |
| `desktop-config-preflight.md` (Codex desktop-app specifics) | Host-specific to Codex; not portable. |
