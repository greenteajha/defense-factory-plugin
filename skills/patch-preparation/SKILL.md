---
name: patch-preparation
description: Prepare a minimal, tested fix for a Defense Factory finding that stage 3b rated reportable, as stage 4 of the workflow. Builds each fix inside one disposable container on the user's own computer, verifies it in an ordered gate sequence (build, the stage 3 reproduction now blocked, a legitimate-behaviour control, the target's own checks, minimal scope), reviews the patch candidate with fresh context, and records a diff plus evidence with a verdict of fixed, no_change, blocked, or inconclusive. The diff is recorded, never applied to the target tree. Use when the user asks to fix, patch, or remediate validated security findings, or to run stage 4 (patch preparation) of the Defense Factory workflow on its own. Do not use to build a threat model, discover findings, validate findings, rate their severity, review or merge a patch (that is stage 5), or fix an ordinary correctness bug that is not a validated security finding.
---

# Patch preparation

Take the findings that stage 3b (`attack-path-analysis`) rated **reportable** and prepare a minimal, tested fix for each, inside one disposable container per run on the user's own computer. Every fix is recorded as a **unified diff plus evidence**; the diff is never applied to the user's working tree. This is stage 4 of the Defense Factory workflow: it runs after attack-path analysis, before human review (stage 5, not implemented).

Each fix ends with an outcome of `fixed`, `no_change`, `blocked`, or `inconclusive`, earned by evidence, never by how simple the fix looks.

## Preconditions

1. **A container engine.** Run `scripts/check_environment.py` first. It must find Docker Desktop with a running daemon and enough memory. If a prerequisite is not met, stop before building anything and tell the user, for each entry in the `unmet` list, what is not met (its `prerequisite` and `problem`) and how to fix it (its `fix` steps, numbered, then its `verify` command). Never run the target on the host.
2. **A stage 3b record.** Start from the `attack-paths.json` that `scripts/find_attack_paths.py --root <target>` selects: the newest stage 3b run that is valid and still matches the code, found without asking (see [references/inputs.md](references/inputs.md)). If none is usable, say so and offer to run stage 3b first. Honor any input or output path the user names.
3. **Request, not a confirmation prompt.** Within the stage 3b run, carry its authorization forward; otherwise record the user's request, quoted (see [references/inputs.md](references/inputs.md#authorization)). If the user says they are not authorized, stop with status `blocked`.
4. **Eligible findings.** Only analyses with stage 3b decision `reportable` are patched. Prepare fixes for the findings the user names, or every reportable one, in priority order (P0 first). `deferred` and `ignore` analyses are listed under `not_eligible`, never patched.

## Ground rules

- **Everything runs in the disposable container, never on the host.** Copy the exact reviewed revision into the container with `scripts/export_target.py`; never mount the user's folders. Put no credentials, SSH agent, engine socket, or host environment variables inside it.
- **The diff is the deliverable; the target tree is never changed.** Develop and test each fix inside the container, then export it as a unified diff under `patches/`. Do not edit, stage, commit, or push anything in the user's working tree.
- **Minimal, repository-native fixes at the shared boundary.** Fix the root control the finding names, in the repository's own conventions. Do not broaden into cleanup, refactoring, or sibling findings, and never weaken a security control to make a test pass. Do not "fix" behaviour the resolved SECURITY.md policy marks as intended.
- **Label everything; clean up by label only.** Every container, image, volume, and network the run creates carries the run label. At the end, and after any failure, run `scripts/cleanup_run.py --run-id <run_id>`, which removes only resources carrying that label.
- **Two phases.** Setup with the network on to install prerequisites and build the app; then turn the network off for testing (`--network none`) unless a test needs a run-local sink on the run's own internal network.
- **Setup failures are never counterevidence.** If prerequisites will not install, the app will not build, or a gate cannot run, the outcome is `inconclusive`, never `fixed`. Record the proof gap.
- **No secrets, and nothing pushed to Git.** Never store credentials or secret values in the record, the diff, or the artifacts. Never push patches or finding detail to Git.

For evidence, uncertainty, and data-handling rules, read [references/evidence-and-handling.md](references/evidence-and-handling.md).

## Workflow

1. **Check the environment.** `scripts/check_environment.py`. Stop with its remediation if it is not ready.
2. **Locate and verify the stage 3b record.** `scripts/find_attack_paths.py --root <target>`; if none is usable, report why and offer to run stage 3b.
3. **Prepare output storage.** `scripts/prepare_workspace.py --root <target> --stage 4-patch-preparation --run-id <stage 3b run_id>`.
4. **Start the record.** `scripts/start_patches.py --root <target> --stage-dir <stage_dir> --attack-paths <path from find_attack_paths.py>` (add `--finding FD-n` for each finding the user named). It verifies the stage 3b record, selects the reportable findings, and writes a `patches.json` skeleton with `<fill: ...>` markers and `environment` null. It never overwrites an existing `patches.json`.
5. **Export the target and build the workbench.** `scripts/export_target.py --root <target> --scope <path> --out <stage_dir>/container-build --run-id <run_id>`, then build the workbench image with `scripts/run_container.py build --run-id <run_id> --tag <tag> --context <stage_dir>/container-build`. Record the base image and its digest and fill the `environment` block (see [references/container-workbench.md](references/container-workbench.md) for the layout, limits, and digest fallback).
6. **For each finding, in priority order** (see [references/method.md](references/method.md)):
   1. **Investigate before patching**, with a fresh read-only pass (a sub-agent when the client offers one; otherwise a stated second pass): the source-to-sink path, the shared enforcement boundary, the affected entry points and alternate representations, the legitimate workflows and public behaviour, and the repository conventions.
   2. **Trace the reported path.** If the current code is already safe, record `no_change` with the evidence and move on.
   3. **Run the stage 3 reproduction and a legitimate control first**, to establish the before-state baseline in the container.
   4. **Implement the smallest repository-native fix** at the shared boundary.
   5. **Verify in the ordered gate sequence** (see [references/method.md](references/method.md#the-verification-gates)): build/type check; the reproduction now blocked; the legitimate control still works; the target's own tests, lint, and any refactoring safety net; minimal scope. Every gate must pass for `fixed`. If a gate cannot run, the outcome is `inconclusive`.
   6. **Review the patch candidate** with fresh read-only context: surviving routes through the entry points, equivalent representations, and any legitimate input the fix would break.
   7. **Export the diff** to `patches/<FD>.patch` and save tests and logs under `tests/<FD>/` and `artifacts/<FD>/`. Record the outcome and its evidence in `patches.json`.
7. **Clean up.** `scripts/cleanup_run.py --run-id <run_id>`; confirm nothing labelled remains.
8. **Normalize, check, and render.** `scripts/normalize_patches.py <patches.json>`, then `scripts/check_patches.py --repo <repo root> <patches.json>`, fixing every problem and normalizing again until both pass; then `scripts/render_patches.py <patches.json>` and `scripts/check_citations.py --repo <repo root> <stage_dir>/patches.md`.

## Completion

The stage is `complete` when the environment was available, every reportable finding has a patch entry with the evidence its outcome requires, no outcome is `blocked` or `inconclusive`, both checks pass, and `cleanup_run.py` reports nothing labelled remaining. Report the path of `patches.md`, the status, outcomes by type, the engine and architecture used, and that all run resources were cleaned up. Suggest stage 5 (human review of the prepared patches) next, P0 first — and that the diffs are applied to the user's code only after that review.

## Failure conditions

- **`blocked`:** the user says they are not authorized, the stage 3b record is missing or stale with no retrievable revision, or no safe output location exists. Save the record only; build no container; `environment` stays null.
- **`inconclusive`:** the environment was unavailable or under-resourced, some findings could not be fixed or verified (setup blocked, root cause unclear, or not Linux-runnable), or the run stopped early. Keep every outcome reached; never present the result as exhaustive.
- **Clean-up left something behind:** report it as a stage failure and name the labelled resources that remain; never remove unlabelled resources to compensate.
- **Python or the engine unavailable:** if the engine is missing, stop `blocked` with the remediation. If Python is unavailable, follow the same rules by hand, write the record in the documented format, note in `tools` that the helpers were not used, and set status no higher than `inconclusive`.

## Resources

- [references/inputs.md](references/inputs.md): the stage 3b gate, finding selection, authorization, and scope.
- [references/method.md](references/method.md): the fix method, the verification gates, the patch-candidate review, the outcome bar, and confidence.
- [references/patch-format.md](references/patch-format.md): filling `patches.json`, the diff and test layout, status, and fixing check failures.
- [references/container-workbench.md](references/container-workbench.md): the engine, the build context, keeping personal data out, the two phases, limits, and clean-up.
- [references/record-and-status.md](references/record-and-status.md) and [references/evidence-and-handling.md](references/evidence-and-handling.md): the shared stage record and evidence rules.
- [assets/patches.schema.json](assets/patches.schema.json) and [assets/patches-example.json](assets/patches-example.json): the format and a filled example.
- `scripts/`: `find_attack_paths.py`, `start_patches.py`, `normalize_patches.py`, `check_patches.py`, `render_patches.py`, plus the shared `check_environment.py`, `export_target.py`, `run_container.py`, `cleanup_run.py`, `prepare_workspace.py`, `target_identity.py`, `check_citations.py`, and the upstream record checks they build on. Each prints JSON, documents its exit codes in `--help`, and needs only Python 3.9 or later.
