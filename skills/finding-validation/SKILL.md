---
name: finding-validation
description: Validate the unvalidated findings from a Defense Factory finding-discovery run by testing each one inside a single disposable container on the user's own computer, and give each a verdict of confirmed, rejected, or inconclusive backed by evidence. Builds a throwaway container from the exact reviewed revision, installs the target's prerequisites, runs the application and a per-finding test, records the verdict, then deletes every resource the run created. Use when the user asks to validate, confirm, reproduce, or falsify one or more security findings, or to run stage 3 (isolated validation) of the Defense Factory workflow on its own. Do not use to build a threat model (stage 1), to discover new findings (stage 2), to fix code (stage 4), or to review a diff or pull request.
---

# Finding validation

Take the unvalidated findings from a stage 2 `finding-discovery` run and decide, with evidence, whether each one holds. Each finding is tested inside **one disposable container per run on the user's own computer**: install the prerequisites, run the application, run a test built from the finding's `investigation_question`, record a verdict of `confirmed`, `rejected`, or `inconclusive`, then delete everything the run created. The only thing left behind is the evidence in the run folder.

## Preconditions

1. **A container engine.** Run `scripts/check_environment.py` first. It must find Docker Desktop with a running daemon and enough memory. Docker is located from the PATH or a standard install location, so a running Docker Desktop is found even when the shell PATH is minimal (for example a non-interactive or remote shell). If a prerequisite is not met, stop before building anything and tell the user, for each entry in the script's `unmet` list, **what is not met** (its `prerequisite` and `problem`) and **how to fix it** (its `fix` steps, numbered, then its `verify` command). Never run the target on the host.
2. **A stage 2 record.** Start from the `findings.json` that `scripts/find_findings.py --root <target>` selects: the newest stage 2 run that is valid, normalized, and still matches the code, found without asking (see [references/inputs-and-authorization.md](references/inputs-and-authorization.md)). If none is usable, say so and offer to rerun stage 2. Honor any input or output path the user names. A single finding the user supplies directly is accepted only when it carries `locations` and an `investigation_question`; otherwise ask for them.
3. **Request, not a confirmation prompt.** Do not ask the user to confirm before running. Within the stage 2 run, carry its recorded authorization forward; otherwise record the user's request, quoted (see [references/inputs-and-authorization.md](references/inputs-and-authorization.md#authorization)). If the user says they are not authorized, stop with status `blocked`.
4. **Scope.** Validate the findings the user names, or all of them in priority order. Never test a finding whose affected location lies outside the stage 2 scope; record it `inconclusive` with that reason.

## Ground rules

- **Everything runs in the disposable container, never on the host.** Copy the exact reviewed revision into the container with `scripts/export_target.py`; never mount the user's folders. Put no credentials, SSH agent, engine socket, or host environment variables inside it.
- **Label everything; clean up by label only.** Every container, image, volume, and network the run creates carries the run label (`scripts/export_target.py` prints the `--label` arguments to pass to every build and run). At the end, and after any failure, run `scripts/cleanup_run.py --run-id <run_id>`, which removes **only** resources carrying that label and never touches anything else on the engine (for example the user's other containers).
- **Two phases.** Setup with the network on to install prerequisites; then turn the network off for testing (`--network none`) unless a finding's test needs a run-local sink, which stays on the run's own internal network only. Never contact external hosts during testing.
- **Limits.** Run every container with a memory limit, a CPU limit, a PID limit, and a wall-clock timeout. Do not kill a command that is making progress for slowness alone, but let the timeout bound a hang.
- **Setup failures are never counterevidence.** If prerequisites will not install or the app will not build, fall back to the static assessment and record `inconclusive`; never `rejected`. A `rejected` verdict needs positive evidence that the finding does not hold.
- **No secrets, and nothing pushed to Git.** Never store credentials or secret values in the record or artifacts; refer to them by name and location. Never push validation results or finding detail to Git.

## Workflow

1. **Check the environment.** `scripts/check_environment.py`. Stop with its remediation if it is not ready.
2. **Locate and verify the stage 2 record.** `scripts/find_findings.py --root <target>`; if none is usable, report why and offer to rerun stage 2.
3. **Prepare output storage.** `scripts/prepare_workspace.py --root <target> --stage 3-finding-validation --run-id <stage 2 run_id>`.
4. **Start the record.** `scripts/start_validation.py --root <target> --stage-dir <stage_dir> --findings <path from find_findings.py>` (add `--finding FD-3` for each finding the user named). It verifies the stage 2 record, selects the findings, and writes a `validations.json` skeleton with `<fill: ...>` markers. It never overwrites an existing `validations.json`.
5. **Export the target and build the workbench.** `scripts/export_target.py --root <target> --scope <path> --out <stage_dir>/container-build --run-id <run_id>`, then build the workbench image with `scripts/run_container.py build --run-id <run_id> --tag <tag> --context <stage_dir>/container-build` (it applies the run labels for you). Record the base image and its digest (see the digest fallback in [references/container-workbench.md](references/container-workbench.md)). Keep the run's own files — `Dockerfile`, stub services, test scripts — under `<stage_dir>/workbench/`, following the layout in that reference.
6. **For each finding, in priority order** (see [references/method.md](references/method.md)):
   1. **Write the rubric first**, up to five pass/fail criteria from the finding's `investigation_question`, before running anything.
   2. **Choose the strongest feasible method:** reproduction through the app's real interface, an added focused test, a crash/sanitizer/debugger trace, or the static fallback in [references/static-finding-assessment.md](references/static-finding-assessment.md) when dynamic execution is blocked or disproportionate. Run test containers with `scripts/run_container.py run --run-id <run_id> --image <tag> ... -- <cmd>`, which applies the labels, the limits, the network setting, and a timeout. For a browser-origin finding (rebinding, CSRF), validate at the HTTP layer as [references/method.md](references/method.md#browser-origin-findings-rebinding-csrf-private-network-access) describes; do not drive a browser.
   3. **Run a harmless control first** to establish the safe baseline.
   4. **Show the suspect code was reached**; a verdict without reachability evidence stays `inconclusive`.
   5. **Repeat a confirmation once** before recording `confirmed`.
   6. **Record the verdict and evidence** in `validations.json` as you go, saving PoCs and logs under `artifacts/<finding_id>/`.
7. **Clean up.** `scripts/cleanup_run.py --run-id <run_id>`; confirm nothing labelled remains. Run this even if a test failed partway.
8. **Normalize, check, and render.** `scripts/normalize_validations.py --repo <repo root> <validations.json>`, then `scripts/check_validations.py --repo <repo root> <validations.json>`, fixing every problem and normalizing again until both pass; then `scripts/render_validations.py <validations.json>` and `scripts/check_citations.py --repo <repo root> <stage_dir>/validation.md`.

## Completion

The stage is `complete` when the environment was available, every selected finding has a verdict with the evidence its verdict requires, both checks pass, and `cleanup_run.py` reports nothing labelled remaining. Report the path of `validation.md`, the status, verdicts by type, the engine and architecture used, and that all run resources were cleaned up. Suggest stage 3b (attack-path analysis) next, to rate the severity and priority of the confirmed and inconclusive findings.

## Failure conditions

- **`blocked`:** the user says they are not authorized, the stage 2 record is missing or stale with no retrievable revision, or no safe output location exists. Save the record only; build no container.
- **`inconclusive`:** the environment was unavailable or under-resourced, some findings could not be tested (setup blocked, outside scope, or not Linux-runnable), or the run stopped early. Keep every verdict reached; never present the result as exhaustive.
- **Clean-up left something behind:** report it as a stage failure and tell the user which labelled resources remain, so they can remove them; never remove unlabelled resources to compensate.
- **Python or the engine unavailable:** if the engine is missing, stop `blocked` with the remediation. If Python is unavailable, follow the same rules by hand, write the record in the documented format, note in `tools` that the helpers were not used, and set status no higher than `inconclusive`.

## Resources

- [references/inputs-and-authorization.md](references/inputs-and-authorization.md): the stage 2 gate, finding selection, a directly supplied finding, authorization, and scope.
- [references/method.md](references/method.md): the rubric, method choice, the harmless control, reachability, the repeated confirmation, and the verdict bar.
- [references/container-workbench.md](references/container-workbench.md): the engine abstraction, the build context, keeping personal data out, the two phases, limits, and clean-up.
- [references/validation-format.md](references/validation-format.md): filling `validations.json`, the static fallback, status, and fixing check failures.
- [references/static-finding-assessment.md](references/static-finding-assessment.md): the static fallback method.
- [references/record-and-status.md](references/record-and-status.md) and [references/evidence-and-handling.md](references/evidence-and-handling.md): the shared stage record and evidence rules.
- [assets/validations.schema.json](assets/validations.schema.json) and [assets/validations-example.json](assets/validations-example.json): the format and a filled example.
- `scripts/`: `check_environment.py`, `find_findings.py`, `start_validation.py`, `export_target.py`, `run_container.py`, `cleanup_run.py`, `normalize_validations.py`, `check_validations.py`, `render_validations.py`, `engine.py`, plus the shared `findings.schema.json`, `check_findings.py`, `normalize_findings.py`, `check_model.py`, `check_citations.py`, `target_identity.py`, and `prepare_workspace.py`. Each helper prints JSON, documents its exit codes in `--help`, and needs only Python 3.9 or later.
