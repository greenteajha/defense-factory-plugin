# Inputs and authorization

Settle these before building anything.

## Finding the stage 3b record

Stage 3b writes its run copy to `.defense-factory/runs/<run_id>/3b-attack-path-analysis/attack-paths.json`, in the repository root (or the target root when it is not a Git repository), unless the user chose another location. Do not ask the user which record to use:

1. If the user names a record path or run in this session, use it.
2. Otherwise run `scripts/find_attack_paths.py --root <target>` (add `--out-dir <folder>` if the user chose a location). It selects the newest run copy that passes `check_attack_paths.py` (which re-checks the stage 1-3 records and confirms the code is unchanged) and has status `complete` or `inconclusive`. Use its `attack_paths` path and `run_id`.
3. If it finds none, report what it found and why each is unusable, and offer to run the `attack-path-analysis` skill (stage 3b) first.

`start_patches.py` repeats the same checks on the chosen record. If it is stale, the code changed after stage 3b ran; never edit a record to make it pass — rerun the earlier stage.

## Eligible findings

Only analyses with stage 3b `decision: reportable` are patched. `deferred` and `ignore` analyses are recorded under `not_eligible`, never patched: a `deferred` finding has an unresolved proof gap, and an `ignore` finding is not a reportable issue for this target. Preparing a fix would claim a resolution the evidence does not support.

## Selection and scope

- Default: prepare a fix for every reportable finding, in priority order (P0 first).
- The user may narrow the set with `--finding FD-n`; the other reportable findings are then named in `coverage_gaps`.
- Stage 4's scope is the stage 3b scope; never widen it. Every patch's affected location must lie within it.

## Authorization

Do not ask the user to confirm authorization; their request to run the stage is the request to prepare the fixes. Record it honestly in `authorization`:

- **Same run as stage 3b:** `start_patches.py` pre-fills `inherited from stage 3b run <run_id>: ` followed by the stage 3b record's `authorization` value, and `check_patches.py` requires exactly that. This carries the recorded request forward.
- **Otherwise:** record the user's request, quoted: `requested by the user in session on <date>: "<their request>"`.

If the user says they are not authorized, or that the owner has not permitted the assessment, stop with status `blocked`.

## Output locations

- Default, used without asking: `.defense-factory/runs/<run_id>/4-patch-preparation/`, beside the earlier stages of the same run. The diffs live under `patches/`, tests under `tests/<finding_id>/`, and logs under `artifacts/<finding_id>/`.
- If the user names another location, pass it to `prepare_workspace.py` with `--out-dir` and record it in `output_location`.
- Never write outputs inside the plugin or skill folder, never edit the user's working tree, and never claim a write that did not happen.
