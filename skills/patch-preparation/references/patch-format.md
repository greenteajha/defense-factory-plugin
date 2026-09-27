# Filling patches.json

The format is specified by [../assets/patches.schema.json](../assets/patches.schema.json); [../assets/patches-example.json](../assets/patches-example.json) is a filled, normalized example. Top level: `record`, `validated_record` (path relative to the stage folder, sha256, and run ID of the consumed stage 3b `attack-paths.json`), `threat_model`, `security_guidance`, `environment`, `patches`, `not_eligible`, `open_questions`.

`start_patches.py` writes the skeleton with `<fill: ...>` markers and `environment: null`. Fill it as you work, then normalize, check, and render.

## The record

The shared stage-record fields are in [record-and-status.md](record-and-status.md). Stage 4 sets `source` to `analysed-record`. Leave `environment` `null` until a container has been built; a `blocked` run keeps it `null` and has no patches.

## The environment block

Fill `environment` once from the run, exactly as stage 3 does: `host_os`, `host_arch`, `engine`, `engine_version` (from `check_environment.py`), `base_image` and `base_image_digest`, `emulation`, `code_source` (from `export_target.py`), `limits` (memory, cpus, pids, timeout_seconds), `network_setup`, `network_testing`, and `cleanup` (the `cleanup_run.py` result: the label, the counts removed by kind, and how many labelled resources remained — which must be `0`). See [container-workbench.md](container-workbench.md).

## Each patch entry

One entry per reportable finding. Copy `analysis_id`, `finding_id`, `finding_key`, `finding_fingerprint`, `title`, `severity`, and `priority` from the stage 3b analysis so `check_patches.py` can confirm the link; keep `locations` exactly as the analysis recorded them. Then record:

- `outcome`: `fixed`, `no_change`, `blocked`, or `inconclusive` (see [method.md](method.md#the-outcome-bar)).
- `vulnerable_path`: the concrete source-to-sink path the fix must close.
- `security_invariant`: the invariant the shared boundary must preserve.
- `patch_strategy`: the minimal, repository-native fix and why; for `no_change`, why the code is already safe.
- `patch_ref`: the path to the diff under `patches/` (for example `patches/FD-16.patch`), or `null` for `no_change` and `blocked`.
- `files_changed`, `tests_added`: the files the diff touches and the focused tests it adds; empty for `no_change`.
- `gates`: the ordered verification gates, each `{gate, result}` with `result` `pass`, `fail`, or `unknown`. Every gate is `pass` for `fixed`.
- `reproduction_before`, `reproduction_after`: cite stage 3's reproduction and what the same reproduction does against the patched code; do not restate stage 3's test inputs.
- `legitimate_behavior`: the legitimate control and its result.
- `candidate_review`: the fresh read-only review of the patch.
- `remaining_risk`: what the patch does not cover.
- `proof_gap`: required for `blocked` and `inconclusive`; the exact missing proof. Delete the field for `fixed` and `no_change`.
- `confidence`: `{level, reason}`, from the evidence actually obtained; an `inconclusive` outcome is never `High`.
- `artifacts` (optional): paths under `artifacts/<finding_id>/` for logs and before/after output. Regular files only; no secrets.

Cite code as backtick `path:line` in the record only through `locations`, so `check_citations.py` can verify it.

## The diff and test layout

- `patches/<finding_id>.patch`: the unified diff against the reviewed revision. It is the deliverable; it is never applied to the user's tree.
- `tests/<finding_id>/`: the focused regression and legitimate-behaviour tests added in the container.
- `artifacts/<finding_id>/`: command logs and before/after reproduction output. Never secrets.

## not_eligible

Every stage 3b analysis whose decision is `deferred` or `ignore` gets one entry: `{analysis_id, finding_id, decision, reason}`. `check_patches.py` requires `not_eligible` to list exactly those analyses.

## Status

- **`complete`**: the environment was available, every reportable finding has a patch entry with the evidence its outcome requires, no outcome is `blocked` or `inconclusive`, clean-up left nothing behind, and every reportable finding is patched or named in `coverage_gaps`.
- **`inconclusive`**: the environment was unavailable, some findings could not be fixed or verified, or the run stopped early. Keep every outcome reached.
- **`blocked`**: the user is not authorized, the stage 3b record is missing or stale with no retrievable revision, or no safe output location exists. Record only; no container, no patches, `environment` null.

## Fixing check failures

Run `scripts/normalize_patches.py <patches.json>`, then `scripts/check_patches.py --repo <repo> <patches.json>`. Fix every problem and normalize again until both pass; then `scripts/render_patches.py <patches.json>` and `scripts/check_citations.py`. Common failures: a `<fill: ...>` left in place; a `fixed` outcome without a passing gate, a written patch, or a test; a `blocked`/`inconclusive` outcome without a `proof_gap`; a `severity` or `priority` that does not match the stage 3b analysis; changed `locations`; `not_eligible` that does not match the deferred and ignore analyses; `status: complete` while an outcome is `blocked` or `inconclusive`.
