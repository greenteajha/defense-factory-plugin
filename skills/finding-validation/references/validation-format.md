# Filling validations.json

The format is specified by [../assets/validations.schema.json](../assets/validations.schema.json); [../assets/validations-example.json](../assets/validations-example.json) is a filled, normalized example (a test regenerates it from a raw fixture so it cannot go stale). Top level: `record`, `validated_record` (path relative to the stage folder, sha256, and run ID of the consumed `findings.json`; `null` for a supplied finding), `environment`, `validations`, `open_questions`.

`start_validation.py` writes the skeleton with `<fill: ...>` markers and `environment: null`. Fill it as you work, then normalize, check, and render.

## The record

The shared stage-record fields are in [record-and-status.md](record-and-status.md). Stage 3 sets `source` to `validated-record` or `supplied-finding`. Leave `environment` `null` until a container has been built; a `blocked` run keeps it `null` and has no validations.

## The environment block

Fill `environment` once from the run: `host_os`, `host_arch`, `engine`, `engine_version` (from `check_environment.py`), `base_image` and `base_image_digest` (from `image inspect`), `emulation` (`none` or the emulated platform and why), `code_source` (from `export_target.py`), `limits` (memory, cpus, pids, timeout_seconds), `network_setup`, `network_testing`, and `cleanup` (the `cleanup_run.py` result: the label, the counts removed by kind, and how many labelled resources remained — which must be `0`).

## Each validation entry

One entry per tested finding. Copy `finding_id`, `finding_key`, `finding_fingerprint`, and `title` from the stage 2 finding so `check_validations.py` can confirm the link. Then record the verdict and its evidence, following [method.md](method.md):

- `verdict`: `confirmed`, `rejected`, or `inconclusive`.
- `method`: `interface-reproduction`, `targeted-test`, `crash-or-sanitizer`, `debugger-trace`, or `static-assessment`.
- `reproduced`: `true` only for a dynamic method that ran in the container; `false` for `static-assessment`.
- `rubric`: the criteria written before running, each with `pass`, `fail`, or `unknown`.
- `control`: the harmless control run and its result.
- `reachability`: evidence the attacker-controlled input reached the sink; required for `confirmed`.
- `repeat_confirmed`: `true` when a `confirmed` result was reproduced a second time.
- `evidence`, `counterevidence_or_proof_gap`, `setup_notes`, `remaining_uncertainty`, `next_step`: as their names say. `setup_notes` records any setup failure, which is never counterevidence.
- `confidence`: `{level, reason}`, calibrated from the method and evidence; a `static-assessment` is never `High`.
- `affected_version`: the record `version` the test ran against.
- `artifacts` (optional): paths under `artifacts/<finding_id>/` for PoCs, inputs, and logs. Regular files only; no secrets.

Cite code as backtick `path:line` in `evidence` and `reachability` so `check_citations.py` can verify it.

## The static fallback

When a test cannot run, use the code-reading method in [static-finding-assessment.md](static-finding-assessment.md), record `method: static-assessment` and `reproduced: false`, and let the report render it as "assessed statically, not reproduced". A static assessment can still reach `confirmed` or `rejected` when the static evidence is decisive, but its confidence is bounded and its proof gap is stated. Missing runtime setup is a proof gap, not counterevidence.

## Status

- **`complete`**: the environment was available, every selected finding has a verdict with the evidence its verdict requires, no verdict is `inconclusive`, clean-up left nothing behind, and every stage 2 finding is either validated or named in `coverage_gaps`.
- **`inconclusive`**: the environment was unavailable or under-resourced, some findings could not be tested, or the run stopped early. Keep every verdict reached.
- **`blocked`**: the user is not authorized, the stage 2 record is missing or stale with no retrievable revision, or no safe output location exists. Record only; no container, no validations, `environment: null`.

## Fixing check failures

Run `scripts/normalize_validations.py --repo <repo> <validations.json>`, then `scripts/check_validations.py --repo <repo> <validations.json>`. Fix every problem it reports and normalize again until both pass; then `scripts/render_validations.py <validations.json>` and `scripts/check_citations.py --repo <repo> <stage_dir>/validation.md`. Common failures: a `<fill: ...>` left in place; a `confirmed` verdict without `repeat_confirmed`, a passing rubric criterion, or reachability; a `rejected` verdict without a failing criterion; a `static-assessment` marked `reproduced` or rated `High`; `status: complete` while a verdict is `inconclusive` or a finding is neither validated nor named in `coverage_gaps`.
