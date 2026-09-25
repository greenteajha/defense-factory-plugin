# Stage record and status

Every Defense Factory stage output starts with a YAML header, the stage record, so a reviewer or a later stage can tell what was assessed, under what authority, and with what result. It sits between `---` lines at the top of the output Markdown file. Stage 1 writes it directly; stage 2 keeps it as the `record` object in `findings.json`, and `render_findings.py` writes it into `findings.md`.

## Record fields

| Field | Required | Meaning |
| --- | --- | --- |
| `record_version` | yes | Format version of this header. Currently `1`. |
| `stage` | yes | Stage identifier, also used as the stage folder name: `1-threat-model` or `2-finding-discovery`. |
| `status` | yes | One of the status values below. |
| `run_id` | yes | Identifier of this run; the name of the run folder. |
| `timestamp` | yes | When the record was written, in UTC ISO 8601 (for example `2026-09-24T07:15:00Z`). Take it from `prepare_workspace.py` or the system clock; never estimate it. |
| `actor` | yes | Who performed the stage: the agent and client (for example "Claude Code agent") and the requesting user if known. |
| `model` | yes | The exact model and version the client reports for this session (for example `Claude Opus 5.5`), not just the vendor. Write `unknown` if the client does not say; never guess. |
| `skill_version` | yes | The `skill_version` printed by `prepare_workspace.py`: a fingerprint of the skill's instructions, template, and scripts. Stage 1 reuse depends on it. |
| `target_id` | yes | Stable target identity from `target_identity.py`. |
| `target_kind` | yes | `git_revision`, `git_worktree`, or `directory_snapshot`. |
| `version` | yes | Commit for a clean Git checkout; snapshot digest otherwise. |
| `revision` | when available | The Git commit, even when the working tree has uncommitted changes. |
| `scope` | yes | `whole-repository`, or the list of in-scope paths relative to the repository root. |
| `authorization` | yes | Who requested the assessment, when, and how, quoting the request (for example `requested by the user in session on 2026-09-25: "Threat model this repository"`), any explicit statement of authorization the user made, or the calling workflow's record. Never record a confirmation of authorization the user did not give. |
| `source` | yes | How the content was obtained; values per stage below. |
| `output_location` | yes | Where outputs were saved and who chose it: `default .defense-factory (Git-ignored)` or `user-chosen: <path> (<ignored or not ignored by Git>)`. |
| `inputs` | yes | Supplied models, knowledge bases, user context, and policies used, by label; `[]` if none. |
| `tools` | yes | Helpers and versions used (for example Python version), or a note that they were not used. |
| `evidence` | yes | Where the evidence lives: this file's citations plus any saved artifacts. |
| `assumptions` | yes | Material assumptions the result depends on; `[]` if none. |
| `coverage_gaps` | yes | Areas not reviewed or not reviewable, with the reason; `[]` only if coverage is complete. |
| `next_action` | yes | The recommended next step. |

Each stage adds its own fields after these.

## Stage 1 (threat model) fields

| Field | Required | Meaning |
| --- | --- | --- |
| `source` | yes | `generated`, `reused`, `supplied`, `supplied-revised`, or `repository-guidance`. |
| `reused_from` | when `source` is `reused` | The `run_id` of the stored model that was copied. |
| `independent_review` | yes | `independent`, `not-independent` (same-agent second pass), or `not-performed` with a reason. |
| `open_questions` | yes | Number of items in the Open questions list. |
| `hypotheses` | yes | Number of hypotheses by priority, for example `{critical: 0, high: 1, medium: 2, low: 0}`. |

## Stage 2 (finding discovery) fields

The first two are written by the agent in `findings.json`; `render_findings.py` derives the rest from the body, so they cannot disagree with it.

| Field | Required | Meaning |
| --- | --- | --- |
| `source` | yes | `stage-1-record` (started from a stage 1 threat model) or `narrow-scan` (named paths without a model). |
| `independent_baseline` | yes | `independent`, `not-independent` (same-agent second pass), or `not-performed` with a reason. |
| `threat_model_ref` | derived | Path and sha256 of the stage 1 model used, or `none`. |
| `findings` | derived | Number of findings by confidence, for example `{high: 1, medium: 2, low: 0}`. |
| `reconciliation` | derived | Number of hypothesis and seed rows by disposition: `findings`, `no-finding`, `open-question`, `not-investigated`. |
| `coverage` | derived | `complete` or `partial`. |

Within one run, stage 2 carries the stage 1 request forward: `authorization` reads `inherited from stage 1 run <run_id>: ` followed by the stage 1 record's `authorization` value.

## Status values

- **`complete`**: the stage's completion criteria are met. The result may still contain hypotheses, unvalidated findings, and open questions; completion means the output is fit for review, not that the target is secure.
- **`rejected`**: the stage examined a finding and evidence shows it does not hold. Not used by stages 1 and 2: rejection needs validation.
- **`inconclusive`**: the stage ran but could not reach a supportable result for part or all of its scope, for example missing source, unverifiable citations, or a test that could not run. Failure to perform a check is inconclusive, never a rejection.
- **`blocked`**: the stage could not proceed because a precondition failed: the user said they are not authorized, unreadable target, a missing required input, or no safe output location.

When status is `blocked`, keep the header, state the blocker in `next_action`, and omit the body.
