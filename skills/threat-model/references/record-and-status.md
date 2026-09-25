# Stage record and status

Every Defense Factory stage output starts with a YAML header, the stage record, so a reviewer or a later stage can tell what was assessed, under what authority, and with what result. Write it between `---` lines at the top of the output Markdown file.

## Record fields

| Field | Required | Meaning |
| --- | --- | --- |
| `record_version` | yes | Format version of this header. Currently `1`. |
| `stage` | yes | Stage identifier, also used as the stage folder name, for example `1-threat-model`. |
| `status` | yes | One of the status values below. |
| `run_id` | yes | Identifier of this run; the name of the run folder. |
| `timestamp` | yes | When the record was written, in UTC ISO 8601 (for example `2026-09-24T07:15:00Z`). Take it from `prepare_workspace.py` or the system clock; never estimate it. |
| `actor` | yes | Who performed the stage: the agent and client (for example "Claude Code agent") and the requesting user if known. |
| `target_id` | yes | Stable target identity from `target_identity.py`. |
| `target_kind` | yes | `git_revision`, `git_worktree`, or `directory_snapshot`. |
| `version` | yes | Commit for a clean Git checkout; snapshot digest otherwise. |
| `revision` | when available | The Git commit, even when the working tree has uncommitted changes. |
| `scope` | yes | `whole-repository`, or the list of in-scope paths relative to the repository root. |
| `authorization` | yes | Who confirmed authorization, when, and how, quoting the user's own words (for example `user stated in session on 2026-09-25: "I'm authorized to assess this repository"`), or the calling workflow's record. Never paraphrase a confirmation that was not given. |
| `source` | yes | How the content was obtained: `generated`, `reused`, `supplied`, `supplied-revised`, or `repository-guidance`. |
| `reused_from` | when `source` is `reused` | The `run_id` of the stored model that was copied. |
| `output_location` | yes | Where outputs were saved and who chose it: `default .defense-factory (Git-ignored)` or `user-chosen: <path> (<ignored or not ignored by Git>)`. |
| `inputs` | yes | Supplied models, knowledge bases, user context, and policies used, by label; `[]` if none. |
| `independent_review` | yes | `independent`, `not-independent` (same-agent second pass), or `not-performed` with a reason. |
| `tools` | yes | Helpers and versions used (for example Python version), or a note that they were not used. |
| `evidence` | yes | Where the evidence lives: this file's citations plus any saved artifacts. |
| `assumptions` | yes | Material assumptions the result depends on; `[]` if none. |
| `coverage_gaps` | yes | Areas not reviewed or not reviewable, with the reason; `[]` only if coverage is complete. |
| `next_action` | yes | The recommended next step. |

Stages may add their own fields after these.

## Status values

- **`complete`**: the stage's completion criteria are met. The result may still contain hypotheses and open questions; completion means the output is fit for review, not that the target is secure.
- **`rejected`**: the stage examined a candidate and evidence shows it does not hold. Not used by stage 1.
- **`inconclusive`**: the stage ran but could not reach a supportable result for part or all of its scope, for example missing source, unverifiable citations, or a test that could not run. Failure to perform a check is inconclusive, never a rejection.
- **`blocked`**: the stage could not proceed because a precondition failed: missing or refused authorization, unclear scope, unreadable target, a missing required input, or no safe output location.

When status is `blocked`, keep the header, state the blocker in `next_action`, and omit the body.
