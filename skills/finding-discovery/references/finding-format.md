# Finding format

`findings.json` in the stage folder is the record of this stage; later stages read it. [assets/findings.schema.json](../assets/findings.schema.json) defines it, and [assets/findings-example.json](../assets/findings-example.json) is a complete, normalized example worth reading once before you start. `findings.md` is generated from it: never edit the Markdown, change the JSON and render again.

## Lifecycle

1. `start_findings.py` writes the skeleton. Every value you must supply is marked `<fill: ...>`, and `check_findings.py` fails while one remains. Fill or replace them; never delete a reconciliation row or stage 1 question entry to get rid of a placeholder.
2. Add findings, seeds, reconciliation outcomes, answers to stage 1 questions, coverage, and open questions as the work proceeds. Save after each finding, so interrupted work is kept.
3. `normalize_findings.py` validates the file and rewrites it in normalized form: it numbers findings `FD-1`, `FD-2`, …, adds fingerprints, `end_line`, and `hypothesis_priority`, merges exact duplicates, and rewrites references to IDs. Running it again is safe. It does not rewrite free text, so write `next_action`, notes, and open questions that name findings by `FD` ID after normalizing, then normalize again.
4. `check_findings.py` checks the rules below; `render_findings.py` writes `findings.md`; `check_citations.py` checks the rendered citations.

## Record

`start_findings.py` fills the target identity, run ID, timestamp (when the record was started; keep it), `skill_version`, scope, source, the start of `tools`, evidence, and (when allowed) inherited authorization. Supply:

- `status`: `complete`, `inconclusive`, or `blocked`, per [Status](#status). It starts as `inconclusive`; change it to `complete` when every condition is met.
- `actor`: the agent and client, and the requesting user if known. `model`: the exact model and version your client reports, or `unknown`; never guess.
- `authorization`: see [inputs-and-authorization.md](inputs-and-authorization.md#authorization).
- `inputs`: labels for seeds, knowledge bases, and user context used; `[]` if none.
- `tools`: add each helper you actually ran after `start_findings.py`.
- `independent_baseline`: `independent`, `not-independent` (you did the baseline pass yourself), or `not-performed: <reason>`.
- `assumptions` and `coverage_gaps`: material assumptions and unreviewed areas, with reasons. Name every `not-investigated` hypothesis or seed in a coverage gap.
- `next_action`: normally stage 3 validation, starting with the highest-priority findings.

## Findings

Write each finding with a `key`: a short lowercase label you choose, such as `archive-member-path-zip`. Use keys, never `FD` numbers, when you refer to a finding you have not yet normalized; after normalization, either works.

| Field | How to fill it |
| --- | --- |
| `title` | One line naming the weakness and where it is. |
| `family` | `<category>.<control-family>` in lowercase, for example `path-traversal.archive-extraction`, `authorization-bypass.object-update`, `sql-injection.query-builder`. No file names or line numbers. |
| `instance` | Only when two findings share a family and anchor file: a short label for each, such as `zip` and `tar`. The checker rejects two findings with the same fingerprint. |
| `cwe_ids` | `CWE-22` style; `[]` when unclear. |
| `origin` | The `TM-H` and `SEED` IDs it came from, or `["open-ended"]` alone when it matches none. |
| `discovered_by` | Every auditor that found it independently, as a list: `baseline`, `investigator`, `parent` (yourself). |
| `locations` | Every materially affected location, each with a role: `entrypoint` (where the attacker's request enters, or a wrapper), `source` (where attacker data is read), `root_control` (the check that is missing, wrong, or bypassable), `sink` (the sensitive operation), `concrete_implementation` (a subclass or handler that selects the behavior), `evidence` (supporting lines). Paths are relative to the repository root; add `end_line` for a range. Include a `root_control` whenever one can be identified. When the control is missing entirely, use the place where it should be enforced (the handler, or the middleware or application setup for a missing application-wide control) and say in `control` that it is absent. |
| `attacker` | Who, what they control, and which privileges they do not have. |
| `source`, `control`, `sink`, `path` | The attacker-controlled input; the closest control and why it is absent, bypassed, mis-scoped, or incomplete; the sensitive operation; how the input reaches it, with the transformations on the way. |
| `impact` | The new capability a failure grants, not a generic class description. |
| `exposure_assumptions` | Configuration, version, or deployment facts the finding needs. |
| `counterevidence` | What weakens it, and what you searched for. "None found" alone is not enough. |
| `proof_gaps` | What static evidence could not settle. |
| `investigation_question` | What stage 3 must do and observe: the setup or input, the expected safe behavior, and the behavior that confirms the finding. Write it so someone who has not read your notes can test it in an isolated copy. |
| `confidence` | `level` High, Medium, or Low, with a `reason`; see [method.md](method.md#confidence). |
| `related` | Findings connected to this one that must stay separate. |
| `excerpt` | Optional; at most about 10 lines, only when a citation alone would not let a reviewer follow the claim. Never secrets. |
| `status` | Always `unvalidated`. |

Do not add severity, exploit steps, or fix proposals; the schema rejects unknown fields.

## Seeds

Add each supplied lead to `seeds` (`SEED-1`, …) with `kind` (`advisory`, `scanner`, `report`, `other`), `label`, `summary`, and any `locations` it names. See [inputs-and-authorization.md](inputs-and-authorization.md#seeds).

## Reconciliation

Every `TM-H` hypothesis in the stage 1 table and every seed has exactly one row:

| Disposition | Use when | Row must contain |
| --- | --- | --- |
| `findings` | It produced one or more findings. | `findings`: their keys or IDs. Each listed finding's `origin` must include the row, and every finding's origin must be listed in its row. |
| `no-finding` | Source shows a control that prevents the new capability. | `note` explaining the control, and `evidence` locations citing it. |
| `open-question` | The code cannot settle it, for example it depends on deployment or third-party behavior. | `note` with the specific question and the evidence that would resolve it; add `evidence` where useful. |
| `not-investigated` | It was not examined. | `note` with the reason; also name the ID in `record.coverage_gaps`. |

A Critical or High hypothesis left `not-investigated` makes the stage `inconclusive`. Keep documentation-versus-configuration disagreements from stage 1 visible in notes or open questions even when no finding results.

**Stage 1 open questions.** For each numbered question, set `status` to `answered` (with the evidence in `note`) or `open` (with what is still unknown). Do not remove entries.

**Open-ended findings** are rendered in `findings.md` under "Boundaries the threat model missed". Add an entry to `open_questions` when one suggests a boundary the next threat model should cover.

## Deduplication

- `normalize_findings.py` merges exact duplicates only: the same family, instance, CWE IDs, and locations.
- Merge further yourself only by **remediation subsumption**: the findings share the same root control, and fixing that one control fixes every finding you absorb. Put the absorbed keys in `merged_from`, and carry over every location, origin, piece of counterevidence, and proof gap. List each affected entry point and sink in the merged finding's `locations`, so none is lost.
- One missing application-wide control (for example, no CSRF protection anywhere) is one root control: record one finding with every affected entry point, not one finding per route.
- Keep findings separate when their root controls differ, even if one broad change (a new framework, a global validator) could cover all of them, or when a source, sink, or impact would remain after fixing the shared control. Never merge because findings share a CWE, subsystem, route, file, helper, or sink family, or because one is louder; link related findings with `related`.
- The discovery checklist's "record each call site" rules apply to call sites with their own source or closest control. Call sites that pass through the same broken control belong in one finding's locations.

## Coverage

- `inventory` and `exclusions` come from `start_findings.py`. Add an exclusion only when the user asks for one, and record why.
- `reviewed_files`: inventory files that you, the baseline, or an investigator read completely. Files seen only in search results or excerpts do not count, and neither does architecture mapping alone.
- `completeness`: `complete` only when every inventory file is in `reviewed_files`. Otherwise `partial`, with `remaining` entries (`paths` and `reason`) covering every unreviewed file. A folder path covers the files under it.

## Status

- `complete`: every check passes, every hypothesis and seed has a row, no Critical or High hypothesis is `not-investigated`, and coverage is complete or its remaining paths are listed.
- `inconclusive`: any of those conditions fails, source was partly unavailable, citations could not be verified, or the run stopped early. Keep every finding; the absence of findings proves nothing.
- `blocked`: see below.

## Blocked record

When a precondition fails after the stage folder exists and the target identity is known (for example, the user refuses authorization after `start_findings.py` ran), set `status` to `blocked`. Then empty `findings` and `reconciliation` (seeds may stay), state the blocker in `next_action`, replace any remaining `<fill: ...>` value with a plain statement that it does not apply, and run the normalize, check, and render steps. If nothing was created yet, write nothing and tell the user why.

## Fixing check failures

| Problem reported | Usual fix |
| --- | --- |
| A schema error on a field | Match the schema: required fields, allowed values, no extra fields. |
| A location is beyond the end of the file or does not exist | Re-read the file and cite the real lines, relative to the repository root. |
| A finding needs an affected location inside the scope | Add the in-scope entry point, control, sink, or implementation, or drop a finding that is out of scope. |
| Findings share a fingerprint | Give each sibling a distinct `instance`, or merge them if one fix covers both. |
| A hypothesis or seed has no reconciliation row | Add one; every row needs a disposition. |
| A row and a finding's origin disagree | Make the row's `findings` list and each finding's `origin` match. |
| A `<fill: ...>` placeholder remains | Supply the value. |
| `security-guidance.md` is missing | Save the `resolve_security_md.py` output in the stage folder (workflow step 3). |
| The stage 1 model or record is stale | The code changed during the run. Tell the user; rerun stage 1 or restart stage 2 on the current code. |
| Coverage does not account for every file | Review the files, or list them in `remaining` with the reason. |
