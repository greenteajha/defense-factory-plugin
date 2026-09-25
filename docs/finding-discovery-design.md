# Stage 2 design: finding discovery

Design for the `finding-discovery` skill, which implements stage 2 of [workflow-contracts.md](workflow-contracts.md). Stage 1 (`threat-model`) produces hypotheses; stage 2 turns them into deduplicated, **unvalidated findings** that stage 3 can test. Capability parity with Codex Security's skill of the same name is tracked in [finding-discovery-parity.md](finding-discovery-parity.md).

Decisions taken on 2026-09-25:

| Decision | Choice | Reason |
| --- | --- | --- |
| Skill name | `finding-discovery` | Same name as Codex Security's skill for this stage, so users and the parity table map one to one. |
| What the stage produces | Findings, each with `status: unvalidated` | One word for the item across stages; the status, not a separate word, says it is not yet proven. Stage 3 changes the status. |
| Record format | `findings.json` is canonical; `findings.md` is rendered from it by a script | Findings have too many structured fields for reliable Markdown tables. Scripts validate, normalize, deduplicate exact copies, assign IDs, and check reconciliation. Stage 3 reads the JSON. |
| Diff, commit, and pull-request scans | Deferred to a later release | Version 1 covers the whole repository and named paths. Listed as a parity gap. |
| Authorization | No confirmation prompt in stages 1 and 2; the user's request is recorded (decided 2026-09-25, later the same day) | Both stages only read code already on the user's machine, so the prompt added friction without real protection. The record states what the user asked for, never a confirmation they did not give; a user who says they are not authorized is still stopped. Revisit for stage 3, which runs code. |
| Output location and model discovery | `.defense-factory/` by default for every target, found automatically by later stages | Stage 1 no longer asks where to save for targets that are not Git repositories; `find_threat_model.py` selects the newest valid, up-to-date stage 1 run without asking. |

## Scope of the skill

- **Activates for:** finding security bugs or vulnerabilities in an authorized repository or paths; hunting from a threat model; stage 2 of a Defense Factory review; checking a supplied advisory, scanner result, or bug report against the code.
- **Does not activate for:** building a threat model (stage 1), confirming or exploiting a finding (stage 3), fixing code (stage 4), or reviewing a diff or pull request (deferred).
- **Read-only and offline**, like stage 1: no running the application, installing dependencies, or network access. An advisory URL the user supplies is read at most once, only with explicit authorization, without following links.

## Inputs

Work through these in order.

1. **Stage 1 record (main route).** The run copy `<run>/1-threat-model/threat-model.md`, selected by `find_threat_model.py` without asking: the newest run copy that is accepted. It is accepted only when:
   - it passes `check_model.py`;
   - its `status` is `complete` or `inconclusive` (an `inconclusive` model's coverage gaps are carried into stage 2's gaps);
   - its `target_id` matches, and its `version` still matches the code when recomputed for **the model's own scope** (a dirty working tree's version is a digest of the in-scope files, so it must be recomputed with the scope it was made for).
   If no run copy is accepted, the code probably changed since the model was built: offer to rerun stage 1, or to continue as a narrow scan without the model. Never silently use a stale model. The model's path and sha256 are recorded so later stages can detect edits.
2. **Narrow scan without a model.** Named paths only, as the contract allows. `source: narrow-scan`, with a coverage gap stating that no threat model was used; no hypothesis reconciliation applies, but seeds still do.
3. **Seeds (optional, either route).** An advisory, scanner or SARIF result, or bug report the user supplies. Each becomes a `SEED-n` entry that stays open until source evidence closes it; a neighbouring issue of the same class does not close it unless it has the same source, control, and impact.
4. **Knowledge base and user context.** Same precedence and origin labels as stage 1 (`inputs-and-reuse.md`, "Precedence of inputs").

Scope may be narrowed from the stage 1 scope, never widened. A narrower stage 2 scope reconciles only the hypotheses whose entry point, control, or sensitive operation lies inside it; the others are recorded as `not-investigated` with the reason "outside stage 2 scope".

## Authorization

Neither stage asks the user to confirm authorization. Stage 1 records the request (`requested by the user in session on <date>: "<request>"`). Stage 2, in the same run as a valid, up-to-date stage 1 model with the same or narrower scope, records `inherited from stage 1 run <run_id>: ` followed by the stage 1 value exactly; otherwise it records the user's own request, quoted. `check_findings.py` enforces both forms. A user who says they are not authorized is stopped with status `blocked`.

Known limit: the record lives in a Git-ignored folder that anyone with write access to the workspace can edit. The recorded sha256 lets later stages detect edits made after stage 2 read it, not before. This is a workflow safeguard, not an access control.

## Workflow

1. **Authorization and scope.** As above.
2. **Prepare output storage.** `prepare_workspace.py --stage 2-finding-discovery --run-id <stage 1 run_id>` (a new run ID for a narrow scan). Same output-location rules as stage 1.
3. **Start the record.** `start_findings.py` checks the stage 1 model (valid, fresh, scope), writes the scope inventory, and writes a `findings.json` skeleton: target identity, run ID, timestamp, `skill_version`, the model's digest, one reconciliation row per hypothesis, and one entry per stage 1 open question, with every value the agent must supply marked `<fill: ...>`. It pre-fills inherited authorization only when the model is in the same run and quotes the user.
4. **Load other inputs.** Seeds, knowledge base, user context.
5. **Resolve security policy.** `resolve_security_md.py` once per directory investigated, applied as policy data. Workers receive the policy for their packets.
6. **Inventory the scope** (done by `start_findings.py`, or `list_scope_files.py` alone): `scope-inventory.txt` is the same file set `target_identity.py` digests, minus symbolic links, binary files, vendored dependency folders, minified or generated bundles, dependency lockfiles, and any exclusion the user asked for, each counted by rule. Coverage is measured against this list.
7. **Build investigation packets.** Group hypotheses and seeds that share an attacker, protected asset, expected controls, entry points, and sensitive operations. Each packet lists its `TM-H` or `SEED` IDs and source anchors. Do not invent locations or reachability.
8. **Independent baseline audit.** If the client can start a sub-agent or separate session with fresh context, give it the fixed baseline brief (in the skill's method reference), the target, scope, inventory, security policy, supplied threat model, and user context, **but not the `TM-H` hypotheses or packets**. It hunts independently and returns findings, resolved questions, and the files it fully reviewed. Otherwise do the same pass sequentially afterwards and record `independent_baseline: not-independent`.
9. **Focused investigations.** Investigate each packet, choosing among four starting perspectives: forward (input to sensitive operation), backward (sensitive operation to attacker), authorization and business logic, and open-ended. Use sub-agents where the client offers them, sized to the work. Apply the discovery checklist: enumerate every independently reachable call site, variant, and concrete implementation; keep the root control visible; follow shared helpers to their siblings. Supporting code may lie outside scope; an affected entry point, control, or operation must lie inside it.
10. **Record findings.** Write each finding to `findings.json` as soon as it exists, under the agent's own short `key` (for example `archive-member-path-zip`), so an interrupted run keeps its work. References between findings and from reconciliation rows use these keys.
11. **Deduplicate.** Merge semantically only by remediation subsumption (below), listing absorbed keys in `merged_from`.
12. **Reconcile.** One reconciliation row for every `TM-H` and `SEED`; carry forward each stage 1 open question.
13. **Check coverage.** Union the files that the baseline, investigators, and parent fully reviewed, and review the remaining inventory files in coherent groups. If budget or unavailable source stops this, list the actual remaining paths.
14. **Normalize, check, render.** `normalize_findings.py` (validates, normalizes, merges exact duplicates, assigns `FD-n` IDs and fingerprints, rewrites references to IDs); `check_findings.py` (every rule below); `render_findings.py` (writes `findings.md`); `check_citations.py` on `findings.md`. Fix and repeat until all pass, then spot-check that cited lines say what each finding claims.
15. **Report.** Output path, status, findings by confidence, reconciliation counts, coverage, and main open questions. Suggest stage 3 (isolated validation) as the next action.

Keep going until no further distinct plausible findings remain in the reviewed scope. No plausible findings is a valid result: the reconciliation and coverage still show what was checked.

## Outputs

`.defense-factory/runs/<run_id>/2-finding-discovery/`:

| File | Purpose |
| --- | --- |
| `findings.json` | Canonical record: stage record, threat-model reference, seeds, findings, reconciliation, carried-forward questions, coverage, open questions. Later stages read this. |
| `findings.md` | Rendered for reviewers: the YAML stage record header (with counts derived from the body), then summary, reconciliation, one section per finding, boundaries the threat model missed, coverage, and open questions. Never edited by hand. |
| `scope-inventory.txt` | The in-scope file list coverage is measured against. |
| `security-guidance.md` | Resolved policy, as in stage 1. |

## Finding record

The format is specified by the skill's `assets/findings.schema.json`; `assets/findings-example.json` is a filled, normalized example (a test regenerates it from `tests/fixtures/finding-discovery/findings-raw.json` so it cannot go stale). Top level: `record`, `threat_model` (path relative to the stage folder, sha256, run ID; `null` for a narrow scan), `seeds`, `findings`, `reconciliation`, `stage1_open_questions`, `coverage`, `open_questions`.

Each finding:

| Field | Written by | Meaning |
| --- | --- | --- |
| `id` | normalizer | `FD-1`, `FD-2`, … ordered by hypothesis priority, confidence, fingerprint, and key. Unique within the run; references are rewritten to it. |
| `key` | agent | The agent's own stable lowercase label. |
| `fingerprint` | normalizer | Digest of target ID, `family`, anchor file (first `root_control`, else first `sink`, else first location), and `instance`, without line numbers, so the same finding matches across runs. A match is a signal, not proof. Two findings in a run may not share one: give siblings distinct `instance` values. |
| `title` | agent | One line. |
| `family` | agent | Stable lowercase `<category>.<control-family>`, for example `path-traversal.archive-extraction`. No file names or line numbers. |
| `instance` | agent, when needed | Distinguishes sibling instances that share a family and anchor. |
| `cwe_ids` | agent | `CWE-n` values (normalized); empty when the class is unclear. |
| `origin` | agent | `TM-H` IDs and `SEED` IDs, or `open-ended` alone. |
| `hypothesis_priority` | normalizer | Highest stage 1 priority among the `TM-H` origins; `null` otherwise. Not a severity. |
| `discovered_by` | agent | Every auditor that found it independently: `baseline`, `investigator`, `parent`. More than one is corroboration. |
| `locations` | agent | One or more `{path, start_line, end_line, role}`; role is `entrypoint`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one affected location (entrypoint, root control, sink, or concrete implementation) must be in scope. |
| `attacker`, `source`, `control`, `sink`, `path`, `impact` | agent | Who attacks and what they control and lack; the attacker-controlled input; the closest control and why it fails; the sensitive operation; how input reaches it; the new capability gained. |
| `exposure_assumptions` | agent | Deployment or configuration assumptions; `[]` if none. |
| `counterevidence` | agent | Controls or facts that weaken it. "None found" must say what was searched. |
| `proof_gaps` | agent | What static evidence could not establish; `[]` if none. |
| `investigation_question` | agent | What stage 3 must show: the input or state to set up, the expected safe behaviour, and the behaviour that would confirm the finding. |
| `confidence` | agent | `{level: High, Medium, or Low, reason}` for static plausibility: High when the source-to-sink path and failing control are shown directly; Medium when a prerequisite is inferred; Low when it rests on unverified behaviour. |
| `merged_from` | agent or normalizer | Keys absorbed into this finding. |
| `related` | agent | Findings that are connected but must stay separate. |
| `excerpt` | agent, optional | At most about 10 lines, only when a citation alone would not let a reviewer follow the claim. Never secrets. |
| `status` | agent | Always `unvalidated` in stage 2. |

Severity is not assigned in stage 2. The affected revision is the record's `version`. Counts in the rendered header (`findings`, `reconciliation`, `coverage`) are derived from the body, so they cannot disagree with it.

## Reconciliation

Every `TM-H` in the stage 1 hypotheses table and every `SEED` gets exactly one row:

| Disposition | Row records |
| --- | --- |
| `findings` | The findings it produced; each listed finding's `origin` includes the row, and every finding's origin is listed in its row. |
| `no-finding` | The control that prevents new capability, with `evidence` locations. |
| `open-question` | A specific question and the evidence that would resolve it. |
| `not-investigated` | The reason; the ID is also named in the record's `coverage_gaps`. |

`open-ended` findings point to boundaries the threat model missed; `findings.md` lists them in a "Boundaries the threat model missed" section for the next stage 1 run. Each numbered stage 1 open question is carried forward once as `answered` or `open`, with a note. Documentation-versus-configuration disagreements from stage 1 are kept even when no finding results.

## Deduplication

- `normalize_findings.py` merges only exact duplicates: the same `family`, `instance`, CWE IDs, and locations. It keeps the finding with the smallest key, joins differing text, unions lists, origins, and auditors, keeps the highest confidence, and records the absorbed keys in `merged_from`.
- The agent may merge further only by **remediation subsumption**: the findings share the same root control, and fixing that control fixes every absorbed one. A missing application-wide control is one root control, with every affected entry point as a location. Findings with different root controls stay separate even if one broad change could cover them all, and so do findings that share a CWE, subsystem, route, file, helper, or sink family; cross-reference them in `related`.
- A merged finding keeps every location, origin, and piece of counterevidence from the absorbed ones. `check_findings.py` confirms that each merged key appears once and is no longer a finding.

## Status

- **`complete`**: every reconciliation row is present; no Critical or High hypothesis is `not-investigated`; every finding passes the schema and location checks; coverage is complete, or every unreviewed inventory file lies under a `coverage.remaining` path with its reason.
- **`inconclusive`**: a Critical or High hypothesis was not investigated, source was partly unavailable, citations could not be verified, or the run was interrupted. Saved findings are kept, and the absence of findings proves nothing.
- **`blocked`**: the user says they are not authorized, or a readable target, a required input, or a safe output location is missing. The record only, with no findings.
- `rejected` is not used in stage 2; rejection needs validation.

## Helper scripts

All use only the Python 3.9+ standard library, print JSON, and document their exit codes in `--help`.

| Script | Does |
| --- | --- |
| `find_threat_model.py` | Selects the newest valid, up-to-date stage 1 run copy, listing every other one with the reason it is unusable. |
| `start_findings.py` | The stage 1 gate and record skeleton (workflow step 3). Never overwrites an existing `findings.json`. |
| `list_scope_files.py` | Writes the scope inventory and reports exclusions by rule; also used by `start_findings.py`. |
| `normalize_findings.py` | Validates against the schema (a built-in validator for exactly the keywords the schema uses; an unknown keyword is an error), checks and normalizes locations and CWE IDs, enforces the in-scope rule, merges exact duplicates, computes fingerprints and hypothesis priorities, assigns IDs, and rewrites references. Idempotent; writes nothing when there are problems. |
| `check_findings.py` | Read-only gate: normalized form; no `<fill: ...>` placeholder left, record placeholders, exact model; target identity now; `security-guidance.md` saved; record not older than the model; stage 1 model digest, validity, run, target, freshness, and scope; authorization rules; reconciliation completeness and agreement with origins; merge accounting; carried-forward questions; coverage against the inventory; status rules. |
| `render_findings.py` | Writes `findings.md`; refuses input that fails the schema or is not normalized. |
| Shared copies | `target_identity.py` (now also importable: `resolve()` and `identify()`), `prepare_workspace.py`, `resolve_security_md.py`, `check_citations.py`, `check_model.py`. |

Known limit: for a non-Git target, a user-chosen output folder inside the target that is not named `.defense-factory` changes the target's snapshot digest as outputs are written, so `check_findings.py` reports the record as stale. The default `.defense-factory/` folder does not have this problem.

Moved or copied folders (0.4.0): a target without a Git remote is identified by its absolute path, so a model made on a copy elsewhere (for example a cloud workspace) has a different `target_id`. The model is accepted when its version (commit, or content digest for its own scope) matches exactly; `find_threat_model.py` and `start_findings.py` report "same code, different location" and the record keeps it as an assumption. A different `target_id` for a target identified by its remote URL is a different repository and is rejected.

## Skill layout

```text
skills/finding-discovery/
├── SKILL.md
├── agents/openai.yaml
├── evals/cases.json
├── references/
│   ├── method.md                 packets, baseline and investigator briefs, perspectives, finding bar, confidence
│   ├── discovery-checklist.md    instance-enumeration rules by vulnerability family
│   ├── inputs-and-authorization.md   stage 1 gate, narrow scans, seeds, precedence, authorization, scope, outputs
│   ├── finding-format.md         filling findings.json, reconciliation, deduplication, coverage, status, fixes
│   ├── record-and-status.md      shared copy
│   └── evidence-and-handling.md  shared copy
├── assets/
│   ├── findings.schema.json
│   └── findings-example.json
└── scripts/
    ├── find_threat_model.py, start_findings.py, list_scope_files.py, normalize_findings.py, check_findings.py, render_findings.py
    └── target_identity.py, prepare_workspace.py, resolve_security_md.py, check_citations.py, check_model.py   (shared copies)
```

The findings schema stays only in this skill until stage 3 consumes it; it then moves to `shared/`.

## Shared resources

Following the "Shared skill resources" rule in the plugin guidelines, extended from `references/` and `assets/` to `scripts/`:

```text
shared/
├── README.md
├── manifest.json            each master file -> the skills that receive it
├── references/record-and-status.md       common fields plus a section per stage
├── references/evidence-and-handling.md
└── scripts/target_identity.py, prepare_workspace.py, resolve_security_md.py,
            check_citations.py, check_model.py
scripts/sync-shared.py       copies masters into skills; --check reports drift without writing
```

- `shared/<folder>/<file>` is copied to `skills/<name>/<folder>/<file>`.
- `scripts/check-package.py` fails when a mapped copy is missing or differs from its master, a master file is not in the manifest, the manifest names a missing file or skill, or a skill holds a copy of a shared file without being listed for it.
- The stage 2 changes to the shared files change the `threat-model` skill's `skill_version`, so models stored by 0.2.0 are not reused by the next release. This is intended.

## Deferred

- Diff, commit, branch, and pull-request scans (Codex's compact and code diff workflows, `relevant_lines`).
- Repeated deep scans with a reducer; SARIF export.
- An answer key and scoring rubric in `evals/` (deferred since stage 1).

## Dry runs

Two fresh-context agents followed the skill on a small, deliberately vulnerable demo app with a hand-written stage 1 model (outside the repository). The first finished `complete`: every script passed on its first real use, and it found all planted weaknesses, including two the threat model omitted. Its feedback led to these changes: the baseline brief now forbids reading `.defense-factory/` and never receives the stage 1 model; the baseline returns the exact finding fields; `discovered_by` became a list; the merge rule is defined by a shared root control; missing controls have an anchoring rule; confidence is rated by the weakest link; `check_findings.py` requires `security-guidance.md` and a record no older than the model; `SKILL.md` says when to set `complete` and when to delegate.

## Build order

1. Done: `shared/`, the manifest, `sync-shared.py`, the package-check rule, and tests.
2. Done: the findings schema and example, the four new scripts, the stage 2 section of the shared record reference, and tests.
3. Done: `SKILL.md`, the four references, `agents/openai.yaml`, eval cases, and `start_findings.py`.
4. Live runs in Claude Code, ChatGPT/Codex, and Cursor on the authorized test app, starting from a stage 1 record; then a 0.3.0 release.
