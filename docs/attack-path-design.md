# Stage 3b design: attack-path analysis and severity

Design for the `attack-path-analysis` skill. It gives each validated finding a **severity and a priority**, derived from an evidence-based attack path, so that stage 4 (patch preparation) knows what to fix first. Capability parity with Codex Security's skill of the same name is tracked in [attack-path-parity.md](attack-path-parity.md).

The user approved this design on 2026-09-26 and the skill is built (unreleased). The four design decisions the user confirmed are listed near the end.

## Why this stage exists

The six-stage contract in [workflow-contracts.md](workflow-contracts.md) has a gap: **no stage owns severity.** Stage 2 does not assign it ("discovery does not own severity"); stage 3 defers it ("severity belongs to a later stage"); stage 4 needs it to order the fixes. Codex Security fills the same slot with its `attack-path-analysis` phase, run right after validation. Stage 1 already writes a target-specific severity calibration table that nothing consumes yet; this stage consumes it.

## Placement (recommended; open decision 1)

A separate skill, `attack-path-analysis`, recorded as **sub-stage 3b** of the isolated-validation stage:

- stage folder `.defense-factory/runs/<run_id>/3b-attack-path-analysis/`, in the same run as stages 1 to 3;
- run by `defense-factory-review` after `finding-validation`, and runnable on its own ("how severe is FD-3?", "calibrate the severity of the confirmed findings");
- the six-stage contract keeps its numbering; stage 3's output gains "severity and priority for validated findings (3b)".

Why a separate skill rather than a final step of `finding-validation`: it has different inputs (the stage 3 record plus the threat model and policy) and a different method (reasoning over evidence, no container). It must be re-runnable when policy or deployment facts change, without rebuilding containers. It also keeps `finding-validation` focused, and maps one to one to Codex Security.

## Scope of the skill

- **Activates for:** calibrating the severity or priority of validated findings; tracing a validated finding from attacker to impact; running stage 3b on its own.
- **Does not activate for:** threat modeling, discovery, validation, fixing, or reviewing a diff; a full Defense Factory review (the review skill sequences the stages).
- **Read-only and offline.** No network, no container, no running the target. It reasons over the code and over the evidence stages 1 to 3 already recorded.

## Inputs

1. **The stage 3 record.** `find_validations.py` selects the newest `3-finding-validation/validations.json` that passes `check_validations.py` (which also re-checks the stage 2 record and that the code has not changed since). Its path and sha256 are recorded.
2. **Eligible findings.** A validation is eligible when its verdict is `confirmed` or `inconclusive`. A `rejected` finding is not analysed; it is listed under `not_eligible` with its VD id, so that coverage stays explicit.
3. **The stage 1 threat model:** its in-scope attackers, trust boundaries, and **severity calibration table**, which gives examples and counterexamples per level for this target.
4. **The stage 2 finding** for each validation: attacker, source, control, sink, labelled locations (the `root_control` line is preserved), exposure assumptions, and `hypothesis_priority` as the starting point.
5. **The resolved security policy** (`security-guidance.md` from the stage 2 run) as policy data. Codex's attack-path phase does not use it; ours does, as an addition.

The user may name specific findings (`FD-3`); the rest are then listed as not selected, as stage 3 does.

## Method

Three sub-steps, kept separate and never merged (Codex parity). Once the facts are set, severity is not re-argued.

### 1. Facts

For each eligible finding:

- **Scope gate:** is it a real security vulnerability (not a correctness bug), in scope under the threat model, and on a product surface or production workflow?
- **Structured facts:**
  - vector: `remote`, `local_network`, `localhost`, `none`, or `unknown`;
  - auth scope: `public`, `internal-only`, `admin-only`, or `unknown`;
  - exposure (from listeners, bind addresses, routing, manifests);
  - identity and trust boundary crossed;
  - preconditions: `plausible`, `unlikely`, `unachievable`, or `unknown`;
  - attacker input control: `yes`, `plausible`, `no`, or `unknown`;
  - impact surface;
  - target reach;
  - existing controls and mitigations;
  - secrets involved, **by name and location only**;
  - blind spots.
- **Dataflow** (source → transformations → sink → outcome) and **reachability** (attacker → entry point → preconditions → outcome), written as numbered attacker steps. Stage 3's evidence is reused: a finding confirmed through the app's real interface has proven reachability. A static-only verdict does not.
- **Counterevidence pass**, before anything is final. For each interpretive fact, look for evidence that the path is out of scope, internal-only, admin-only, not cross-boundary, or not reachable, and state whether that evidence is **dispositive**. Missing ingress or deployment evidence is a proof gap, never dispositive on its own.

### 2. Calibration

Rate **impact** and **likelihood** separately (`high`, `medium`, `low`, `ignore`, `unknown`):

- Start from stage 2's hypothesis priority, then adjust with the facts, using stage 1's calibration table for this target and the security policy.
- Likelihood follows the vector: `remote` is usually high, `local_network` usually medium, `localhost` usually low.
- **Escalate** for: unauthenticated or internet reach; zero-click; cross-tenant impact; compromise of signing, identity, or cloud credentials; persistence or mass exploitation; proven code execution.
- **Downgrade** for: localhost-only or self-only paths; constrained or unrealistic preconditions; already-privileged attackers, unless the privilege gain *is* the issue.
- **Keep confidence separate from impact.** An unproven high-impact path is high impact with low confidence, not medium severity. This is stage 1's existing rule.

### 3. Policy (mechanical, and enforced by a script)

Apply in this order:

1. **Hard suppression → `ignore`:** self-only impact; unachievable or highly unrealistic preconditions; privileged, operator, developer, or physical-access preconditions.
2. **Reportability gate:** no realistic lower-privileged, in-scope attacker path → `ignore`.
3. **Matrix** (impact × likelihood):

   | Impact ↓ / Likelihood → | high | medium | low | unknown | ignore |
   | --- | --- | --- | --- | --- | --- |
   | **high** | critical (only if the critical criteria are met), else high | medium | low | medium | ignore |
   | **medium** | medium | low | low | low | ignore |
   | **low** | low | low | low | low | ignore |
   | **unknown** | medium | low | low | low | ignore |
   | **ignore** | ignore | ignore | ignore | ignore | ignore |

4. **Floor:** a finding that is not ignored never goes below `low`.
5. **Priority:** critical P0, high P1, medium P2, low P3; `ignore` gets no priority.

`check_attack_paths.py` **recomputes** steps 1 to 5 from the recorded facts and ratings, and rejects any severity that disagrees. Codex states "do not re-argue severity after the matrix" as an instruction; here it becomes a check.

### Decisions

| Decision | Requires |
| --- | --- |
| `reportable` | severity `critical`, `high`, `medium`, or `low`; **only for a `confirmed` stage 3 verdict** |
| `ignore` | severity `ignore`, plus the suppression reason or dispositive counterevidence |
| `deferred` | a provisional severity or `unknown`, plus the exact `proof_gap`. **Required for an `inconclusive` verdict**: an unconfirmed finding never gets a final severity |

Every decision also records dataflow, reachability, counterevidence, impact, likelihood, severity rationale, and **change conditions**: the concrete evidence that would raise or lower the severity. Independently attackable siblings are analysed separately, and a cleaner neighbouring story is never a reason to skip a finding.

## Outputs

`.defense-factory/runs/<run_id>/3b-attack-path-analysis/`:

| File | Purpose |
| --- | --- |
| `attack-paths.json` | The canonical record: the stage record; references to the consumed stage 3 record, threat model, and policy; one analysis per eligible finding; `not_eligible`; open questions. Stage 4 reads it, in priority order. |
| `attack-paths.md` | Rendered for reviewers: the header with counts by severity and decision, a priority table, then one section per finding. Each section has the affected lines by role, numbered attacker steps, facts as bullets, counterevidence, calibration, decision, and change conditions. |

Each analysis has these fields:

- identity: `id` (`AP-n`), `validation_id`, `finding_id`, `finding_key`, `fingerprint`, `title`;
- the preserved `locations`;
- the analysis: `facts`, `attacker_steps`, `dataflow`, `reachability`, `counterevidence` (a list of `{fact, evidence, dispositive}`);
- the ratings: `impact`, `likelihood`, `suppression` (null or a reason);
- the result: `severity`, `severity_rationale`, `change_conditions`, `proof_gap`, `decision`, `priority`, and `confidence` (level and reason, separate from severity).

## Status

- **`complete`:** every eligible finding has exactly one analysis, and the checks pass.
- **`inconclusive`:** some eligible findings could not be analysed (for example, missing source), or the run stopped early.
- **`blocked`:** no usable stage 3 record, or the user says they are not authorized.

## Helper scripts

All use only the Python 3.9+ standard library and print JSON.

| Script | Does |
| --- | --- |
| `find_validations.py` | Selects the newest valid, up-to-date stage 3 record. |
| `start_attack_paths.py` | The stage 3 gate and the record skeleton: one entry per eligible finding, with `<fill: ...>` markers and the preserved locations. Never overwrites an existing record. |
| `normalize_attack_paths.py` | Validates against the schema, assigns `AP-n` in priority order, and derives the priority. |
| `check_attack_paths.py` | Read-only gate: coverage (exactly one analysis per eligible finding), eligibility, the decision rules and the verdict rule, the recomputed policy and matrix, digests of the consumed records, placeholders, and status. |
| `render_attack_paths.py` | Writes `attack-paths.md`. |
| Shared copies | Stage 3b reads stage 3's record, so `validations.schema.json`, `check_validations.py`, and `normalize_validations.py` move to `shared/` (the same pattern used when stage 3 consumed stage 2's record), alongside the existing shared helpers. |

## Integration

- **`defense-factory-review`** runs 1 → 2 → 3 → 3b. The summary gains a severity and priority table. The overall status is still the weakest stage status.
- **Stage 4 (later)** consumes `reportable` analyses in priority order; `deferred` ones are listed as awaiting proof.
- **`workflow-contracts.md`**: stage 3's output gains "severity, priority, and attack path for validated findings (3b)".

## Changes after the first dry run (2026-09-26)

A fresh agent following only the skill's instructions ran it on a real 12-finding stage 3 record. It was stopped partway by a safety classifier while writing attacker steps, but it reported these gaps, now fixed:

- **Calibration versus the matrix.** Stage 1's table was said to "outrank" the generic policy, but the check accepted only the matrix result. The sanctioned exception is now an explicit, checked `calibration_override`, quoting the stage 1 row and giving its level. It may not be combined with a suppression and must differ from the matrix. This is the same lever Codex Security gives the threat model.
- **`critical_criteria_met`** is defined as a necessary condition: high impact, an escalator, a match to stage 1's Critical row, and no stage 1 counterexample.
- **Configuration-dependent confirmed findings are `reportable`.** A non-default bind, an `http:` URL, or a victim visiting a page are preconditions that lower likelihood, not reasons to defer.
- **Facts:**
  - a `product_surface` gate fact;
  - `not-applicable` as an `auth_scope`, for outbound findings;
  - `vector` guidance for attacks delivered through the victim's browser (the attacker is `remote`).
- **Attacker steps are written at vulnerability-report level:** no payloads or request bodies.
- **Smaller fixes:**
  - stage 3's evidence outranks a contradicting stage 1 claim;
  - a new request under inherited authorization goes in `inputs`;
  - a warning about backticked `host:port` being read as a citation.

## Changes after the second dry run (2026-09-26)

A second fresh agent, using the fixed instructions, completed the same 12-finding record:

- status `complete`, with every check and all 75 citations passing on the first try;
- 10 reportable, 1 deferred, 1 ignored.

It showed that the calibration override was the norm rather than the exception: 7 of 12 findings needed one. The cause was **double-counting**. Stage 1's rows already price preconditions in ("a *visited* page…"), and the method then lowered likelihood again for the same precondition. Fixes:

- a fixed precondition rule: `plausible` means no change, `unlikely` one step down, `unachievable` suppressed;
- a precondition the cited stage 1 row already names is not counted again;
- a configuration-dependent vector is rated under the configuration the finding needs;
- `auth_scope` describes the endpoint's own control;
- a threat-model scope exclusion counts as dispositive;
- a deferred finding with unknown impact gets severity `unknown`;
- stage 3 overrides stage 1 prose, as well as table rows;
- guidance for findings that depend on another finding;
- stage 3 evidence is cited, not restated. The skeleton no longer copies stage 3's text.

## Decisions confirmed by the user (2026-09-26)

1. **Placement:** a separate skill `attack-path-analysis` as sub-stage 3b. Rejected alternatives: a final step inside `finding-validation`; the first step of stage 4.
2. **Review integration:** `defense-factory-review` runs it automatically after stage 3 (1 → 2 → 3 → 3b).
3. **Severity scale:** Codex's `critical` / `high` / `medium` / `low` / `ignore`, with P0 to P3. Rejected alternative: CVSS.
4. **Inconclusive findings:** analysed, but only ever `deferred` with a provisional severity. Rejected alternative: skip them until confirmed.

## Build order (after approval)

1. Shared moves (the stage 3 schema and checks) and the stage 3b section of the shared record reference.
2. Schema, example, and the five scripts with tests, including matrix and suppression tests for every cell.
3. `SKILL.md`, references (the method, the severity policy, the facts and counterevidence checklist), `agents/openai.yaml`, and eval cases.
4. `defense-factory-review` integration and the contract update.
5. Package check, tests, then a dry run on the ThreatStream stage 3 record, which already has eight confirmed findings.
