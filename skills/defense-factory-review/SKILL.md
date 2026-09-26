---
name: defense-factory-review
description: Run a Defense Factory review of an authorized code repository, folder, or path by performing the implemented Defense Factory stages in order in one run, stage 1 (threat model), then stage 2 (finding discovery), then stage 3 (isolated validation), handing each stage's record to the next without extra prompts, and reporting the combined result. Stage 3 builds and runs a disposable container on the user's own computer to test the findings. Use when the user asks for a Defense Factory review, for example "do a Defense Factory review of this repository" or "run a Defense Factory review on services/api". Do not use when the user asks only for a threat model, only for finding discovery, or only to validate findings (those skills run one stage on their own), or to fix a vulnerability.
---

# Defense Factory review

Run the implemented Defense Factory stages in order on one target, in one run, and report the result as a whole. Today that is stage 1 (`threat-model`), then stage 2 (`finding-discovery`), then stage 3 (`finding-validation`). Stages 4 to 6 (patch preparation, human review, revalidation) are not implemented: the review ends after stage 3 and says so.

This skill only sequences the stages. Each stage follows its own skill's instructions and writes its own records; this skill never does a stage's work itself.

## Preconditions

1. **All three stage skills are available.** This review needs the `threat-model`, `finding-discovery`, and `finding-validation` skills from the same Defense Factory plugin. If any is not installed (for example after a single-skill install), say which one is missing and stop. Never imitate a missing stage.
2. **Target and scope.** Use the target the user named (default: the current workspace root) and any narrower paths they gave. Pass the same target and scope to every stage. Do not widen it.
3. **No confirmation prompts.** The user's request for the review is the request for every stage; the stages record it themselves. If the user says they are not authorized, or that the owner has not permitted the assessment, stop with nothing run.

## Workflow

1. **Say what will happen, once.** Tell the user the review runs stage 1 (threat model), stage 2 (finding discovery), and stage 3 (isolated validation); that stage 2 reads the in-scope code thoroughly and can take a long time; that **stage 3 builds and runs a disposable container** on their computer to install prerequisites and test the findings, that nothing personal enters it and their working tree is never modified, and that everything the run creates is deleted afterward; and that they can ask to stop after stage 1 or stage 2.
2. **Stage 1.** Perform the `threat-model` skill on the target and scope, following its instructions completely. Invoke it by name the way the client allows (for example `/defense-factory-plugin:threat-model` in Claude Code, `$threat-model` in Codex, or the skill picker in Cursor), or load its `SKILL.md` and follow it. Note its run folder, run ID, and status.
   - `blocked`: stop the review and report the blocker.
   - `complete` or `inconclusive`: continue to stage 2 without asking the user.
3. **Stage 2.** Perform the `finding-discovery` skill on the same target and scope, following its instructions completely. Its `find_threat_model.py` should select the stage 1 model just produced; confirm that the run ID it selects equals stage 1's run ID, so the stages share one run folder and stage 2 carries the stage 1 request forward. If it selects a different run or no usable model, stop and report what it returned instead of guessing.
   - `blocked`: stop the review and report the blocker.
   - `complete` or `inconclusive`: continue to stage 3 without asking the user.
4. **Stage 3.** Perform the `finding-validation` skill on the same target and scope, following its instructions completely. It runs `check_environment.py` first and its `find_findings.py` should select the stage 2 record just produced; confirm the run ID matches, so all three stages share one run folder and stage 3 carries the request forward.
   - If `check_environment.py` finds no usable container engine, do **not** fail the whole review: report stages 1 and 2, record that stage 3 could not run for lack of an engine (its status is `inconclusive` with the remediation), and tell the user how to enable it and rerun stage 3 on its own.
   - `blocked` for any other reason: report it as the stage 3 result.
   - `complete` or `inconclusive`: continue to the report.
5. **Between and within stages, ask the user only when a stage's own instructions require a decision** (for example a stale model or an unsafe output location). Otherwise keep going.
6. **Report.** Give one summary:
   - target, scope, and the run folder (`.defense-factory/runs/<run_id>/`);
   - stage 1: status, hypotheses by priority, and the main open questions, with the path of `threat-model.md`;
   - stage 2: status, findings by confidence, dispositions by type, and coverage, with the path of `findings.md`;
   - stage 3: status, verdicts by type (`confirmed`, `rejected`, `inconclusive`), the engine and architecture used, and that all run resources were cleaned up, with the path of `validation.md`;
   - the overall status: the weakest stage status (`blocked`, then `inconclusive`, then `complete`);
   - next step: stage 4 (patch preparation) is not available yet, so the confirmed findings await a fix; suggest human triage, starting with the confirmed findings, then the highest-priority unvalidated ones.

## Failure conditions

- **A stage fails or stops:** report its status and reason exactly as that stage recorded it. Never mark a stage done that did not run, and never write or edit another stage's records by hand.
- **No container engine for stage 3:** report stages 1 and 2 and record stage 3 as `inconclusive` with the remediation from `check_environment.py`; the findings stay unvalidated. Do not run the target on the host.
- **The session runs out during stage 2 or 3:** that stage saves its work as `inconclusive`. Report it, and tell the user they can finish later by asking to run that stage in a new session; the finder scripts will select the same earlier records if the code has not changed.
- **The user asks to stop after stage 1 or stage 2:** report the stages run so far and say that the remaining stages can be run later on their own.
