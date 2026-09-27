---
name: defense-factory-review
description: Run a Defense Factory review of an authorized code repository, folder, or path by performing the implemented stages in order in one run, stage 1 (threat model), stage 2 (finding discovery), stage 3 (isolated validation), stage 3b (attack-path analysis, rating severity and priority), then stage 4 (patch preparation, preparing and verifying a fix for each reportable finding), handing each stage's record to the next without extra prompts, and reporting the combined result. Stages 3 and 4 build and run a disposable container on the user's own computer; stage 4 records a diff per fix and never modifies the working tree. Use when the user asks for a Defense Factory review, for example "do a Defense Factory review of this repository" or "run a Defense Factory review on services/api". Do not use when the user asks only for a threat model, only for finding discovery, only to validate findings, only to rate severity, or only to prepare patches (those skills run one stage on their own).
---

# Defense Factory review

Run the implemented Defense Factory stages in order on one target, in one run, and report the result as a whole. Today that is stage 1 (`threat-model`), then stage 2 (`finding-discovery`), then stage 3 (`finding-validation`), then stage 3b (`attack-path-analysis`), then stage 4 (`patch-preparation`). Stages 5 and 6 (human review, revalidation) are not implemented: the review ends after stage 4 and says so.

This skill only sequences the stages. Each stage follows its own skill's instructions and writes its own records; this skill never does a stage's work itself.

## Preconditions

1. **All five stage skills are available.** This review needs the `threat-model`, `finding-discovery`, `finding-validation`, `attack-path-analysis`, and `patch-preparation` skills from the same Defense Factory plugin. If any is not installed (for example after a single-skill install), say which one is missing and stop. Never imitate a missing stage.
2. **Target and scope.** Use the target the user named (default: the current workspace root) and any narrower paths they gave. Pass the same target and scope to every stage. Do not widen it.
3. **No confirmation prompts.** The user's request for the review is the request for every stage; the stages record it themselves. If the user says they are not authorized, or that the owner has not permitted the assessment, stop with nothing run.

## Workflow

0. **Check prerequisites before stage 1.** Run `scripts/check_environment.py` (with `python3`). It checks what stage 3 needs: Docker Desktop installed, running, reachable from this session, and with enough memory. Stages 1 and 2 need only Python 3.9 or later.
   - **All met** (exit 0): mention it in one line in step 1 and continue.
   - **Something is not met** (exit 1): before starting any stage, tell the user, for each entry in the script's `unmet` list:
     - **What is not met:** the entry's `prerequisite` and `problem`, in plain words.
     - **How to fix it:** the entry's `fix` steps, numbered, in order, followed by how to confirm the fix (its `verify` command).

     Then **stop**: run no stage and write no records. Ask the user to fix the prerequisites and then send the review request again. Do not offer to run stages 1 and 2 without stage 3, and never run the target on the host as a substitute.
   - **Python is not available** (the check cannot run): tell the user the prerequisite **Python 3.9 or later** is not met; to fix it, install Python 3.9 or later (from python.org, or with the system's package manager) and confirm with `python3 --version`. Then stop and ask the user to send the review request again once Python is installed.
1. **Say what will happen, once.** Tell the user the review runs stage 1 (threat model), stage 2 (finding discovery), stage 3 (isolated validation), stage 3b (attack-path analysis, which rates each validated finding's severity and priority), and stage 4 (patch preparation, which prepares and verifies a fix for each reportable finding); that stage 2 reads the in-scope code thoroughly and can take a long time; that **stages 3 and 4 build and run a disposable container** on their computer to test the findings and the fixes, that nothing personal enters it and their working tree is never modified (stage 4 records a diff per fix for them to apply later, after review), and that everything the run creates is deleted afterward; and that they can ask to stop after any stage.
2. **Stage 1.** Perform the `threat-model` skill on the target and scope, following its instructions completely. Invoke it by name the way the client allows (for example `/defense-factory-plugin:threat-model` in Claude Code, `$threat-model` in Codex, or the skill picker in Cursor), or load its `SKILL.md` and follow it. Note its run folder, run ID, and status.
   - `blocked`: stop the review and report the blocker.
   - `complete` or `inconclusive`: continue to stage 2 without asking the user.
3. **Stage 2.** Perform the `finding-discovery` skill on the same target and scope, following its instructions completely. Its `find_threat_model.py` should select the stage 1 model just produced; confirm that the run ID it selects equals stage 1's run ID, so the stages share one run folder and stage 2 carries the stage 1 request forward. If it selects a different run or no usable model, stop and report what it returned instead of guessing.
   - `blocked`: stop the review and report the blocker.
   - `complete` or `inconclusive`: continue to stage 3 without asking the user.
4. **Stage 3.** Perform the `finding-validation` skill on the same target and scope, following its instructions completely. It runs `check_environment.py` first and its `find_findings.py` should select the stage 2 record just produced; confirm the run ID matches, so all three stages share one run folder and stage 3 carries the request forward.
   - If Docker became unavailable after step 0 passed, do **not** discard stages 1 and 2: report them, record stage 3 as `inconclusive`, tell the user what is not met and how to fix it (as in step 0), and that they can then rerun stage 3 on its own.
   - `blocked` for any other reason: report it as the stage 3 result.
   - `complete` or `inconclusive`: continue to stage 3b without asking the user.
5. **Stage 3b.** Perform the `attack-path-analysis` skill on the same target, following its instructions completely. Its `find_validations.py` should select the stage 3 record just produced; confirm the run ID matches, so every stage shares one run folder and stage 3b carries the request forward. It reads code and records only; it runs nothing.
   - If stage 3 validated no finding as `confirmed` or `inconclusive`, stage 3b has nothing to rate: record that in the summary and skip it.
   - `blocked`: report it as the stage 3b result.
   - `complete` or `inconclusive`: continue to stage 4.
6. **Stage 4.** Perform the `patch-preparation` skill on the same target, following its instructions completely, when stage 3b rated at least one finding `reportable`. Its `find_attack_paths.py` should select the stage 3b record just produced; confirm the run ID matches, so every stage shares one run folder and stage 4 carries the request forward. It builds a disposable container and records a diff per fix; it never modifies the working tree.
   - If stage 3b produced no `reportable` finding, stage 4 has nothing to prepare: record that in the summary and skip it.
   - If Docker became unavailable after step 0 passed, do **not** discard stages 1 to 3b: report them, record stage 4 as `inconclusive`, tell the user what is not met and how to fix it (as in step 0), and that they can then rerun stage 4 on its own.
   - `blocked` for any other reason: report it as the stage 4 result.
   - `complete` or `inconclusive`: continue to the report.
7. **Between and within stages, ask the user only when a stage's own instructions require a decision** (for example a stale model or an unsafe output location). Otherwise keep going.
8. **Report.** Give one summary:
   - target, scope, and the run folder (`.defense-factory/runs/<run_id>/`);
   - stage 1: status, hypotheses by priority, and the main open questions, with the path of `threat-model.md`;
   - stage 2: status, findings by confidence, dispositions by type, and coverage, with the path of `findings.md`;
   - stage 3: status, verdicts by type (`confirmed`, `rejected`, `inconclusive`), the engine and architecture used, and that all run resources were cleaned up, with the path of `validation.md`;
   - stage 3b: status, and a table of the analysed findings in priority order (finding, severity, priority, decision), with the path of `attack-paths.md`;
   - stage 4: status, outcomes by type (`fixed`, `no_change`, `blocked`, `inconclusive`), the engine and architecture used, and that all run resources were cleaned up, with the path of `patches.md`;
   - the overall status: the weakest stage status (`blocked`, then `inconclusive`, then `complete`);
   - next step: stage 5 (human review) is not available yet, so the prepared diffs await human review before they are applied to the code; suggest reviewing them in priority order (P0 first), and closing the `deferred` findings' proof gaps so they can be patched later.

## Failure conditions

- **A stage fails or stops:** report its status and reason exactly as that stage recorded it. Never mark a stage done that did not run, and never write or edit another stage's records by hand.
- **A prerequisite is not met:** before any stage starts, say what is not met and exactly how to fix it, as in step 0, then stop and ask the user to rerun the review request once it is fixed. Run nothing in the meantime, and never run the target on the host.
- **The session runs out during stage 2, 3, 3b, or 4:** that stage saves its work as `inconclusive`. Report it, and tell the user they can finish later by asking to run that stage in a new session; the finder scripts will select the same earlier records if the code has not changed.
- **The user asks to stop after any stage:** report the stages run so far and say that the remaining stages can be run later on their own.
