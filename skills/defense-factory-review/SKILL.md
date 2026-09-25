---
name: defense-factory-review
description: Run a Defense Factory review of an authorized code repository, folder, or path by performing the implemented Defense Factory stages in order in one run, stage 1 (threat model) then stage 2 (finding discovery), handing each stage's record to the next without extra prompts, and reporting the combined result. Use when the user asks for a Defense Factory review, for example "do a Defense Factory review of this repository" or "run a Defense Factory review on services/api". Do not use when the user asks only for a threat model or only for finding discovery (those skills run one stage on their own), or to confirm, exploit, or fix a vulnerability.
---

# Defense Factory review

Run the implemented Defense Factory stages in order on one target, in one run, and report the result as a whole. Today that is stage 1 (`threat-model`) then stage 2 (`finding-discovery`). Stages 3 to 6 (isolated validation, patch preparation, human review, revalidation) are not implemented: the review ends after stage 2 and says so.

This skill only sequences the stages. Each stage follows its own skill's instructions and writes its own records; this skill never does a stage's work itself.

## Preconditions

1. **Both stage skills are available.** This review needs the `threat-model` and `finding-discovery` skills from the same Defense Factory plugin. If either is not installed (for example after a single-skill install), say which one is missing and stop. Never imitate a missing stage.
2. **Target and scope.** Use the target the user named (default: the current workspace root) and any narrower paths they gave. Pass the same target and scope to both stages. Do not widen it.
3. **No confirmation prompts.** The user's request for the review is the request for both stages; the stages record it themselves. If the user says they are not authorized, or that the owner has not permitted the assessment, stop with nothing run.

## Workflow

1. **Say what will happen, once.** Tell the user the review runs stage 1 (threat model) and then stage 2 (finding discovery), that stage 2 reads the in-scope code thoroughly and can take a long time, and that they can ask to stop after stage 1.
2. **Stage 1.** Perform the `threat-model` skill on the target and scope, following its instructions completely. Invoke it by name the way the client allows (for example `/defense-factory-plugin:threat-model` in Claude Code, `$threat-model` in Codex, or the skill picker in Cursor), or load its `SKILL.md` and follow it. Note its run folder, run ID, and status.
   - `blocked`: stop the review and report the blocker.
   - `complete` or `inconclusive`: continue to stage 2 without asking the user.
3. **Stage 2.** Perform the `finding-discovery` skill on the same target and scope, following its instructions completely. Its `find_threat_model.py` should select the stage 1 model just produced; confirm that the run ID it selects equals stage 1's run ID, so both stages share one run folder and stage 2 carries the stage 1 request forward. If it selects a different run or no usable model, stop and report what it returned instead of guessing.
4. **Between and within stages, ask the user only when a stage's own instructions require a decision** (for example a stale model or an unsafe output location). Otherwise keep going.
5. **Report.** Give one summary:
   - target, scope, and the run folder (`.defense-factory/runs/<run_id>/`);
   - stage 1: status, hypotheses by priority, and the main open questions, with the path of `threat-model.md`;
   - stage 2: status, findings by confidence, dispositions by type, and coverage, with the path of `findings.md`;
   - the overall status: the weakest stage status (`blocked`, then `inconclusive`, then `complete`);
   - next step: stage 3 (isolated validation) is not available yet, so the findings stay unvalidated; suggest human triage, starting with the highest-priority findings.

## Failure conditions

- **A stage fails or stops:** report its status and reason exactly as that stage recorded it. Never mark a stage done that did not run, and never write or edit another stage's records by hand.
- **The session runs out during stage 2:** stage 2 saves its work as `inconclusive`. Report that, and tell the user they can finish later by asking to run stage 2 in a new session; `find_threat_model.py` will select the same stage 1 model if the code has not changed.
- **The user asks to stop after stage 1:** report stage 1 and say that stage 2 can be run later on its own.
