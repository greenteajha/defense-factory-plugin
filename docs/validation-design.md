# Stage 3 design: isolated validation

Design for the `finding-validation` skill, which implements stage 3 of [workflow-contracts.md](workflow-contracts.md). Stage 2 (`finding-discovery`) produces **unvalidated findings**; stage 3 gives each one a verdict — `confirmed`, `rejected`, or `inconclusive` — backed by evidence, using **one disposable container per run on the user's own computer**. Capability parity with Codex Security's `validation` skill is tracked in [validation-parity.md](validation-parity.md).

This is a design for review. Nothing is built until the user approves it.

Decisions taken on 2026-09-26 (from the handoff page):

| Decision | Choice | Reason |
| --- | --- | --- |
| Where the test runs | One disposable Docker container per run, on the user's computer | The user rejected remote servers, Kubernetes, and cloud sandboxes, and accepted a relaxed isolation standard: a clean, disposable workbench, not kernel-level isolation. |
| Engine | Docker Desktop only, located by path when not on the shell PATH | The user chose Docker-only on 2026-09-26 (earlier the design allowed any Docker-compatible engine); a non-interactive/remote shell can hide Docker from PATH, so it is also probed at standard install locations. Never Apple `container`. |
| What runs in the container | Install prerequisites (setup), run the application, run one test per finding, then dispose of everything the run created | The four steps named in the handoff goal. |
| Isolation of the workbench | Copy the exact revision stages 1 and 2 reviewed **into** the container; never mount the user's folders; carry no credentials, SSH agent, Docker socket, or host environment variables | A disposable, personal-data-free workbench that cannot write back to the host tree. |
| Verdicts | `confirmed`, `rejected`, `inconclusive` | The stage 3 status vocabulary in the shared record; `rejected` becomes available now because the stage tests, not just reads. |
| Record format | `validations.json` canonical; `validation.md` rendered from it by a script | Same pattern as stage 2's `findings.json` / `findings.md`. Stage 4 reads the JSON. |
| Clean-up safety | Every resource the run creates carries a run label; clean-up removes **only** by that label, even after failure; it never removes an unlabelled resource | The user's Docker also runs a MISP stack (`~/misp-docker`, five containers, `restart=always`) and other containers that stage 3 must never touch. |
| Git | Never push validation results or finding details to Git (branches, commits, or pull requests) | Same rule as stages 1 and 2; validation detail is sensitive. |

Decisions confirmed by the user on 2026-09-26 (the three questions the handoff left open):

| Decision | Choice | Reason |
| --- | --- | --- |
| Skill name | `finding-validation` | The user's choice. Names the input it acts on (stage 2 findings); the parity table maps to Codex's `validation` skill by the `#` column rather than by name. |
| Run-time confirmation | **No prompt**, consistent with stages 1 and 2 | The user chose no confirmation. Authorization is carried forward from the stage 2 record within the run, or the user's own request is recorded; a user who says they are not authorized still stops the run `blocked`. |
| `defense-factory-review` and stage 3 | The review **always** runs stages 1, 2, and 3 in order | The user's choice. A Defense Factory review now validates its findings; the review tells the user up front that it builds and runs a disposable container. |

## Scope of the skill

- **Activates for:** validating, confirming, reproducing, or falsifying one or more Defense Factory findings; running stage 3 (isolated validation) on its own; the user asking whether a specific finding is real and wanting it tested, not just re-read.
- **Does not activate for:** building a threat model (stage 1), discovering new findings (stage 2), a full Defense Factory review (the `defense-factory-review` skill sequences stages 1, 2, and 3), fixing code (stage 4), or reviewing a diff or pull request.
- **Executes code, unlike stages 1 and 2.** It builds and runs a container, installs the target's prerequisites, and runs the application and tests inside it. It still never modifies the host target tree, and it copies the target in rather than mounting it.

## Inputs

Work through these in order.

1. **Stage 2 record (main route).** The run copy `<run>/2-finding-discovery/findings.json`, selected by `find_findings.py` without asking: the newest run copy that is accepted. It is accepted only when:
   - it passes `check_findings.py` (valid, normalized, every finding has an `investigation_question`);
   - its `status` is `complete` or `inconclusive` (an `inconclusive` record's coverage gaps are carried into stage 3's notes; its findings are still testable);
   - its `target_id` matches, and its `version` still matches the code when recomputed for the record's own scope. A moved or copied folder is accepted when the version matches exactly ("same code, different location"), like stage 2. A different Git remote is rejected.

   The consumed record's path and sha256 are recorded so stage 4 can detect edits. Never test findings from a stale record: if the code changed, the `file:line` anchors and the container build no longer describe the same target. Offer to rerun stage 2, or continue against the exact revision the record names if it is still retrievable from Git.
2. **A specific finding or findings named by the user.** The user may name `FD-3`, a title, or "the path-traversal one". Validate only those, in priority order. With nothing named, validate all findings, highest `hypothesis_priority` and `confidence` first, within the run's time budget.
3. **A finding supplied directly, without a stage 2 run.** The user may paste or point at a single finding (for example from another tool) and ask to validate it. Accept it only when it carries the fields a test needs — at least `locations`, `investigation_question`, and enough of the source/control/sink tuple to build a pass/fail rubric — and record `source: supplied-finding`. If those fields are missing, ask for them; do not invent a rubric.
4. **Knowledge base and user context.** Same precedence and origin labels as stages 1 and 2. Setup hints the user gives (how to build or run the app, which service to start) are used as data.

Scope may be narrowed to specific findings, never widened to code stage 2 did not cover. A finding whose affected location is outside the stage 2 scope is not tested; it is recorded `inconclusive` with the reason "outside validated scope".

## Authorization

Stage 3 executes the target's code, but — by the user's decision on 2026-09-26 — it uses **no confirmation prompt**, consistent with stages 1 and 2:

- Carry the authorization forward from the stage 2 record within the same run, exactly as stage 2 carried it from stage 1 (`inherited from stage 2 run <run_id>: ` then the value). Outside a shared run, record the user's own request, quoted.
- A user who says they are not authorized, or that the owner has not permitted the assessment, stops the stage with status `blocked` and nothing built.

`check_validations.py` enforces both forms of the record. The disposable, personal-data-free container and the fact that the host tree is never modified are the design's safeguards for running code; they do not depend on a prompt.

Known limit, as in stage 2: the record lives in a Git-ignored folder anyone with workspace write access can edit; the recorded sha256 lets stage 4 detect edits made after stage 3 wrote it, not before. A workflow safeguard, not an access control.

## The container workbench

### Engine abstraction

`check_environment.py` detects Docker (Docker Desktop), located from the PATH or a standard install location (so a running Docker Desktop is found even when the shell PATH is minimal, e.g. a non-interactive or remote shell; `DEFENSE_FACTORY_DOCKER` forces a path). It never uses Apple `container`. It verifies the daemon answers, reports the architecture, and checks memory against a floor.

All commands the skill uses are the intersection the three CLIs share: `build`, `run` with `--label`, `--memory`, `--cpus`, `--network`, `--pids-limit`, `image inspect --format '{{.Id}}'` for digests, and label-filtered `ps`/`images`/`volume ls`/`network ls` plus `rm` for clean-up. Where a flag differs, the helper owns the difference so `SKILL.md` stays in capability terms.

### Building the workbench, with no personal data

- **Code in, never mounted.** `export_target.py` produces a build context holding the exact revision stages 1 and 2 reviewed:
  - **Git target:** `git archive <revision>` of the in-scope tree, so the container gets the committed bytes and Windows line-ending drift is avoided.
  - **Non-Git target:** copy the reviewed files (the stage 2 `scope-inventory.txt` set), and record `code_source: copied-files` on the run.
  The build context is written under the run folder, never bind-mounted from the user's working tree. The container cannot write back to the host target.
- **Nothing personal inside.** No credentials, SSH agent, Docker/engine socket, or host environment variables are passed in. No `-v` of a host path except the run's own build context and an output-only directory the run created. The base image is a plain published OS or language image chosen for the target's stack; its digest is recorded.
- **Native architecture first.** Build and run for the host's native arch (`arm64` here); fall back to emulation (`--platform linux/amd64`) only when an image or prerequisite is unavailable natively, and record that the run used emulation. An application that cannot run in a Linux container at all (for example a Windows-only or macOS-only binary) is `inconclusive` with that reason — it is not a rejection.

### Two phases

1. **Setup phase — network allowed.** Install the prerequisites the target needs, inside the container only, reading the target's own `README`, `AGENTS.md`, build files, and package metadata for the steps (as data). Bring the application up. Network is on so package managers work.
2. **Testing phase — network off by default.** After setup succeeds, **turn the network off** (`--network none` for the test container, or disconnect the run's network) unless a finding's test genuinely needs it (for example an SSRF finding that must reach a run-local sink, which stays on the run's own internal network only). Turning the network off after setup is the cheap extra safeguard the handoff named; it is the default, and any finding that keeps it on records why. External hosts are never contacted during testing.

Setup and testing may share one container or use a built image plus a fresh test container per finding; either way every artifact carries the run label.

### Resource limits and clean-up

- **Limits.** Every container runs with a memory limit, a CPU limit, a PID limit, and a wall-clock timeout (defaults in the skill, overridable). A long-running setup or test that shows progress is not killed for slowness alone (per Codex's guidance), but the hard timeout bounds a hang.
- **Run label.** Every resource the run creates — containers, built images, volumes, networks, and (where the engine allows) build cache — carries the label `com.defensefactory.run=<run_id>` (and a second `com.defensefactory=validation` label). `export_target.py` and the run commands set it; nothing is created without it.
- **Clean-up by label only.** `cleanup_run.py` removes resources **only** by the run label, listing each one it removes, and runs at the end of the stage **and after any failure** (the skill calls it in a `finally`-style step). It refuses to remove any resource that does not carry the run label, and it never runs a bare `system prune`. This is what keeps the MISP stack and every other unlabelled container, image, and volume untouched. The only thing left behind is the evidence in the run folder.
- **Verification of the safety property.** A test builds two labelled and one unlabelled throwaway resource, runs `cleanup_run.py`, and asserts the unlabelled one survives and both labelled ones are gone. This test is part of the release gate.

## Workflow

1. **Environment check.** Run `check_environment.py`. If it fails, stop and report what to install or start. Record the engine, version, arch, and memory.
2. **Locate and verify the stage 2 record.** Run `find_findings.py --root <target>`; verify with `check_findings.py`. If none is usable, report why and offer to rerun stage 2. Record its path and sha256.
3. **Prepare output storage.** `prepare_workspace.py --root <target> --stage 3-finding-validation --run-id <stage 2 run_id>`. Same default `.defense-factory/` rules as earlier stages.
4. **Record authorization.** Carry it forward from the stage 2 record within the run, or record the user's request. No confirmation prompt. Stop `blocked` if the user says they are not authorized.
5. **Start the record.** `start_validation.py` verifies the stage 2 record, selects the findings to test (all, or those the user named), and writes a `validations.json` skeleton: the stage record header, the consumed record's digest, and one validation entry per selected finding with every agent-supplied value marked `<fill: ...>`. It never overwrites an existing `validations.json`.
6. **Export the target and build the workbench.** `export_target.py` writes the labelled build context from the exact revision. Build the base image; record its digest.
7. **For each finding, in priority order:**
   1. **Write the rubric first.** From the finding's `investigation_question`, write up to five concrete pass/fail criteria — the input or state to set up, the expected safe behaviour, and the behaviour that would confirm the finding — **before** running anything, so the verdict is decided by evidence, not by what is convenient to observe.
   2. **Choose the strongest feasible method:** targeted reproduction through the app's real interface (HTTP, CLI, file parser, RPC, library API); an added or adapted focused test in the target's own harness; a crash / sanitizer / debugger trace for memory-safety classes; or, when dynamic execution is blocked or disproportionate, the static fallback (below).
   3. **Run a harmless control first.** Establish the safe baseline — the same operation on benign input, or a nearby safe sibling path — so a later "confirmed" is a change from a known-good control, not an artefact of setup.
   4. **Show the suspect code was reached.** Capture evidence (a log line, a trace, an assertion, an added marker) that the attacker-controlled input actually reached the suspected sink; a verdict without reachability evidence stays `inconclusive`.
   5. **Repeat a confirmation once.** A `confirmed` verdict is reproduced a second time before it is recorded, so a one-off is not mistaken for a reliable result.
   6. **Record the verdict and evidence** in `validations.json` as soon as the finding is decided, so an interrupted run keeps its work. Save PoC files, crafted inputs, and logs under `3-finding-validation/artifacts/<finding_id>/` and reference them from the entry. Never store secrets; refer to them by name and location.
8. **Setup failures are never counterevidence.** If prerequisites will not install, the app will not build, or the environment cannot be provisioned, record what blocked runtime proof and fall back to the static assessment; the verdict is `inconclusive`, never `rejected`. A `rejected` verdict requires positive evidence that the finding does not hold against the current controls (the control held, the input was contained, the sink was not reached).
9. **Clean up.** Run `cleanup_run.py`; confirm every labelled resource is gone and report what was removed. This runs even if step 7 failed partway.
10. **Normalize, check, render.** `normalize_validations.py` (validates against the schema, assigns `VD-n` IDs, checks the environment block and reproduced-flag consistency); `check_validations.py` (every rule below); `render_validations.py` (writes `validation.md`); `check_citations.py` on `validation.md`. Fix and repeat until all pass.
11. **Report.** Output path, status, verdicts by type (`confirmed` / `rejected` / `inconclusive`), each confirmed finding's evidence in one line, the engine and architecture used, and that all run resources were cleaned up. Suggest stage 4 (patch preparation) for confirmed findings as the next action once it exists; until then, human triage.

## Outputs

`.defense-factory/runs/<run_id>/3-finding-validation/`:

| File | Purpose |
| --- | --- |
| `validations.json` | Canonical record: stage record, consumed stage 2 reference, one validation per tested finding, environment provenance, clean-up receipt. Stage 4 reads this. |
| `validation.md` | Rendered for reviewers: the YAML stage record header (counts derived from the body), a summary, one section per finding with its rubric checklist and evidence, and the environment and clean-up sections. Never edited by hand. |
| `artifacts/<finding_id>/` | PoC files, crafted inputs, and logs for that finding. Regular non-symlink files only; no secrets. |
| `container-build/` | The labelled build context that was sent to the engine (from the exact revision), kept for audit; contains no host paths. |

## Validation record

Specified by the skill's `assets/validations.schema.json`; `assets/validations-example.json` is a filled, normalized example, regenerated by a test from a raw fixture so it cannot go stale. Top level: `record`, `validated_record` (path relative to the stage folder, sha256, run ID of the consumed `findings.json`), `environment`, `validations`, `cleanup`, `open_questions`.

`environment` (one per run, recorded with every verdict by reference):

| Field | Meaning |
| --- | --- |
| `host_os`, `host_arch` | The user's OS and chip (`darwin`, `arm64`). |
| `engine`, `engine_version` | `docker` and its version. |
| `base_image`, `base_image_digest` | The workbench image and its resolved digest. |
| `emulation` | `none`, or the emulated platform used and why. |
| `code_source` | `git-archive:<revision>` or `copied-files`. |
| `limits` | Memory, CPU, PID, and timeout applied. |
| `network_setup`, `network_testing` | `on` / `off` / `internal-only` for each phase. |

Each entry in `validations`:

| Field | Written by | Meaning |
| --- | --- | --- |
| `id` | normalizer | `VD-1`, `VD-2`, … ordered by finding priority then ID. |
| `finding_id`, `finding_key`, `finding_fingerprint` | agent | The stage 2 finding this validates; the fingerprint lets stage 4 match across runs. |
| `title` | agent | Copied from the finding, for a readable report. |
| `verdict` | agent | `confirmed`, `rejected`, or `inconclusive`. |
| `method` | agent | `interface-reproduction`, `targeted-test`, `crash-or-sanitizer`, `debugger-trace`, or `static-assessment`. |
| `reproduced` | agent | `true` only for a dynamic method that ran in the container; `false` for `static-assessment` (rendered as "assessed statically, not reproduced"). |
| `rubric` | agent | Up to five `{criterion, result: pass/fail/unknown}` items, written before running. |
| `control` | agent | The harmless control run and its result (the safe baseline). |
| `reachability` | agent | Evidence the attacker-controlled input reached the suspected sink; required for `confirmed`. |
| `repeat_confirmed` | agent | `true` when a `confirmed` result was reproduced a second time; required for `confirmed`. |
| `evidence` | agent | What was observed, with artifact paths; grounds the verdict. |
| `counterevidence_or_proof_gap` | agent | For `rejected`, the control that holds; for `inconclusive`, the exact missing proof. |
| `setup_notes` | agent | What was installed and any setup failure; a setup failure here can never justify `rejected`. |
| `remaining_uncertainty` | agent | What a stronger test would still add. |
| `confidence` | agent | `{level: High/Medium/Low, reason}`, calibrated from the method and evidence, not the bug class's scariness (High for a reproduced PoC with a passing control; Low for static-only). |
| `next_step` | agent | The minimal next action if more proof is needed. |
| `affected_version` | agent | The record `version` the test ran against. |

`cleanup` records the label used, the resources removed by kind, and whether any labelled resource remained (which is a stage failure).

## Static fallback

When a test cannot run — the app will not build with bounded effort, a prerequisite or internal service is unavailable, or dynamic execution is disproportionate to the finding — fall back to a code-reading assessment using the shared source/control/sink, boundary, counterevidence, and proof-gap method. It is recorded as `method: static-assessment`, `reproduced: false`, and rendered as "assessed statically, not reproduced", so it is never mistaken for a reproduced result. A static assessment can still reach `confirmed` or `rejected` when the static evidence is decisive, but its confidence is bounded and the proof gap is stated. Missing runtime setup is a proof gap, not counterevidence.

## Status

- **`complete`**: the environment was available, every selected finding has a verdict with the evidence its verdict requires (a `confirmed` has a rubric, a held control, reachability evidence, and a repeated confirmation; a `rejected` has positive counterevidence), the record passes the schema and the checks, and every run resource was cleaned up.
- **`inconclusive`**: the environment was unavailable or under-resourced, some findings could not be tested (setup blocked, outside scope, not Linux-runnable), or the run stopped early. Verdicts reached are kept; untested findings are recorded `inconclusive` with the reason.
- **`blocked`**: the user says they are not authorized or declines the run, the stage 2 record is missing or stale with no retrievable revision, or no safe output location exists. The record only, with no container built.
- `rejected` is a per-finding verdict, not a stage status.

## Helper scripts

All use only the Python 3.9+ standard library, print JSON, and document their exit codes in `--help`. They never contact the network and never run the target on the host; they orchestrate the engine and read and write the run folder.

| Script | Does |
| --- | --- |
| `check_environment.py` | Detects a usable engine, checks the daemon, memory floor, and architecture; prints the environment facts or the exact remediation. Runs before anything else. |
| `find_findings.py` | Selects the newest valid, up-to-date stage 2 run copy, listing every other one with the reason it is unusable (analogue of stage 2's `find_threat_model.py`). |
| `start_validation.py` | The stage 2 gate and record skeleton; selects the findings to test; never overwrites an existing `validations.json`. |
| `export_target.py` | Writes the labelled build context from the exact reviewed revision (`git archive`, or copied scope files), never mounting the host tree. |
| `cleanup_run.py` | Removes only resources carrying the run label, lists them, refuses unlabelled resources, and never runs a bare prune. Idempotent; safe to call after a failure. |
| `normalize_validations.py` | Validates against the schema, assigns `VD-n` IDs, checks the environment block and the `reproduced`/`method` consistency. Idempotent; writes nothing when there are problems. |
| `check_validations.py` | Read-only gate: normalized form; no placeholder left; the consumed stage 2 record's digest, validity, target, and freshness; authorization rule; one verdict per selected finding; `confirmed` requires rubric + held control + reachability + repeated confirmation; `rejected` requires counterevidence and forbids resting on a setup failure; environment recorded; clean-up receipt present with no labelled resource remaining; status rules. |
| `render_validations.py` | Writes `validation.md`; refuses input that fails the schema or is not normalized. |
| Shared copies | `target_identity.py`, `prepare_workspace.py`, `check_citations.py` (already shared), plus `find_findings.py` / `check_findings.py` / `normalize_findings.py` moved to `shared/` because stage 3 now consumes stage 2's record. |

## Skill layout

```text
skills/finding-validation/
├── SKILL.md
├── agents/openai.yaml
├── evals/cases.json
├── references/
│   ├── method.md                  rubric, method choice, control-first, reachability, repeat, verdict bar
│   ├── container-workbench.md      engine abstraction, build-context, no-personal-data, two phases, limits, clean-up
│   ├── inputs-and-authorization.md the stage 2 gate, finding selection, authorization (no prompt), scope
│   ├── validation-format.md        filling validations.json, static fallback, status, fixing check failures
│   ├── static-finding-assessment.md  the static fallback method
│   ├── record-and-status.md        shared copy
│   └── evidence-and-handling.md    shared copy
├── assets/
│   ├── validations.schema.json
│   └── validations-example.json
└── scripts/
    ├── check_environment.py, start_validation.py, export_target.py, cleanup_run.py,
    │   normalize_validations.py, check_validations.py, render_validations.py
    └── find_findings.py, check_findings.py, normalize_findings.py, target_identity.py,
        prepare_workspace.py, check_citations.py   (shared copies)
```

The validations schema stays only in this skill until stage 4 consumes it; it then moves to `shared/`.

## Shared resources

Following the "Shared skill resources" rule (master in `shared/<folder>/<file>`, a synced copy in each skill that uses it, `shared/manifest.json` mapping them, `scripts/sync-shared.py` copying, and `check-package.py` failing on drift):

- **New masters mastered in `shared/`:** `references/static-finding-assessment.md` is not shared (only stage 3 uses it) — it lives in the skill. The stage 3 additions to the shared set are the stage-2 helpers stage 3 must reuse: `scripts/find_findings.py` (new, mastered in `shared/`), and `scripts/check_findings.py` and `scripts/normalize_findings.py` **moved** from the `finding-discovery` skill into `shared/scripts/` and synced back into both skills.
- **`shared/assets/findings.schema.json`** is moved to `shared/` and synced into `finding-discovery` and `finding-validation`, because stage 3 must validate the stage 2 record it reads. (Stage 2's design anticipated this move.)
- **`record-and-status.md`** gains a stage 3 section (verdict fields, the `environment` and `cleanup` blocks); it is already shared across all three skills.
- Moving these files changes the `finding-discovery` skill's `skill_version`. As with the stage 2 shared changes, that is intended and is called out in the release notes.

## Integration with `defense-factory-review`

By the user's decision, `defense-factory-review` now runs stages 1, 2, **and 3** in order, in one run. This changes the review skill (updated during the build, not by this stage's scripts):

- Its description and its opening "say what will happen once" step now state that the review also **builds and runs one disposable container** to validate the findings, that nothing personal enters it and the host tree is never modified, and that the user can ask to stop after stage 1 or stage 2.
- After stage 2 completes (`complete` or `inconclusive`), the review runs `finding-validation` on the same run, which reads the stage 2 `findings.json` just written. A stage 2 `blocked` stops the review. If `check_environment.py` finds no usable engine, the review reports stages 1 and 2 and records stage 3 as `inconclusive` with the remediation, rather than failing the whole review.
- The review's overall status is the weakest of the three stage statuses, and it reports verdicts by type and points to `validation.md`.

## Parity

Capability parity with Codex Security's `validation` phase is tracked in [validation-parity.md](validation-parity.md). In short: Codex Security has **no separate sandbox** — its validation runs in whatever environment Codex is already in, with instructions to use a disposable copy, keep commands short and non-interactive, and avoid network access unless essential. This skill keeps its method choice, its rubric, its "setup errors are not counterevidence" rule, its static fallback, and its instance-preserving discipline, and **adds** the dedicated disposable container as a deliberate capability, not a parity gap. Codex's workbench MCP tools, compact diff-mode validation, deep-scan reducer, and severity/attack-path scoring are not adopted (severity belongs to a later stage); each is recorded with its reason in the parity table.

## Deferred

- Severity and attack-path scoring (Codex assigns these during/after validation; here they belong to a later stage).
- Compact workbench-backed diff-mode validation and the deep-scan reducer.
- SARIF or other export of validation results.
- An answer key and scoring rubric in `evals/` (deferred since stage 1).
- Validating findings that require a non-Linux runtime (recorded `inconclusive`).

## Build order (only after approval)

1. The container helpers and their safety test: `check_environment.py`, `export_target.py`, `cleanup_run.py`, with the label-only clean-up test that protects the MISP stack.
2. The shared moves: `findings.schema.json`, `find_findings.py`, `check_findings.py`, `normalize_findings.py` into `shared/`; update `manifest.json`, run `sync-shared.py`, extend `check-package.py` expectations, and add the stage 3 record section.
3. The validations schema and example, `start_validation.py`, `normalize_validations.py`, `check_validations.py`, `render_validations.py`, and tests.
4. `SKILL.md`, the references, `agents/openai.yaml`, and eval cases.
5. Update the `defense-factory-review` skill to sequence stage 3 after stage 2 (description, the "say what will happen once" step, the stage 3 call on the shared run, the engine-missing degraded path, and the combined report), plus its eval cases.
6. `python3 scripts/check-package.py`, `python3 -m unittest discover -s tests`, a dry run on a small deliberately vulnerable demo app (with a clean-up test proving the MISP stack is untouched), then live runs in Claude Code, ChatGPT/Codex, and Cursor.
7. Release as a minor version only when the user asks.
