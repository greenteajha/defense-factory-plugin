# Stage 4 design: the `patch-preparation` skill

Stage 4 prepares a minimal, tested fix for each finding that stage 3b rated `reportable`, inside the disposable container stage 3 uses, and records each fix as a unified diff plus evidence. The diff is never applied to the user's working tree; applying it is stage 5 (human review). This document is the design basis; [patch-preparation-parity.md](patch-preparation-parity.md) maps the skill against Codex Security's `fix-finding`.

## Place in the workflow

Stage 4 consumes the stage 3b `attack-paths.json` (chosen by `find_attack_paths.py`: the newest run copy that passes `check_attack_paths.py` and is `complete` or `inconclusive`). It patches only analyses with `decision: reportable`, in priority order (P0 first), and cross-references the stage 2 finding (its `root_control` location) and the stage 3 reproduction by reference (path + sha256 + run_id). It never patches `deferred` or `ignore` analyses, and it does not "fix" behaviour the resolved SECURITY.md policy marks as intended.

`defense-factory-review` runs stage 4 after stage 3b when at least one finding is reportable (auto-run, the user's choice for this project). The skill also runs on its own when the user asks to fix or patch validated findings.

## Outcome vocabulary

Per finding: `fixed`, `no_change`, `blocked`, or `inconclusive`. This is Codex Security's `fixed`/`no_change`/`blocked` plus the project-wide `inconclusive` (a fix attempted but the gates could not run, or the result is ambiguous). A setup failure is never counterevidence and never `fixed`.

## The container workbench

Stage 4 reuses stage 3's disposable-container workbench (the shared `check_environment.py`, `export_target.py`, `run_container.py`, `cleanup_run.py`, `engine.py`): the reviewed revision is copied in (never mounted), the fix is developed on the copy, the network is on for setup and off for testing, every container carries the run label, and clean-up removes only what the run created. The diff is exported to `patches/<finding_id>.patch`; tests go under `tests/<finding_id>/` and logs under `artifacts/<finding_id>/`. See [../skills/patch-preparation/references/container-workbench.md](../skills/patch-preparation/references/container-workbench.md).

## The verification gates

A fix is `fixed` only when every ordered gate passes: (1) the target's build/type check; (2) the stage 3 reproduction is now blocked, tried against alternate representations of the same attack; (3) a legitimate-behaviour control still works; (4) the target's own tests, lint, and any refactoring safety net pass; (5) the scope is minimal. A focused test that exercises the vulnerable path and asserts the safe behaviour is required — code inspection is not enough. A fresh read-only patch-candidate review checks for surviving routes and broken legitimate inputs.

## The record

`patches.json` is the source of truth; `patches.md` is rendered from it. Top level: `record`, `validated_record` (the stage 3b reference), `threat_model`, `security_guidance`, `environment` (the container provenance, as in stage 3; null for a blocked run), `patches[]`, `not_eligible[]` (the deferred and ignore analyses), and `open_questions[]`. Each `patches[]` entry carries the finding identity, severity, and priority copied from the stage 3b analysis, its unchanged `locations`, the outcome, the vulnerable path and invariant, the patch strategy and the diff path, the files changed and tests added, the ordered gates, the before/after reproduction, the legitimate-behaviour result, the candidate review, the remaining risk, a proof gap (for `blocked`/`inconclusive`), and a confidence rating. See [../skills/patch-preparation/references/patch-format.md](../skills/patch-preparation/references/patch-format.md).

## The helper scripts

Deterministic, standard-library, Python 3.9+, each printing one JSON object:

- `find_attack_paths.py` — select the newest usable stage 3b record.
- `start_patches.py` — verify the stage 3b record and write a `patches.json` skeleton with one patch per reportable finding, `<fill: ...>` markers, and `environment` null; never overwrites.
- `normalize_patches.py` — validate against `patches.schema.json`, order the patches by priority then finding number, and number them `PP-n`.
- `check_patches.py` — read-only gate: normalized form, no placeholders, target-identity and stage 3b linkage, authorization, the environment (present unless blocked), coverage (every patch maps to a reportable analysis with matching identity/severity/priority and unchanged locations; `not_eligible` lists exactly the deferred and ignore analyses), the outcome rules (recomputed by `check_outcome`), and the `complete` conditions.
- `render_patches.py` — render `patches.md`.

## Shared-resource promotions

Stage 4 reuses the container helpers (owned by `finding-validation`) and the stage 3b record checks (owned by `attack-path-analysis`). Those files were promoted to `shared/` masters and listed for both the original owner and `patch-preparation` in `shared/manifest.json`, so every copy stays byte-identical and `check-package.py` enforces it. `record-and-status.md` gained a stage 4 section.

## Milestones

1. Skill, schema, example, helpers, references, `agents/openai.yaml`, eval cases, and 29 tests; `check-package.py`, `sync-shared.py --check`, `claude plugin validate`, and the full test suite pass.
2. A `v0.5.0` test package (stage 4 under `[Unreleased]`), then a live run in Claude Code and ChatGPT/Codex on the authorized test app: prepare a fix for a reportable non-challenge finding, confirm the diff, the passing gates, and the clean-up, and that the working tree is untouched.
3. A `0.6.0` release when the maintainer asks.

## What stage 4 is not

It does not apply, commit, or push the fix; it does not assess merge eligibility or open a pull request (stage 5); and it does not re-validate a merged fix against a deployment (stage 6).
