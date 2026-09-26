# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-09-26

- Added stage 3 (isolated validation) as the `finding-validation` skill: it takes the stage 2 findings and gives each a verdict of `confirmed`, `rejected`, or `inconclusive`, backed by evidence, by building one disposable container per run on the user's own computer (Docker Desktop, Podman, Colima, or Rancher Desktop; never Apple `container`), installing the target's prerequisites, running the app and a per-finding test, then deleting everything the run created. The exact reviewed revision is copied in, never mounted; no credentials, sockets, or host environment enter the container; the network is on for setup and off by default for testing; and clean-up removes only resources carrying the run's label, so other containers (for example a MISP stack) are never touched. Setup failures are never counterevidence; a static fallback is recorded as "assessed statically, not reproduced". Includes `docs/validation-design.md`, `docs/validation-parity.md`, the `validations.json` schema and example, eight helpers (`check_environment.py`, `find_findings.py`, `start_validation.py`, `export_target.py`, `cleanup_run.py`, `normalize_validations.py`, `check_validations.py`, `render_validations.py`) with `engine.py`, `agents/openai.yaml`, and eval cases. Not yet tested live in each client.
- Stage 3 uses **Docker Desktop only** (dropped Podman/Colima/Rancher/nerdctl from detection and messaging), and now locates the `docker` CLI from a standard install location when it is not on the shell PATH, so a running Docker Desktop is found from non-interactive or remote shells (e.g. Claude Cowork); `DEFENSE_FACTORY_DOCKER` forces a specific executable.
- The `defense-factory-review` skill now runs stage 1 (threat model), then stage 2 (finding discovery), then stage 3 (isolated validation) in one run, and reports all three in one summary. If no container engine is available it reports stages 1 and 2 and records stage 3 as `inconclusive` rather than failing the review. Earlier it ran only stages 1 and 2.
- `findings.schema.json`, `check_findings.py`, and `normalize_findings.py` moved into `shared/` because stage 3 consumes the stage 2 record; the shared record reference gained a stage 3 section. Because the shared record reference changed, threat models and finding records stored by earlier versions are not reused.
- Fixed: stage 2 rejected a threat model made on a moved or copied folder (for example in a cloud workspace) as stale, because a folder without a Git remote is identified by its absolute path. The model is now accepted when its version matches the code exactly, with a "same code, different location" note that the stage 2 record keeps as an assumption. A different Git repository is still rejected, and stale messages now say whether the code changed or the repository differs.
- The `threat-model` and `finding-discovery` skills describe themselves as running their stage on its own, so a review request goes to the `defense-factory-review` skill.

## [0.3.0] - 2026-09-26

Adds stage 2 (finding discovery) as the `finding-discovery` skill and removes the stage 1 confirmation prompts. Tested live in Cursor by the maintainer; Claude Code and ChatGPT/Codex have not yet been tested live with this version. Known limitation: for a folder that is not a Git repository, the target identity depends on the folder's absolute path, so a threat model made on a copy of the folder in another location (for example a cloud workspace) is reported as stale by stage 2.

- Added the stage 2 design for the `finding-discovery` skill (`docs/finding-discovery-design.md`) and its planned capability map against Codex Security (`docs/finding-discovery-parity.md`).
- Added `shared/`: master copies of the record and evidence references and the five stage 1 helper scripts, a manifest of which skills receive each file, and `scripts/sync-shared.py`. The package check now fails when a copy is missing or differs, a master is unlisted, or a skill holds an unlisted copy.
- Added the `finding-discovery` skill (stage 2): instructions, references (method, discovery checklist, inputs and authorization, finding format), the `findings.json` schema and example, `agents/openai.yaml`, eval cases, and five helpers: `start_findings.py`, `list_scope_files.py`, `normalize_findings.py`, `check_findings.py`, and `render_findings.py`. Stage 2 output items are called findings and carry `status: unvalidated` until stage 3. Not yet tested live in each client.
- `target_identity.py` can now be imported (`resolve()`, `identify()`); its output is unchanged.
- The shared record reference now has sections for stage 1 and stage 2 fields. Because the threat-model skill's files changed, models stored by 0.2.0 will not be reused.
- Stage 1 no longer prompts for authorization: it records the user's request (quoted) and stops only if the user says they are not authorized. Stage 2 carries that record forward within the same run.
- Stage 1 no longer asks where to save output for targets that are not Git repositories: `prepare_workspace.py` defaults to `.defense-factory/` in the target folder, which target identity already ignores.
- Added `find_threat_model.py` to stage 2: it selects the newest valid, up-to-date stage 1 run copy without asking the user.
- Renamed stage 2 from "candidate discovery" to "finding discovery" in the workflow contracts and the threat-model skill's next-step wording.

## [0.2.0] - 2026-09-25

First release. Implements stage 1 (scope and threat model); stages 2 to 6 remain in design. Version 0.1.0 was a development candidate and was never released.


- Added the portable Agent Plugins manifest and an empty shared `skills/` directory; no skills are implemented yet.
- Added thin Claude Code and ChatGPT/Codex package metadata; Cursor can read the portable manifest.
- Documented six provider-neutral workflow contracts, data boundaries, and a release process.
- Marked all workflow stages and live client compatibility as unimplemented or unverified.
- Added a Claude Code marketplace catalog (`.claude-plugin/marketplace.json`) so the repository can be added with `/plugin marketplace add`.
- Aligned the Claude Code manifest's repository, license, and keywords with the root manifest.
- Extended `scripts/check-package.py` to enforce the layout rules: manifest parity, catalog fields and policy values, no top-level `skills`/`mcpServers`, Agent Skills name and description limits, and self-contained skill folders. It now reports every failure instead of stopping at the first.
- Added offline client-compatibility checks: validation against vendored Agent Plugins 1.0.0 schemas (plugin and MCP), Codex manifest, interface, and marketplace load rules, and Cursor skill and component rules. Components without checks (hooks, `.cursor-plugin`, skill `agents/openai.yaml`, Codex apps) are blocked until checks are added.
- Added `longDescription` to the Codex interface; the extension's interface replaces Codex defaults, so it was otherwise blank.
- Added `tests/` regression tests for the package check and run them in CI.
- Added the `threat-model` skill (stage 1): authorization gate, reuse of a stored model by target identity and version, supplied-model and repository-guidance handling, `SECURITY.md` resolution, architecture and effective-resource mapping, independent review with fallback, prioritized hypotheses with STRIDE check and severity calibration, verified citations, and a self-ignoring `.defense-factory/` output folder. Includes four standard-library helper scripts, an output template, evals, and Codex `agents/openai.yaml`.
- Documented capability parity with the Codex Security threat-model skill in `docs/threat-model-parity.md`.
- Added `agents/openai.yaml` checks to the package check and set the Codex `defaultPrompt`.
- Tightened the threat-model gate and storage rules after the first live test: explicit authorization statements only, user-chosen output locations only, every trust boundary accounted for.
- Threat-model skill hardening from cross-client comparison runs: `.DS_Store` and other OS metadata no longer change a target's version; reuse requires a matching `skill_version` fingerprint and a model that passes the new `scripts/check_model.py`, and reused models are never amended; records name the exact `model`; hypotheses carry a confidence rating; `check_citations.py` checks comma-separated line lists.
- Documented release packages for ChatGPT upload (plugin-only, never `.agents/`), Claude Code, Cursor, and each skill. They are built by a separate plugin packager kept outside this repository.
- Documented the ChatGPT Upload plugin archive and Add a marketplace routes and corrected the Cursor install route (`~/.cursor/plugins/local/`).
