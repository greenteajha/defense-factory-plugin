# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased] - 0.1.0 candidate

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
