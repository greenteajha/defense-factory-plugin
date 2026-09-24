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
