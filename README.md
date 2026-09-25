# Defense Factory Plugin

An early, provider-neutral application security plugin inspired by [OpenAI's Defense Factory](https://openai.com/the-defense-factory/). Version 0.3.0 (in development; the current release is 0.2.0) implements stages 1 and 2 of a [six-stage workflow](docs/workflow-contracts.md), the `threat-model` and `finding-discovery` skills, with portable manifests and client adapters for Claude Code, ChatGPT/Codex, and Cursor. It is an independent project, not an OpenAI product or an implementation of OpenAI's full Defense Factory.

## What is in 0.3.0 (unreleased)

- `plugin.json` is the canonical Agent Plugins 1.0 manifest. `skills/` holds the shared skills.
- `skills/threat-model` builds, reuses, or revises an evidence-backed threat model of an authorized repository (stage 1). It records who requested the assessment (it does not prompt for confirmation), works read-only and offline, and saves output to a self-ignoring `.defense-factory/` folder, also for folders that are not Git repositories. Its helpers need Python 3.9 or later. [docs/threat-model-parity.md](docs/threat-model-parity.md) maps it against the Codex Security threat-model skill.
- `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and `.agents/plugins/marketplace.json` are thin packaging adapters. Cursor uses the root manifest. No MCP server, credentials, scanner, patch automation, or production integration is bundled.
- `skills/finding-discovery` starts from a stage 1 threat model, or a narrow scan of named paths, and records deduplicated, **unvalidated** findings with source, control, sink, `file:line` evidence, counterevidence, and an investigation question for stage 3, accounting for every threat-model hypothesis (stage 2). [docs/finding-discovery-design.md](docs/finding-discovery-design.md) describes it; [docs/finding-discovery-parity.md](docs/finding-discovery-parity.md) maps it against Codex Security.
- Stages 3 to 6 are specified in `docs/workflow-contracts.md` and are **not yet implemented**.

## Layout

```text
plugin.json                         portable identity and metadata
skills/threat-model/                stage 1 skill: SKILL.md, references, template, helper scripts, evals
skills/finding-discovery/           stage 2 skill: SKILL.md, references, schema, example, helper scripts, evals
docs/workflow-contracts.md          stage handoff and evidence contracts
docs/threat-model-parity.md         capability map against Codex Security's threat-model skill
docs/finding-discovery-design.md    stage 2 design (not yet implemented)
docs/finding-discovery-parity.md    planned capability map against Codex Security's discovery phase
.claude-plugin/plugin.json          Claude Code metadata adapter
.claude-plugin/marketplace.json     Claude Code marketplace catalog
.agents/plugins/marketplace.json    local ChatGPT/Codex catalog
scripts/check-package.py            offline package checks for the core and each client
scripts/sync-shared.py              copies shared/ masters into the skills that use them
shared/                             master copies of files several skills use (never read by clients)
scripts/schemas/                    vendored Agent Plugins 1.0.0 schemas (Apache-2.0)
tests/                              regression tests for the package check
```

## Install and use

| Client surface | Route | Status for 0.2.0 |
| --- | --- | --- |
| Claude Code | Add the repository as a marketplace with `/plugin marketplace add greenteajha/defense-factory-plugin`, then `/plugin install defense-factory-plugin@defense-factory`. For local use, clone the repository and run `claude --plugin-dir /absolute/path/to/defense-factory-plugin`, or unzip the `-claude-` package and point `--plugin-dir` at it. Invoke with `/defense-factory-plugin:threat-model`. | Full threat-model runs confirmed with `--plugin-dir`. Marketplace install confirmed with a local catalog. |
| ChatGPT desktop / Codex (upload) | In Plugins, choose **Add**, then **Upload plugin archive**, and select the `-chatgpt-` package. Do not upload the repository itself: the uploader rejects archives that contain `.agents/plugins/marketplace.json`. | Upload and full threat-model runs confirmed. |
| ChatGPT desktop / Codex (marketplace) | In Plugins, choose **Add**, then **Add a marketplace**, with `greenteajha/defense-factory-plugin`; or run `codex plugin marketplace add greenteajha/defense-factory-plugin` and `codex plugin add defense-factory-plugin@defense-factory`. Uses `.agents/plugins/marketplace.json`. | Catalog prepared; not yet tested. |
| Cursor | In **Customize**, add a plugin from **GitHub Repository** with `greenteajha/defense-factory-plugin`; Cursor reads `.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json`. Offline: copy the repository without `.git` into `~/.cursor/plugins/local/defense-factory-plugin/`, then run **Developer: Reload Window**; Cursor ignores symlinks that point outside that folder. Cursor Marketplace publication is separate. | Full threat-model runs confirmed. |

The `-chatgpt-` and `-claude-` packages are built outside this repository by a separate plugin packager and attached to GitHub Releases; Cursor installs from the repository itself; see [RELEASING.md](RELEASING.md#packages). The target client must support plugins and skills. A GitHub download by itself does not activate any skill. ChatGPT web/workspace distribution and Claude or Cursor marketplace publication are separate review and installation paths; this release does not claim those routes. Repository and execution access come from the host, not this package.

Installing this version adds the `threat-model` and `finding-discovery` skills. Ask for a threat model of a repository, then ask to find security issues in it (stage 2), or invoke either skill by name. Skills for later stages will be added under `skills/` as they are implemented.

## Data and permissions

Skills read the repository through whichever access the host provides. The threat-model skill writes its output to `.defense-factory/` in the repository, which ignores itself in Git; the folder still travels in archives, container build contexts, and synced folders, and it is sensitive. Local source or excerpts may be sent to that host's model service during use; check its data handling settings before assessing sensitive code. The package contains no telemetry, network endpoint, secret, or bundled MCP connection. Keep findings and reproduction details in approved private storage. Assess only code you are permitted to assess: the skills record who requested an assessment but do not prompt for confirmation; use isolated temporary environments for later validation; require human review before merge. Host and repository permissions enforce these boundaries; prompt text alone cannot.

## Versioning and contribution

`plugin.json` is the single version source. The current release is `0.2.0`, tagged `v0.2.0`; `0.3.0` is in development and not yet tested live. Before proposing a change, run `python3 scripts/check-package.py` and `python3 -m unittest discover -s tests`. The package check validates the manifest against the Agent Plugins schema and reproduces the load rules Claude Code, ChatGPT/Codex, and Cursor document or implement; it blocks components (hooks, `.cursor-plugin`, skill `agents/openai.yaml`) until checks exist for them. It approximates client acceptance and does not replace live smoke tests. Releases use Semantic Versioning and matching `vX.Y.Z` Git tags, with checks and a client smoke-test matrix described in [RELEASING.md](RELEASING.md). See [CHANGELOG.md](CHANGELOG.md) for changes and [SECURITY.md](SECURITY.md) for reporting sensitive issues. The code and documentation are [MIT licensed](LICENSE).

## Sources

- [Defense Factory Project](https://app.notion.com/p/3e46cc31d3d581c48283de3a000039d1) and [Agent plugins guidelines](https://app.notion.com/p/3e46cc31d3d581b1a718f102349aefa3) informed the architecture.
- [Agent Plugins manifest](https://agent-plugins.org/plugin-authors/manifest), [skills layout](https://agent-plugins.org/plugin-authors/skills), [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins), [Claude Code plugins](https://code.claude.com/docs/en/plugins), and [Cursor plugins](https://cursor.com/docs/reference/plugins) describe current client packaging.
