# Defense Factory Plugin

An early, provider-neutral application security plugin inspired by [OpenAI's Defense Factory](https://openai.com/the-defense-factory/). The current candidate is a package shell: portable manifests, client adapters, and [contracts for a six-stage workflow](docs/workflow-contracts.md) that future skills will implement. It is an independent project, not an OpenAI product or an implementation of OpenAI's full Defense Factory.

## What is in the 0.1.0 candidate

- `plugin.json` is the canonical Agent Plugins 1.0 manifest. `skills/` will hold shared behavior and is currently empty.
- `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and `.agents/plugins/marketplace.json` are thin packaging adapters. Cursor uses the root manifest. No skill, MCP server, credentials, scanner, patch automation, or production integration is bundled.
- All six workflow stages are specified in `docs/workflow-contracts.md` and are **not yet implemented**.

## Layout

```text
plugin.json                         portable identity and metadata
skills/                             shared skills (empty)
docs/workflow-contracts.md          stage handoff and evidence contracts
.claude-plugin/plugin.json          Claude Code metadata adapter
.claude-plugin/marketplace.json     Claude Code marketplace catalog
.agents/plugins/marketplace.json    local ChatGPT/Codex catalog
scripts/check-package.py            offline package checks for the core and each client
scripts/schemas/                    vendored Agent Plugins 1.0.0 schemas (Apache-2.0)
tests/                              regression tests for the package check
```

## Install and use

| Client surface | Route | Status for this candidate |
| --- | --- | --- |
| Claude Code | Add the repository as a marketplace with `/plugin marketplace add greenteajha/defense-factory-plugin`, then `/plugin install defense-factory-plugin@defense-factory`. For local use, clone the repository and run `claude --plugin-dir /absolute/path/to/defense-factory-plugin`. | Catalog validated and installs from a local marketplace; live skill activation still needs a smoke test. |
| ChatGPT desktop / Codex local | Add the repository as a plugin marketplace with `codex plugin marketplace add greenteajha/defense-factory-plugin`, then install and enable **Defense Factory** in the Plugins Directory. The included local catalog points to this repository root. | Catalog prepared; live client activation still needs a smoke test. |
| Cursor plugin client | Clone/download the repository and import its root `plugin.json` using Cursor's plugin flow. Marketplace publication is separate. | Standard package prepared; live client activation still needs a smoke test. |

The target client must support plugins and skills. A GitHub download by itself does not activate any skill. ChatGPT web/workspace distribution and Claude or Cursor marketplace publication are separate review and installation paths; this candidate does not claim those routes. Repository and execution access come from the host, not this package.

Installing this candidate adds no agent behavior yet. Skills for each workflow stage will be added under `skills/` as they are implemented.

## Data and permissions

Future skills will read the repository through whichever access the host provides. Local source or excerpts may be sent to that host's model service during use; check its data handling settings before assessing sensitive code. The package contains no telemetry, network endpoint, secret, or bundled MCP connection. Keep findings and reproduction details in approved private storage. Ask for authorization before scanning; use isolated temporary environments for later validation; require human review before merge. Host and repository permissions enforce these boundaries; prompt text alone cannot.

## Versioning and contribution

`plugin.json` is the single version source. The current `0.1.0` is a candidate until client smoke tests and a matching Git tag are completed. Before proposing a change, run `python3 scripts/check-package.py` and `python3 -m unittest discover -s tests`. The package check validates the manifest against the Agent Plugins schema and reproduces the load rules Claude Code, ChatGPT/Codex, and Cursor document or implement; it blocks components (hooks, `.cursor-plugin`, skill `agents/openai.yaml`) until checks exist for them. It approximates client acceptance and does not replace live smoke tests. Releases use Semantic Versioning and matching `vX.Y.Z` Git tags, with checks and a client smoke-test matrix described in [RELEASING.md](RELEASING.md). See [CHANGELOG.md](CHANGELOG.md) for changes and [SECURITY.md](SECURITY.md) for reporting sensitive issues. The code and documentation are [MIT licensed](LICENSE).

## Sources

- [Defense Factory Project](https://app.notion.com/p/3e46cc31d3d581c48283de3a000039d1) and [Agent plugins guidelines](https://app.notion.com/p/3e46cc31d3d581b1a718f102349aefa3) informed the architecture.
- [Agent Plugins manifest](https://agent-plugins.org/plugin-authors/manifest), [skills layout](https://agent-plugins.org/plugin-authors/skills), [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins), [Claude Code plugins](https://code.claude.com/docs/en/plugins), and [Cursor plugins](https://cursor.com/docs/reference/plugins) describe current client packaging.
