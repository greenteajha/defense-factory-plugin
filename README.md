# Defense Factory Plugin

An early, provider-neutral application security plugin inspired by [OpenAI's Defense Factory](https://openai.com/the-defense-factory/). The current candidate provides an evidence-linked repository threat-modeling skill and [contracts for a six-stage workflow](docs/workflow-contracts.md). It is an independent project, not an OpenAI product or an implementation of OpenAI's full Defense Factory.

## What is in the 0.1.0 candidate

- `skills/threat-model-repository/SKILL.md` guides an authorized source review and produces a threat model with evidence, assumptions, and validation questions.
- `plugin.json` is the canonical Agent Plugins 1.0 manifest. `skills/` holds shared behavior.
- `.claude-plugin/plugin.json` and `.agents/plugins/marketplace.json` are thin packaging adapters. Cursor uses the root manifest. No MCP server, credentials, scanner, patch automation, or production integration is bundled.
- Later workflow stages are specified in `docs/workflow-contracts.md` and are **not yet implemented**.

## Layout

```text
plugin.json                         portable identity and metadata
skills/threat-model-repository/     shared skill
docs/workflow-contracts.md          stage handoff and evidence contracts
.claude-plugin/plugin.json          Claude Code metadata adapter
.agents/plugins/marketplace.json    local ChatGPT/Codex catalog
scripts/check-package.py            packaging checks
```

## Install and use

| Client surface | Route | Status for this candidate |
| --- | --- | --- |
| Claude Code | Clone/download the repository and run `claude --plugin-dir /absolute/path/to/defense-factory-plugin`. | Package layout prepared; live client activation still needs a smoke test. |
| ChatGPT desktop / Codex local | Add the repository as a plugin marketplace with `codex plugin marketplace add greenteajha/defense-factory-plugin`, then install and enable **Defense Factory** in the Plugins Directory. The included local catalog points to this repository root. | Catalog prepared; live client activation still needs a smoke test. |
| Cursor plugin client | Clone/download the repository and import its root `plugin.json` using Cursor's plugin flow. Marketplace publication is separate. | Standard package prepared; live client activation still needs a smoke test. |

The target client must support plugins and skills. A GitHub download by itself does not activate the skill. ChatGPT web/workspace distribution and Claude or Cursor marketplace publication are separate review and installation paths; this candidate does not claim those routes. Repository and execution access come from the host, not this package.

Ask the installed agent to **threat-model a repository you are authorized to assess**. Give the repository, revision, and scope. A good result includes assets, entry points, trust boundaries, prioritized hypotheses, file references, and unresolved questions. A request for a complete vulnerability scan or a validated finding should be reported as outside the implemented capability.

## Data and permissions

The skill reads the repository through whichever access the host provides. Local source or excerpts may be sent to that host's model service during use; check its data handling settings before assessing sensitive code. The package contains no telemetry, network endpoint, secret, or bundled MCP connection. Keep findings and reproduction details in approved private storage. Ask for authorization before scanning; use isolated temporary environments for later validation; require human review before merge. Host and repository permissions enforce these boundaries; prompt text alone cannot.

## Versioning and contribution

`plugin.json` is the single version source. The current `0.1.0` is a candidate until client smoke tests and a matching Git tag are completed. Releases use Semantic Versioning and matching `vX.Y.Z` Git tags, with checks and a client smoke-test matrix described in [RELEASING.md](RELEASING.md). See [CHANGELOG.md](CHANGELOG.md) for changes and [SECURITY.md](SECURITY.md) for reporting sensitive issues. The code and documentation are [MIT licensed](LICENSE).

## Sources

- [Defense Factory Project](https://app.notion.com/p/3e46cc31d3d581c48283de3a000039d1) and [Agent plugins: cross-provider gold standard](https://app.notion.com/p/3e46cc31d3d581b1a718f102349aefa3) informed the architecture.
- [Agent Plugins manifest](https://agent-plugins.org/plugin-authors/manifest), [skills layout](https://agent-plugins.org/plugin-authors/skills), [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins), [Claude Code plugins](https://code.claude.com/docs/en/plugins), and [Cursor plugins](https://cursor.com/docs/reference/plugins) describe current client packaging.
