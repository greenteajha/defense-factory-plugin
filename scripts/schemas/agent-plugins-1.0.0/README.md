# Agent Plugins 1.0.0 schemas

Unmodified copies of `schemas/1.0.0/plugin.schema.json` and `schemas/1.0.0/mcp.schema.json` from [agentplugins/agent-plugins-spec](https://github.com/agentplugins/agent-plugins-spec) at commit `ff8ab5e392`, licensed under the Apache License 2.0 (see `LICENSE`).

`scripts/check-package.py` validates `plugin.json` (and `mcp.json`, once added) against these files offline. Clients must not fetch the schema at runtime, so the package check must not either. Replace these copies only when deliberately moving to a newer Agent Plugins version.
