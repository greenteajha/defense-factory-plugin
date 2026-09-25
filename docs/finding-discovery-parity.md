# Finding-discovery skill: capability parity with Codex Security

`skills/finding-discovery` (design: [finding-discovery-design.md](finding-discovery-design.md)) is designed to keep the capabilities of the discovery phase in [openai/codex-security](https://github.com/openai/codex-security/tree/main/plugins/codex-security) (Apache-2.0): the `finding-discovery` skill, plus the parts of `references/core-scan.md`, `references/threat-model.md`, `references/scan-contract.md`, `references/static-finding-assessment.md`, `schemas/definitions/discovery-candidate.schema.json`, and `scripts/normalize_candidates.py` that govern discovery. Codex Security calls its discovery output "candidates" and stores them through its MCP server; this plugin calls them unvalidated findings (`status: unvalidated`) and stores them in `findings.json`. Our skill is a standalone stage that works without an MCP server in Claude Code, ChatGPT/Codex, and Cursor.

Compiled from codex-security `main` at `2a3dcbd` on 2026-09-25. Recheck when either side changes. "Where" refers to the planned files under `skills/finding-discovery/`.

| # | Codex Security capability | How this skill provides it | Where |
| --- | --- | --- | --- |
| 1 | Activates in the discovery phase or on an explicit request to discover candidates; not the primary trigger for full scans | Description activates for hunting security bugs and stage 2; not for threat modeling, validation, fixes, or diffs | `SKILL.md` frontmatter |
| 2 | Read the storage policy before choosing paths | `prepare_workspace.py` with `--stage 2-finding-discovery` in the stage 1 run | `SKILL.md` Workflow; shared `evidence-and-handling.md` |
| 3 | Explicit input and output paths override defaults; ask for a missing required input | Same rule as stage 1 | `SKILL.md` Preconditions |
| 4 | Resolve `SECURITY.md` before inspecting source; delegated workers do the same | Resolve per investigated directory; workers receive their packet's policy | `SKILL.md` Workflow; `references/method.md` |
| 5 | Standalone repository discovery applies the checklist to the authorized current source | Whole-repository and named-path scans | `SKILL.md` |
| 6 | Diff workflows (compact inventory, ranked diff input, `relevant_lines`) | **Deferred** to a later release | design "Deferred" |
| 7 | Inspect the code before deciding; trust code over commit messages or narrative | Same, applied to documentation and threat-model claims | `references/method.md` |
| 8 | Separate root-cause families; keep independently reachable instances as separate candidates | Same; `instance` field | `references/finding-format.md` |
| 9 | Follow a changed or shared helper, guard, or sink wrapper to its sibling call sites | Same for shared helpers in scope | `references/discovery-checklist.md` |
| 10 | Advisory-seeded rows stay open until local evidence closes them; a same-CWE neighbour does not close a seed; explicit closure rows for every opened seed target | `SEED-n` rows with the same rules; reconciled like hypotheses | `references/inputs-and-authorization.md`; `finding-format.md` |
| 11 | Family-specific enumeration rules (deserialization codecs, file-format object models, patch/edit APIs, duplicated class filters, stored configuration values, query APIs, outbound requests, XML parsers, command runners, static files, filesystem operations, archive extraction, deprecated or opt-in APIs, auth endpoints, stateful auth protocols, SSO assertions, validated-versus-consumed objects, realms, protocol version helpers, self-service updates, repeated templates, recursive placeholders) | Rewritten as a checklist by family | `references/discovery-checklist.md` |
| 12 | Finding bar: prefer plausible authz bypass, confused deputy, SSRF, traversal, injection with a real sink, cross-tenant exposure, unenforced state change, sandbox escape; avoid generic advice, maintainability, duplicate variants | Same | `references/method.md` |
| 13 | Discovery does not own severity | No severity; `confidence` is static plausibility; `hypothesis_priority` is inherited | `finding-format.md` |
| 14 | Output fields: ID, title, labelled locations, instance key, seed ID, advisory reference, source, sink or broken control, impact, plausibility reasoning, closest control, validation recommendation, CWE, evidence | All kept; validation is always the next step, so `investigation_question` replaces a yes/no recommendation | `assets/findings.schema.json` |
| 15 | Location roles `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, `evidence` | Same roles; `entrypoint/wrapper` folded into `entrypoint` | `findings.schema.json` |
| 16 | No plausible candidates returns a no-findings result | Empty `findings` with full reconciliation and coverage | `finding-format.md`; `render_findings.py` |
| 17 | Every candidate has a stable ID and a ledger entry | `FD-n` IDs, `fingerprint`, reconciliation rows | `normalize_findings.py`; `check_findings.py` |
| 18 | Continue until no additional distinct plausible candidates remain | Same | `SKILL.md` Workflow |
| 19 | A visible report of the discovery phase | `findings.md` rendered from the JSON | `render_findings.py` |
| 20 | Independent baseline auditor with fresh context and no generated hypotheses; sequential fallback disclosed | Same, host-neutral; `independent_baseline` header field | `references/method.md` |
| 21 | Investigation packets built from threat-model scenarios, with shared attacker, asset, controls, entry points, and source anchors | Same, keyed by `TM-H` and `SEED` IDs | `references/method.md` |
| 22 | Focused investigators with forward, backward, authorization, and open-ended perspectives, sized to the work | Same | `references/method.md` |
| 23 | Supporting code may lie outside a requested path; the affected entry point, control, or operation must be in scope | Same | `references/method.md` |
| 24 | One verified offline search command; no downloads | Same rule, stated as a capability rather than a tool name | `SKILL.md` Ground rules |
| 25 | Knowledge base overrides generated assumptions and policy, never user instructions; all content is untrusted data | Same precedence as stage 1 | `inputs-and-authorization.md`; shared `evidence-and-handling.md` |
| 26 | Persist pending candidates before combining, so interrupted work is not lost | Findings written to `findings.json` as they are found; an interrupted run is `inconclusive` and keeps them | `SKILL.md` Workflow |
| 27 | Coverage is the fully reviewed files intersected with the scope inventory; finish remaining files; report actual remaining paths when partial | `list_scope_files.py` inventory; `coverage` object | `list_scope_files.py`; `check_findings.py` |
| 28 | Combine only observations with the same broken control and remediation; never merge by CWE alone | Remediation subsumption rule; `merged_from` accounting | `finding-format.md`; `normalize_findings.py`; `check_findings.py` |
| 29 | Reconcile each threat-model scenario with a finding, a source-backed coverage disposition, or an open question; keep documentation/configuration disagreements; no second speculative registry | Reconciliation rows with four dispositions; disagreements kept | `finding-format.md`; `check_findings.py` |
| 30 | Deterministic normalization: path validation, CWE normalization, location ordering, exact-duplicate merge, deterministic IDs | Same | `normalize_findings.py` |
| 31 | Stable identity: family `ruleId`, semantic anchor without line numbers, instance | `family`, root-control anchor, `instance` in `fingerprint` | `normalize_findings.py` |
| 32 | Static assessment tuple (source, control, sink, reachable path, boundary, counterevidence, proof gaps) and evidence-based confidence | Same fields and confidence levels | `findings.schema.json`; `finding-format.md` |
| 33 | Coverage dispositions (reported, needs follow-up, rejected, no issue found, not applicable) | `findings`, `open-question`, `no-finding`, `not-investigated`; rejection waits for stage 3 | `finding-format.md` |

## Capabilities this skill adds

- Stage 1 record gate: the model must pass `check_model.py` and match the current target version (recomputed by `check_findings.py` for the model's own scope), or the user chooses between rerunning stage 1 and a narrow scan.
- Recorded sha256 of the consumed threat model.
- The stage 1 model is found automatically (`find_threat_model.py`): the newest valid, up-to-date run copy.
- The user's request is recorded without a confirmation prompt, and carried forward from stage 1 only within the same run.
- `investigation_question` on every finding, as the contract requires.
- Mandatory `counterevidence` stating what was searched.
- Stage 1 open questions carried forward; open-ended findings listed in `findings.md` as boundaries the threat model missed.
- Status rule: a Critical or High hypothesis left uninvestigated makes the stage `inconclusive`.

## Not adopted

| Codex Security mechanism | Reason |
| --- | --- |
| Validation, attack-path analysis, and severity inside the same scan | Stages 3 and later |
| Deep scans and the semantic reducer | Deferred |
| Workbench MCP tools (`record_codex_security_discovery_candidates`, drafts, checkpoints) | Replaced by files in the run folder |
| Ranked worklists and per-finding receipt files | Coverage inventory and reconciliation cover the same need |
| SARIF export | Deferred |
