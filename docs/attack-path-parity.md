# Attack-path analysis: capability parity with Codex Security

`skills/attack-path-analysis` (design: [attack-path-design.md](attack-path-design.md)) is designed to keep the capabilities of the attack-path phase in [openai/codex-security](https://github.com/openai/codex-security/tree/main/plugins/codex-security) (Apache-2.0). That phase covers:

- the `attack-path-analysis` skill and its references `attack-path-facts.md` and `severity-policy.md`;
- `schemas/tools/candidate-attack-paths.schema.json` and `mcp-app/src/artifact-attack-path.ts`;
- the parts of `references/scan-contract.md` and `references/scan-artifacts.md` that feed attack paths into the final report.

Codex Security records a nested `attack_path` object on each candidate through its MCP workbench. This plugin records an `attack-paths.json` in the run folder, and works without an MCP server in Claude Code, ChatGPT/Codex, and Cursor.

Compiled from codex-security `main` at `fe6d7db` on 2026-09-26. Recheck when either side changes. "Where" refers to the planned files under `skills/attack-path-analysis/`.

| # | Codex Security capability | How this skill provides it | Where |
| --- | --- | --- | --- |
| 1 | Runs only in the attack-path phase or on an explicit request to trace a finding and calibrate severity; never the primary trigger for scans | Description activates for severity/priority calibration and stage 3b; not for scans, discovery, validation, or fixes | `SKILL.md` frontmatter |
| 2 | Standard and Deep scans do attack-path reasoning inline | `defense-factory-review` runs it as its own sub-stage after stage 3 | review `SKILL.md` |
| 3 | A user-supplied path overrides the default; ask for a missing required input | Same rule as stages 1–3 | `SKILL.md` Preconditions |
| 4 | Inputs: the scan's threat model as source of truth, plus the candidates | Stage 1 model (attackers, boundaries, **severity calibration table**), stage 2 findings, stage 3 validations | `references/inputs.md` |
| 5 | Eligible only if the validation disposition is `reportable` or `deferred`; enforced in code | Eligible only if the verdict is `confirmed` or `inconclusive`; `rejected` is listed as not eligible; enforced by `check_attack_paths.py` | `check_attack_paths.py` |
| 6 | Every eligible candidate gets exactly one decision; the tool rejects missing, duplicate, unknown, or ineligible ids | Same, checked against the stage 3 record | `check_attack_paths.py` |
| 7 | Scope gate: a real vulnerability, in scope under the threat model, on a product surface | Same, as three facts (`security_vulnerability`, `in_scope`, `product_surface`); a `no` on any needs a suppression reason, checked | `references/method.md`; `check_attack_paths.py` |
| 8 | Facts from repository evidence only: service map, exposure, entry points, identity, trust boundaries, secrets flow, reachability, controls | Same, plus stage 3's recorded runtime evidence | `references/method.md` |
| 9 | A realistic attacker must reach and use the issue from an in-scope surface | Same | `references/method.md` |
| 10 | Counterevidence pass over seven interpretive fields, each marked dispositive or not | Same; stored as `{fact, evidence, dispositive}` entries | `references/facts-checklist.md`; schema |
| 11 | Incomplete evidence lowers confidence or stays unknown; missing ingress evidence is not dispositive | Same | `references/method.md` |
| 12 | Structured facts taxonomy (context, in-scope, exposure, identity, cross-boundary, vector, preconditions, input control, category, mitigations, auth scope, impact surface, reach, secrets, blind spots, controls) | Same taxonomy as a `facts` object; secrets by name and location only | schema |
| 13 | Three separate sub-stages (facts, then calibration, then policy); discovery is not reopened; no re-arguing after the matrix | Same, and the policy step is **recomputed by a script** | `check_attack_paths.py` |
| 14 | Start from the candidate's original severity hypothesis | Start from stage 2's `hypothesis_priority` | `references/method.md` |
| 15 | High/critical bar: material security impact, credible path, and auditor-acceptance checklist | Same | `references/severity-policy.md` |
| 16 | Example catalogues for critical, high, and not-high cases | Same catalogues, **plus the target-specific examples from stage 1's calibration table** | `references/severity-policy.md` |
| 17 | Escalators from high to critical | Same | `references/severity-policy.md` |
| 18 | Downgrades (localhost, self-only, constrained preconditions, already privileged) | Same | `references/severity-policy.md` |
| 19 | Hard suppression first → `ignore` | Same; the recorded `suppression` reason is checked | `check_attack_paths.py` |
| 20 | Vector-weighted likelihood | Same | `references/severity-policy.md` |
| 21 | Reportability gate: no realistic lower-privileged attacker means `ignore` | Same | `check_attack_paths.py` |
| 22 | Internal-surface exception: do not suppress only because a surface is private | Same | `references/severity-policy.md` |
| 23 | Low is a downgrade, not a discard | Same; floor `low` unless ignored | `check_attack_paths.py` |
| 24 | Threat model is the only override lever in the phase (SECURITY.md applies in Standard scans) | Threat model **and** the resolved SECURITY.md policy both apply; the threat model's exception is an explicit `calibration_override` that quotes the stage 1 calibration row and is checked (never combined with a suppression, never equal to the matrix result) | `references/inputs.md`; `references/method.md`; `check_attack_paths.py` |
| 25 | Decisions: `reportable` needs a real severity, `ignore` needs `ignore`, `deferred` needs a provisional severity plus a proof gap | Same; `reportable` additionally requires a `confirmed` verdict, and `inconclusive` must be `deferred` | schema; `check_attack_paths.py` |
| 26 | `ignore` recorded explicitly | Same, with its reason | schema |
| 27 | `change_conditions` on every decision | Same | schema |
| 28 | Confidence rendered as a fact, stored on the validation | A separate `confidence` on each analysis, kept apart from severity (stage 1's rule) | schema |
| 29 | Sibling rows are never skipped; root-control file:line preserved; independent instances kept distinct | Same; locations are copied from stage 2 and preserved | `start_attack_paths.py`; `check_attack_paths.py` |
| 30 | Visible per-candidate report: ids, affected lines by role, numbered attacker steps, facts as bullets, counterevidence, calibration, decision | Same, as sections of `attack-paths.md` | `render_attack_paths.py` |
| 31 | Priority mapping P0–P3 | Same, derived by the normalizer | `normalize_attack_paths.py` |
| 32 | Dataflow and reachability narratives feed the final report | Recorded per analysis; the review summary shows the severity and priority table | schema; review `SKILL.md` |
| 33 | No network unless expressly authorised | Always offline | `SKILL.md` Ground rules |

## Capabilities this skill adds

- **Target-specific calibration:** stage 1's severity calibration table (examples and counterexamples for this target) is applied alongside the generic policy.
- **An enforced policy step:** the script recomputes suppression, the gate, the matrix, the floor, and the priority from the recorded facts, so a severity cannot silently disagree with the policy.
- **Runtime evidence:** reachability for a finding confirmed in stage 3's container is proven, not argued.
- **A verdict rule:** only `confirmed` findings can be `reportable`; unconfirmed findings stay `deferred` with a provisional severity.
- **Explicit `not_eligible` list:** rejected findings are accounted for rather than silently dropped.

## Not adopted

| Codex Security mechanism | Reason |
| --- | --- |
| MCP workbench tools (`list_codex_security_candidates`, `record_candidate_attack_paths`) and `scanId` | Replaced by files in the run folder, so the skill needs no MCP server |
| Compact diff mode with an atomic `candidate_ledger.jsonl` rewrite | Diff scans are deferred plugin-wide |
| Deep Scan workers and coordinator | Out of scope |
| Per-candidate receipts and `attack_path_analysis_report.md` files | One canonical JSON plus one rendered report cover the same need |
| Deterministic sealed `report.md` finalisation | Partial: the review summary aggregates the stages; a sealed final report is a candidate for later |
